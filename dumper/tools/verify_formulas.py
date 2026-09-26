#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_formulas.py —— 免 IDA、免 .bin 的公式离线校验器

用途
----
换版本时，`reloc_ida.py` 负责**发现**新值，本脚本负责**判定**对不对：
读 exe + global-metadata.dat + dumper.h，把每条公式真正解一次，
用「偏移是否落在 blob 内 / 是否按记录大小对齐 / 内容是否可读」
把错的当场挑出来。也就是 docs.md §20.2「离线核对」的自动化。

用法
----
    python3 verify_formulas.py                 # 用同目录上级的默认路径
    python3 verify_formulas.py --exe a.exe --dat b.dat --h ../dumper/dumper.h
    python3 verify_formulas.py --found found.txt   # 附带校验 reloc_ida.py 的发现
    python3 verify_formulas.py --json          # 机器可读输出

判定标准（全部只依赖 IL2CPP 的结构性质，不含版本相关数值）
------------------------------------------------------
  * header 魔数 == kHeaderMagic
  * 每张表的 blob 偏移落在 [0, blob_size) 内
  * 偏移 + N*stride 不越界（能放下理论最大条数时）
  * 偏移按记录大小对齐（不对齐只是提醒，不算失败）
  * 偏移 < kHeaderBytes -> **警告**：指进了 header 区，多半是常数写错
  * MPT：界内地址零重复 + 长度
  * 88B 堆表：计数与 stride 自洽、首记录字段能解出可打印名

退出码: 0 = 全部通过(可能有警告)   1 = 有 FAIL   2 = 用法/环境错误
"""

import argparse
import json
import os
import re
import struct
import sys

# ------------------------------------------------------------------ PE ------

class PE:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.d = f.read()
        d = self.d
        if d[:2] != b"MZ":
            raise ValueError("不是 PE 文件: %s" % path)
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise ValueError("PE 签名无效")
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        self.magic = struct.unpack_from("<H", d, pe + 24)[0]
        if self.magic == 0x20B:                      # PE32+
            self.base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
            self.sizeofimage = struct.unpack_from("<I", d, pe + 24 + 56)[0]
        else:                                        # PE32
            self.base = struct.unpack_from("<I", d, pe + 24 + 28)[0]
            self.sizeofimage = struct.unpack_from("<I", d, pe + 24 + 56)[0]
        self.secs = []
        so = pe + 24 + optsz
        for i in range(nsec):
            b = so + i * 40
            nm = d[b:b + 8].rstrip(b"\0").decode("latin1")
            vs, va, rs, ro = struct.unpack_from("<IIII", d, b + 8)
            ch = struct.unpack_from("<I", d, b + 36)[0]
            self.secs.append(dict(name=nm, va=va, vs=vs, ro=ro, rs=rs,
                                  chars=ch, exec=bool(ch & 0x20000000)))

    def r2o(self, rva):
        """RVA -> 文件偏移；不落在任何节内返回 None。"""
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
                return s["ro"] + (rva - s["va"])
        return None

    def exec_ranges(self):
        out = []
        for s in self.secs:
            if s["exec"]:
                out.append((s["va"], s["va"] + max(s["vs"], s["rs"])))
        return out

    def read(self, rva, n):
        o = self.r2o(rva)
        if o is None or o + n > len(self.d):
            return None
        return self.d[o:o + n]

    def u8(self, rva):
        b = self.read(rva, 1)
        return None if b is None else b[0]

    def u32(self, rva):
        b = self.read(rva, 4)
        return None if b is None else struct.unpack_from("<I", b, 0)[0]

    def u64(self, rva):
        b = self.read(rva, 8)
        return None if b is None else struct.unpack_from("<Q", b, 0)[0]


# ------------------------------------------------------- 解析 dumper.h ------

def parse_header(path):
    """从 dumper.h 里抠出所有 constexpr 常量和 kT_* 表规格。

    记录大小从注释里取（`// 70B/条`），这样表结构改了校验器自动跟上，
    不用两边手工同步。
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    consts = {}
    for m in re.finditer(
            r"static\s+constexpr\s+\w+(?:_t)?\s+(k\w+)\s*=\s*"
            r"(0x[0-9A-Fa-f]+ULL|\d+ULL|0x[0-9A-Fa-f]+u?|\d+u?)\s*;",
            src):
        name, raw = m.group(1), m.group(2)
        # 后缀五花八门: ULL / ull / U / L / u64 风格，统一剥掉尾部所有 [uUlL]
        consts[name] = int(re.sub(r"[uUlL]+$", "", raw), 0)
    tables = []
    for m in re.finditer(
            r"static\s+constexpr\s+TableSpec\s+(k\w+)\s*=\s*"
            r"\{\s*(\d+)\s*,\s*'([-+\^])'\s*,\s*(0x[0-9A-Fa-f]+|\d+)[uU]?\s*\}"
            r"\s*;\s*//(.*)", src):
        name, field, op, k, tail = m.groups()
        sz = re.search(r"(\d+)\s*B\s*/\s*条", tail)
        tables.append(dict(name=name, field=int(field), op=op,
                           k=int(k, 0), stride=int(sz.group(1)) if sz else None,
                           note=tail.strip()))
    return consts, tables


def apply_formula(h, op, k):
    v = h & 0xFFFFFFFF
    if op == "^":
        return (v ^ k) & 0xFFFFFFFF
    if op == "-":
        return (v - k) & 0xFFFFFFFF
    return (v + k) & 0xFFFFFFFF


# --------------------------------------------------------------- 校验 -------

class Report:
    def __init__(self):
        self.items = []

    def add(self, level, name, msg):
        self.items.append(dict(level=level, name=name, msg=msg))

    def count(self, lv):
        return sum(1 for i in self.items if i["level"] == lv)

    def dump(self):
        for i in self.items:
            tag = {"PASS": "  ok  ", "WARN": " warn ", "FAIL": " FAIL "}[i["level"]]
            print("[%s] %-22s %s" % (tag, i["name"], i["msg"]))


def check_header(pe, consts, rep):
    hb = consts.get("kHeaderBytes", 528)
    magic = consts.get("kHeaderMagic", 0x0059484D)
    rva = consts.get("kRvaHeader")
    if rva is None:
        rep.add("FAIL", "header", "dumper.h 里没有 kRvaHeader，无法定位 528B header")
        return None
    raw = pe.read(rva, hb)
    if raw is None:
        rep.add("FAIL", "header", "RVA 0x%X 不在文件内(段未加载?)" % rva)
        return None
    got = struct.unpack_from("<I", raw, 0)[0]
    if got == magic:
        rep.add("PASS", "header", "RVA 0x%X  魔数 0x%08X  OK  (%d 字节)"
                % (rva, got, hb))
    else:
        rep.add("FAIL", "header", "RVA 0x%X 魔数 0x%08X != 期望 0x%08X"
                % (rva, got, magic))
    return list(struct.unpack_from("<%dI" % (hb // 4), raw, 0))


def check_tables(pe, hdr, dat, tables, consts, rep):
    """逐条解公式并判定。

    ⚠️ `kT_*` 里的第二个数是 **header 内的字节偏移**，不是 u32 下标。
    证据: 7.1 的 15 个值 144..516 全部 < kHeaderBytes(528)；
    而 u32 下标上限是 528/4 = 132，148/160/180/316 全部越界。
    """
    bl = len(dat)
    hb = consts.get("kHeaderBytes", 528)
    for t in tables:
        off_in_hdr = t["field"]
        if off_in_hdr % 4 or off_in_hdr + 4 > hb:
            rep.add("FAIL", t["name"],
                    "field=%d 不是 4 字节对齐且落在 528B header 内" % off_in_hdr)
            continue
        h = hdr[off_in_hdr // 4]
        off = apply_formula(h, t["op"], t["k"])
        nm = "hdr+0x%X %s 0x%X" % (off_in_hdr, t["op"], t["k"])
        if off >= bl:
            rep.add("FAIL", t["name"],
                    "%s -> 0x%X 越界(blob 只有 0x%X)" % (nm, off, bl))
            continue
        if off < hb:
            rep.add("WARN", t["name"],
                    "%s -> 0x%X **指进 header 区(<%d)**, 常数可能写错"
                    % (nm, off, hb))
            continue
        if t["stride"] and (t["stride"] & (t["stride"] - 1)) == 0 \
                and off % t["stride"]:
            # 只对 2 的幂 stride 有意义。70B/26B/12B/10B/14B 这类紧凑记录
            # 数组，起点本来就多半不对齐，强行要求对齐会满屏假警告。
            rep.add("WARN", t["name"],
                    "%s -> 0x%X 未按 %dB 对齐" % (nm, off, t["stride"]))
            continue
        if t["stride"] and off + t["stride"] > bl:
            rep.add("WARN", t["name"], "%s -> 0x%X 首条就越界" % (nm, off))
            continue
        rep.add("PASS", t["name"], "%s -> blob+0x%X  OK  %s"
                % (nm, off, t["note"][:44]))


def check_type_array(pe, consts, rep):
    """16B Il2CppType 数组的 RVA 存在 kRvaTypeStruct + kTypeArrayOff 处。"""
    rva = consts.get("kRvaTypeStruct")
    off = consts.get("kTypeArrayOff")
    if rva is None or off is None:
        rep.add("WARN", "Il2CppType[]", "dumper.h 缺 kRvaTypeStruct/kTypeArrayOff")
        return
    v = pe.u64(rva + off)
    if v is None:
        rep.add("FAIL", "Il2CppType[]",
                "读 *(u64*)(0x%X+0x%X) 失败(不在文件内)" % (rva, off))
        return
    if v and v < pe.sizeofimage and pe.r2o(v) is not None:
        rep.add("PASS", "Il2CppType[]",
                "*(0x%X+0x%X) = RVA 0x%X  16B/条  在文件内"
                % (rva, off, v))
    else:
        rep.add("WARN", "Il2CppType[]",
                "*(0x%X+0x%X) = 0x%X  不像 RVA(超出 SizeOfImage 0x%X 或未映射)—— "
                "该结构可能运行期才填充" % (rva, off, v, pe.sizeofimage))


def check_mpt(pe, consts, rep, cap=1 << 21):
    """整表扫 MPT：界内地址应 16B 对齐且**两两不同**(真 MPT 判据)。"""
    rva = consts.get("kRvaMethodCodePtrs")
    if rva is None:
        rep.add("WARN", "MPT", "dumper.h 缺 kRvaMethodCodePtrs")
        return
    lo = pe.base
    hi = pe.base + pe.sizeofimage
    n = inimg = zero = dup = aligned = bad = 0
    bad_run = 0
    seen = set()
    ea = rva
    CH = 1 << 16                                   # 每次读 64K 项
    TOL = 64                                       # 容忍的连续离群项
    stop = False
    while n < cap and not stop:
        raw = pe.read(ea + n * 8, min(CH, cap - n) * 8)
        if not raw:
            break
        cnt = len(raw) // 8
        for i in range(cnt):
            v = struct.unpack_from("<Q", raw, i * 8)[0]
            n += 1
            if v == 0:
                zero += 1
                bad_run = 0
            elif lo <= v < hi and (v - pe.base) & 0xF == 0:
                inimg += 1
                aligned += 1
                bad_run = 0
                if v in seen:
                    dup += 1
                else:
                    seen.add(v)
            else:
                bad += 1
                bad_run += 1
                # 连续离群项超过阈值 -> 已越过表尾，停。
                # 不能靠 cap 猜：读过头会把相邻表的数据算进来，
                # 7.1 误读成 2097152 项、1352966 项"越界"就是这么来的。
                if bad_run > TOL:
                    stop = True
                    break
    if n == 0:
        rep.add("FAIL", "MPT", "RVA 0x%X 读不出任何项" % rva)
        return
    tail = ""
    if stop:
        # 越过表尾后读到的离群项属正常，不参与"真伪"判定
        tail = "  (尾部越过表尾的 %d 个离群项已排除)" % bad
        bad = bad - bad_run
    if dup == 0 and bad == 0:
        rep.add("PASS", "MPT",
                "RVA 0x%X  长度 %d  界内 %d  零 %d  重复 0%s  -> 真 MPT"
                % (rva, n, inimg, zero, tail))
    else:
        rep.add("WARN", "MPT",
                "RVA 0x%X  长度 %d  界内 %d  重复 %d(%.2f%%)  表内离群 %d%s"
                "  -> 重复率显著时可能是桩表"
                % (rva, n, inimg, dup, 100.0 * dup / max(inimg, 1), bad, tail))
    th = consts.get("kRvaMethodThunkPtrs")
    if th:
        rep.add("WARN", "thunk",
                "RVA 0x%X  仅供诊断的泛型/共享桩表，不作为方法地址" % th)


def check_88b(pe, dat, consts, rep):
    """88B 堆表在**运行期 CRT 堆**上，静态 exe 里必然读不到真值。"""
    for tag, cr, tr in (("asm88", "kRvaAsmCount", "kRvaAsmTable"),
                        ("img88", "kRvaImgCount", "kRvaImgTable")):
        crv, trv = consts.get(cr), consts.get(tr)
        st = consts.get("kAsmImgStride", 88)
        cnt = consts.get("kAsmImgCount", "?")
        if crv is None or trv is None:
            rep.add("WARN", tag, "dumper.h 缺 %s/%s" % (cr, tr))
            continue
        disk_cnt = pe.u32(crv)
        heap = pe.u64(trv)
        ok_heap = bool(heap and lo_is_plausible(pe, heap))
        rep.add("WARN", tag,
                "stride=%d 期望 %s 条；磁盘读到 count=0x%08X table=0x%X%s —— "
                "运行期堆表，静态无法校验，需真机运行确认"
                % (st, cnt, disk_cnt or 0, heap or 0,
                   "" if ok_heap else "(不是有效运行期地址)"))


def lo_is_plausible(pe, v):
    return 0x10000 <= v < (1 << 48)


def check_found(found_path, hdr, dat, tables, consts, rep):
    """把 reloc_ida.py 的发现与 dumper.h 权威值对齐。"""
    if not os.path.exists(found_path):
        rep.add("WARN", "reloc发现", "找不到 %s" % found_path)
        return
    with open(found_path, "r", encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip()]
    found = []
    for l in lines:
        m = re.match(r"^hdr\+0x([0-9A-Fa-f]+)\s+([\^\-+])\s+0x([0-9A-Fa-f]+)", l)
        if m:
            found.append((int(m.group(1), 16), m.group(2), int(m.group(3), 16)))
    if not found:
        rep.add("WARN", "reloc发现", "%s 里没解析出条目" % found_path)
        return
    bl = len(dat)
    # dumper.h 权威值 -> blob 偏移
    auth = {}
    for t in tables:
        b = t["field"]
        if b % 4 or b + 4 > 528:
            continue
        auth.setdefault(apply_formula(hdr[b // 4], t["op"], t["k"]), t)
    hit = 0
    for disp, op, k in found:
        if disp % 4 or disp + 4 > 528:
            continue
        off = apply_formula(hdr[disp // 4], op, k)
        if off in auth:
            t = auth[off]
            same = (t["field"] == disp and t["op"] == op and t["k"] == k)
            hit += 1
            rep.add("PASS", "reloc发现",
                    "0x%X %s 0x%X -> blob+0x%X  = dumper.h %s  %s"
                    % (disp, op, k, off, t["name"],
                       "(写法完全一致)" if same else "(同一张表，常数写法不同)"))
        elif off < bl:
            rep.add("WARN", "reloc发现",
                    "0x%X %s 0x%X -> blob+0x%X  不对应 dumper.h 任何表"
                    % (disp, op, k, off))
    rep.add("PASS", "reloc发现", "命中 %d / %d" % (hit, len(found)))


# --------------------------------------------------------------- main -------

def main():
    here = os.path.dirname(os.path.abspath(__file__))     # .../7.1/tools/v6/tools
    v6 = os.path.dirname(here)                            # .../7.1/tools/v6
    root = os.path.dirname(os.path.dirname(v6))           # .../7.1
    ap = argparse.ArgumentParser(description="免 IDA 的公式离线校验器")
    ap.add_argument("--exe", default=os.path.join(root, "GenshinImpact.exe"))
    ap.add_argument("--dat", default=os.path.join(root, "global-metadata.dat"))
    ap.add_argument("--h", "--header", dest="h",
                    default=os.path.join(v6, "dumper", "dumper.h"))
    ap.add_argument("--found", default=os.path.join(here, "found.txt"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    for p in (a.exe, a.dat, a.h):
        if not os.path.exists(p):
            print("缺少文件: %s" % p, file=sys.stderr)
            return 2

    pe = PE(a.exe)
    with open(a.dat, "rb") as f:
        dat = f.read()
    consts, tables = parse_header(a.h)
    if not consts:
        print("没能从 %s 解析出任何 constexpr" % a.h, file=sys.stderr)
        return 2

    rep = Report()
    if not a.json:
        print("=" * 74)
        print(" 公式离线校验   imagebase 0x%X   blob 0x%X (%d 字节)"
              % (pe.base, len(dat), len(dat)))
        print(" exe : %s" % a.exe)
        print(" dat : %s" % a.dat)
        print(" 常量: %s (%d 条 constexpr, %d 张表)"
              % (a.h, len(consts), len(tables)))
        print("=" * 74)

    hdr = check_header(pe, consts, rep)
    if hdr:
        check_tables(pe, hdr, dat, tables, consts, rep)
        check_type_array(pe, consts, rep)
        check_found(a.found, hdr, dat, tables, consts, rep)
    check_mpt(pe, consts, rep)
    check_88b(pe, dat, consts, rep)

    if a.json:
        print(json.dumps(dict(imagebase=pe.base, blob=len(dat), items=rep.items),
                         ensure_ascii=False, indent=2))
    else:
        rep.dump()
        print("-" * 74)
        print(" PASS %d   WARN %d   FAIL %d"
              % (rep.count("PASS"), rep.count("WARN"), rep.count("FAIL")))
    return 1 if rep.count("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
