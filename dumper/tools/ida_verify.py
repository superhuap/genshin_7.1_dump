#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ida_verify.py —— 7.1/7.2 公式离线验证（**不需要任何 .bin**）

替代原 nativetest / idxprobe：那两个工具依赖 gi_dump 产出的 module.bin 与
pool_metadata.bin，而目标版本不保证有这些 dump。本脚本只依赖：

    GenshinImpact.exe        （或已在 IDA 里打开）
    global-metadata.dat

为什么值得单独一个脚本：58 项 formulaCheck 全在**真机**里跑（要注入 DLL、几分钟），
而下面 6 项里有 4 项**只靠静态数据**就能算，改一次常数就能秒查。剩下 2 项
（成员索引连续性、MPT 零重复）是 formulaCheck **结构上无法替代**的 ——
索引错位不改变方法总数，所有计数类自检照样全 PASS，症状只是"方法指向了别的函数"。
2026-09-26 的 MPT 事故就是这一类：覆盖率 96% ✓、不同地址 649,615 ✓，全绿，但 99.9% 方法地址是错的。

用法
----
独立模式（任何平台，推荐做迁移期快查）：

    python3 ida_verify.py <global-metadata.dat> [GenshinImpact.exe]

IDA 内模式（File > Script File...，直接读 IDB）：

    选中本脚本 → 提示框选 global-metadata.dat

判定原则
--------
* **结构不变式**（索引空洞/重叠、MPT 重复地址）—— 不成立直接 FAIL。
  这类量在换版本时也不该变，变了就是公式错了。
* **统计量**（Σ methodCount、MPT 界内条数、各表偏移）—— 只与 7.1 基线比对并
  提示 drift，不 FAIL。换版本时它们本来就会变，变化是预期的，要人工确认语义。
"""

import os
import struct
import sys

# ============================================================================
#  7.1 基线。换版本时这些值应当变化 —— 变化会在 DRIFT 段列出，需人工确认语义。
# ============================================================================
BASE_71 = {
    "header_magic":   0x59484D,      # "MHY\0" 小端
    "rva_header":     0x27D4BD0,
    "rva_type_array": 0x2E1EA20,
    "rva_sse":        0x39085D0,
    "rva_mpt":        0x2870B90,     # 真方法指针表
    "rva_thunk":      0x27D4DE0,     # 泛型/共享派发桩表
    "rva_asm_cnt":    0x5AD52F0,
    "rva_asm_tab":    0x5AD52F8,
    "rva_img_cnt":    0x5AD5300,
    "rva_img_tab":    0x5AD5308,
    "rva_generic":    0x5AD4E98,
    "hdr_bytes":      528,
    "image_size":     0x1AFF7000,
    "n_asm":          75,
    "n_methods":      733442,   # 方法指针表条数; 多读会踩进相邻数据
    # 表基址: field -> (op, konst, 条大小, 名称)
    "tables": {
        180: ('-', 330781793,    70, "typedef"),
        364: ('-', 483030612,    26, "method"),
        148: ('^', 0x4A4C0A71,   4, "mptr"),
        396: ('-', 336578260,     8, "field"),
        336: ('-', 473781129,    10, "prop"),
        488: ('^', 0x100547B1,   14, "event"),
        276: ('^', 0x3E5D33E6,    8, "param"),
        516: ('-', 450622139,     4, "iface"),
        296: ('^', 0x0F92DC85,    4, "fieldoff"),
        144: ('+', 0x0B7255040,  12, "fdesc12"),
        376: ('+', 0x0ADEC9E28,   4, "fhidx4"),
        316: ('^', 0x593DE464,   12, "enumval"),
        160: ('^', 0x3F525210,    0, "enumvalblob"),
        412: ('^', 0x30F4D28E,    8, "tokentype"),
        388: ('+', 0xBF9D4735,    0, "strblob"),
    },
    # 70B typeDef 记录: 偏移 -> (读宽, 公式描述, 名称)
    "typedef": {
        0:  ("u32", "- 1145778368",          "ns token"),
        4:  ("u32", "^ 0x0DA4711B",           "byvalType (值类型判定主依据)"),
        8:  ("u32", "- 1995389561",          "propStart"),
        12: ("u32", "^ 0x4D8127F2",           "methodStart"),
        16: ("u32", "- 1950851500",          "baseType(非基类!)"),
        24: ("u32", "- 1031049247",          "elementType"),
        28: ("u32", "^ 0x29010897",           "fieldStart"),
        36: ("u32", "- 72511848",             "name token"),
        48: ("u16", "+ 4806",                 "methodCount"),
        52: ("i16", "+ 3330",                 "eventStart"),
        54: ("i16", "+ 6631",                 "ifaceStart"),
        56: ("u16", "^ 0x51A8",               "fieldCount"),
        58: ("u16", "(raw)",                  "flags"),
        67: ("u8",  "^ 0x16",                 "propCount"),
        68: ("u8",  "+ 113",                  "eventCount"),
        69: ("u8",  "^ 0xBA",                 "ifaceCount"),
    },
    "expect_type_count": 88902,
    "expect_method_sum": 733442,
    "expect_mpt_inimg":  711021,
    "expect_thunk_dup":  3754,      # 桩表应有大量重复(两表可区分的证据)
}

M32 = 0xFFFFFFFF
FAIL, DRIFT, OK = [], [], []


def ok(msg):    OK.append(msg);    print("  [ OK ]   " + msg)
def drift(msg): DRIFT.append(msg); print("  [DRIFT]  " + msg)
def fail(msg):  FAIL.append(msg);  print("  [FAIL]   " + msg)


# ============================================================================
#  读 exe：优先用 IDA（IDB 已是内存映像），否则自己解析 PE section 表
# ============================================================================
class Exe:
    """按 RVA 取字节。两种后端：IDA IDB，或磁盘文件 + section 表。"""

    def __init__(self, path=None):
        self.mode = None
        self.name = ""
        if path and os.path.exists(path):
            self._init_file(path)
            return
        try:                                    # IDA 内(IDB 已是内存映像, RVA 直取)
            import ida_bytes, ida_nalt, ida_segment
            self.mode = "ida"
            self.name = ida_nalt.get_root_filename()
            # IDA 9.x: get_imagebase() 在 ida_nalt, ida_idaapi/idaapi 上都没有了
            self.base = ida_nalt.get_imagebase()
            self._get = lambda rva, n: ida_bytes.get_bytes(self.base + rva, n) or b""
            # IDA 里没有"ImageSize"的概念。取映像实际覆盖范围作为上界:
            # 最高的段末端。退化时回落到 7.1 常量。
            self.image_size = 0
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                end = seg.end_ea - self.base
                if end > self.image_size:
                    self.image_size = end
            if not self.image_size:
                self.image_size = BASE_71["image_size"]
            self._ida = True
        except Exception:
            self.mode = "none"

    def _init_file(self, path):
        self.mode, self.name = "file", os.path.basename(path)
        self.base = 0x140000000                 # 7.1/7.2 的 PE 首选基址
        f = open(path, "rb")
        d = f.read(0x400)
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        ohsz = struct.unpack_from("<H", d, pe + 0x14)[0]   # SizeOfOptionalHeader
        self.image_size = struct.unpack_from("<I", d, pe + 0x18 + 0x38)[0]
        self.base = struct.unpack_from("<Q", d, pe + 0x18 + 0x18)[0]  # ImageBase(8B)
        # section table 紧跟 optional header 之后(易错: 不要再 +0x20)
        base = pe + 4 + 20 + ohsz
        self.sec = []
        for i in range(nsec):
            o = base + 40 * i
            f.seek(o)
            nm = f.read(8).rstrip(b"\x00").decode("latin1")
            vs, va, rs, ro = struct.unpack("<IIII", f.read(16))
            self.sec.append((va, vs, ro, rs, nm))
        self._f = f

    def has(self, rva, n=1):
        try:
            return self.get(rva, n) is not None
        except Exception:
            return False

    def get(self, rva, n):
        if self.mode == "ida":
            b = self._get(rva, n)
            return b if b and len(b) == n else None
        if self.mode != "file":
            return None
        off = self.r2o(rva)
        if off is None:
            return None
        self._f.seek(off)
        b = self._f.read(n)
        return b if len(b) == n else None

    def r2o(self, rva):
        for va, vs, ro, rs, nm in self.sec:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None

    def u32(self, rva):
        b = self.get(rva, 4)
        return struct.unpack("<I", b)[0] if b else None

    def u64(self, rva):
        b = self.get(rva, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def qwords(self, rva, n):
        """整块读。逐条 u64() 在 80 万条目上要 80 万次 seek+read, 太慢。"""
        blob = self.get(rva, 8 * n)
        if blob is None:                        # 尾部可能超出映像, 退化为逐段读
            out, got = [], 0
            while got < n:
                v = self.u64(rva + 8 * got)
                if v is None:
                    break
                out.append(v)
                got += 1
            return out
        return list(struct.unpack("<%dQ" % n, blob))


# ============================================================================
#  1. header
# ============================================================================
def chk_header(exe):
    print("\n[1] 528B header")
    h = exe.get(BASE_71["rva_header"], BASE_71["hdr_bytes"])
    if not h:
        fail("读不到 header @ RVA 0x%X（版本可能变了，先更新 RVA 常量）" % BASE_71["rva_header"])
        return None
    magic = struct.unpack_from("<I", h, 0)[0]
    if magic == BASE_71["header_magic"]:
        ok("magic = 0x%08X  (\"MHY\\0\")" % magic)
    else:
        fail("magic = 0x%08X, 期望 0x%08X" % (magic, BASE_71["header_magic"]))
    return h


# ============================================================================
#  2/3. MPT 双表判别 —— 拿错表是本项目最贵的坑
# ============================================================================
def scan_ptr_table(exe, rva, label):
    """统计一张 8B/条指针表。零值 = '无实现'，不算重复地址。"""
    lo, hi = exe.base, exe.base + (exe.image_size or BASE_71["image_size"])
    inimg, zero, oob = [], 0, 0
    for v in exe.qwords(rva, BASE_71["n_methods"]):
        if not v:
            zero += 1
        elif lo <= v < hi:
            inimg.append(v - exe.base)
        else:
            oob += 1
    cnt = {}
    for r in inimg:
        cnt[r] = cnt.get(r, 0) + 1
    dup = sum(1 for n in cnt.values() if n > 1)
    maxdup = max(cnt.values()) if cnt else 0
    align = 100.0 * sum(1 for r in inimg if r & 0xF == 0) / len(inimg) if inimg else 0.0
    band = 100.0 * sum(1 for r in inimg if 0x43A000 <= r < 0x480000) / len(inimg) if inimg else 0.0
    return dict(label=label, inimg=len(inimg), zero=zero, oob=oob, distinct=len(cnt),
                dup=dup, maxdup=maxdup, align=align, band=band)


def chk_mpt(exe):
    print("\n[2/3] 方法代码地址：两张表的判别")
    m = scan_ptr_table(exe, BASE_71["rva_mpt"], "真MPT候选")
    t = scan_ptr_table(exe, BASE_71["rva_thunk"], "桩表候选")
    for s in (m, t):
        print("    %-10s 界内=%d 零(无实现)=%d 界外=%d 不同=%d 重复=%d 最大重数=%d "
              "16B对齐=%.1f%% 窄带=%.1f%%"
              % (s["label"], s["inimg"], s["zero"], s["oob"], s["distinct"],
                 s["dup"], s["maxdup"], s["align"], s["band"]))
    # 结构不变式: 真 MPT 每个方法一个唯一代码体
    if m["dup"] == 0:
        ok("真MPT 界内地址零重复 (%d 个)" % m["distinct"])
    else:
        fail("真MPT 有 %d 个重复地址(最大重数 %d) —— 这不是真 MPT, 换版本后 RVA 常量错了"
             % (m["dup"], m["maxdup"]))
    if t["dup"] > 0:
        ok("桩表 有 %d 个重复地址(最大重数 %d) —— 与真MPT 可区分" % (t["dup"], t["maxdup"]))
    else:
        fail("桩表 竟然零重复 —— 两张表已无法用'重复地址'区分, 需另找判据(见 docs §13)")
    # 统计量: 只提示 drift
    for s, key, exp in ((m, "真MPT 界内条数", BASE_71["expect_mpt_inimg"]),
                        (t, "桩表 重复地址数", BASE_71["expect_thunk_dup"])):
        got = m["inimg"] if "界内" in key else t["dup"]
        (ok if got == exp else drift)("%s = %d (7.1 基线 %d)" % (key, got, exp))


# ============================================================================
#  4. 88B 指针全局形态 —— 论证"堆表必须运行期抓"
# ============================================================================
def chk_heap_globals(exe):
    print("\n[4] 88B 堆表指针全局（论证为何不能从 exe 抓）")
    lo, hi = exe.base, exe.base + (exe.image_size or BASE_71["image_size"])
    # 这几个全局在运行期是 75 / 堆指针, 但**磁盘上是密文**(对照: 528B header 与
    # 16B 类型数组 32/32 字节一致, 这块 0/32)。所以磁盘上应全部表现为"非映像内指针"。
    for rva, nm in ((BASE_71["rva_asm_cnt"], "asmCnt"),
                    (BASE_71["rva_asm_tab"], "asmTab"),
                    (BASE_71["rva_img_cnt"], "imgCnt"),
                    (BASE_71["rva_img_tab"], "imgTab"),
                    (BASE_71["rva_generic"], "genericDesc")):
        v = exe.u64(rva)
        if v is None:
            drift("%-11s @0x%X 读不到" % (nm, rva))
            continue
        looks_ptr = lo <= v < hi or v == BASE_71["n_asm"]
        (ok if not looks_ptr else fail)(
            "%-11s = 0x%016X %s" % (nm, v,
            "=> 加密值, 堆表确实不在磁盘上(预期)" if not looks_ptr
            else "=> 已是明文/有效指针! 结构已变, 需重新确认这张表"))


# ============================================================================
#  5. 成员索引连续性 —— formulaCheck 结构上无法替代的那一项
# ============================================================================
def chk_index_continuity(hdr, dat):
    print("\n[5] 成员索引空间连续性  ← formulaCheck 替代不了的一项")
    td = table_off(hdr, 180)
    if td is None:
        fail("typedef 表基址复算失败, 跳过")
        return
    N = BASE_71["expect_type_count"]
    need = td + 70 * N
    if need > len(dat):
        drift("typedef 表需要 %d 字节, .dat 只有 %d —— 类型数可能变了, 请更新 expect_type_count"
              % (need, len(dat)))
        N = max(0, (len(dat) - td) // 70)
    st = [0] * N
    ct = [0] * N
    tot = 0
    for i in range(N):
        b = td + 70 * i
        st[i] = struct.unpack_from("<I", dat, b + 12)[0] ^ 0x4D8127F2
        ct[i] = (struct.unpack_from("<H", dat, b + 48)[0] + 4806) & 0xFFFF
        tot += ct[i]
    withm = [i for i in range(N) if ct[i]]
    holes = overlaps = 0
    last = first = 0
    for k, i in enumerate(withm):
        if k == 0:
            first = st[i]
        elif st[i] > last:
            holes += 1
        elif st[i] < last:
            overlaps += 1
        last = st[i] + ct[i]
    print("    有方法的类型 = %d  (count==0 的 %d 个已排除, start 是 0xFFFFFFFF 哨兵)"
          % (len(withm), N - len(withm)))
    print("    索引区间 = %d .. %d    Σ methodCount = %d" % (first, last, tot))
    # 结构不变式
    if holes == 0 and overlaps == 0 and first == 0:
        ok("索引空间无缝连续: 空洞=0 重叠=0 起点=0")
    else:
        fail("索引空间异常: 空洞=%d 重叠=%d 起点=%d —— methodStart 公式错了, "
             "方法地址会全部错位而计数类自检仍全 PASS" % (holes, overlaps, first))
    (ok if last == tot else drift)("末值(%d) == Σ methodCount(%d)" % (last, tot))
    (ok if tot == BASE_71["expect_method_sum"] else drift)(
        "Σ methodCount = %d (7.1 基线 %d)" % (tot, BASE_71["expect_method_sum"]))


# ============================================================================
#  6. 表基址复算
# ============================================================================
def table_off(hdr, field):
    h = struct.unpack_from("<I", hdr, field)[0]
    spec = BASE_71["tables"].get(field)
    if not spec:
        return None
    op, k, _, _ = spec
    off = (h - k) & M32 if op == '-' else ((h ^ k) if op == '^' else (h + k))
    return BASE_71["hdr_bytes"] + off


def chk_tables(hdr, dat):
    print("\n[6] 表基址复算  table = blob + 528 + (h32(field) OP CONST)")
    for field in sorted(BASE_71["tables"]):
        op, k, recsz, nm = BASE_71["tables"][field]
        off = table_off(hdr, field)
        h = struct.unpack_from("<I", hdr, field)[0]
        if off is None:
            fail("%-12s h32(%d)=0x%08X -> 无法复算" % (nm, field, h))
            continue
        mark = "" if recsz == 0 else "  (%dB/条)" % recsz
        # `-`/`^` 的表是 blob 内部的, 越界说明常数错了; `+` 的表(fdesc12/fhidx4/
        # strblob)偏移天然落在 blob 之外 —— 它们指向堆, 不能按越界判错。
        inside = off < len(dat)
        if op == '+' and not inside:
            drift("%-12s h32(%-3d)=0x%08X + 0x%08X -> off 0x%X  (落在 blob 外, 预期: 指向堆)%s"
                  % (nm, field, h, k, off, mark))
        elif inside:
            ok("%-12s h32(%-3d)=0x%08X %s 0x%08X -> off 0x%06X%s" % (nm, field, h, op, k, off, mark))
        else:
            fail("%-12s h32(%-3d)=0x%08X %s 0x%08X -> off 0x%X 越界(blob 共 0x%X), 常数错了"
                 % (nm, field, h, op, k, off, len(dat)))


# ============================================================================
def main():
    print("=" * 74)
    print(" 7.1 公式离线验证（无需 .bin）")
    print("=" * 74)
    if len(sys.argv) > 1:
        datp, exep = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        try:                                     # IDA 内
            import tkinter as tk
            from tkinter import filedialog
            r = tk.Tk(); r.withdraw()
            datp = filedialog.askopenfilename(title="选 global-metadata.dat")
            r.destroy()
        except Exception:
            print("用法: python3 ida_verify.py <global-metadata.dat> [GenshinImpact.exe]")
            return 2
        exep = None
        if not datp:
            print("未选择文件, 退出")
            return 2
    if not os.path.exists(datp):
        print("找不到 %s" % datp)
        return 2
    dat = open(datp, "rb").read()
    print("dat   : %s  (0x%X 字节)" % (os.path.basename(datp), len(dat)))
    exe = Exe(exep)
    if exe.mode == "none":
        print("exe   : 未提供且不在 IDA 内 —— 跳过 [1][2][3][4]，只做 [5][6]")
        hdr = None
    else:
        print("exe   : %s  (%s 后端, base 0x%X)" % (exe.name, exe.mode, exe.base))
        hdr = chk_header(exe)
        if hdr:
            chk_mpt(exe)
            chk_heap_globals(exe)
    if hdr:
        chk_index_continuity(hdr, dat)
        chk_tables(hdr, dat)
    print("\n" + "=" * 74)
    print(" 汇总: OK=%d  DRIFT=%d  FAIL=%d" % (len(OK), len(DRIFT), len(FAIL)))
    if DRIFT:
        print(" DRIFT = 与 7.1 基线不同。换版本时这是预期的，但需人工确认语义未变。")
    if FAIL:
        print("\n *** 有 %d 项 FAIL —— 公式/地址语义不成立，别信产物 ***" % len(FAIL))
        return 1
    print(" 全部结构不变式成立。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
