#!/usr/bin/env python3
"""Genshin 7.1 元数据 v1 dump 工具。
产出: dump.cs(类型/方法/地址)+ dump.json(机器可读)

已解码:
- 字符串全密码(sub_14050F280 复刻)
- typedef 70B 表 @180: namespace(+0)/name(+36)/flags(+58)/methodStart(+12)/methodCount(+48)
- 方法 26B 表 @364: name(+0)/declaring(+12)/slot(+16)/flags(+22)
- 方法指针: @148 4B 间接 → 5298+96 数组
- 程序集 typeStart/typeCount: 池 52F8 表 +56 ^0x4B1CB1C1 / +36 ^0x6A3E22EA
"""
import struct, sys, json, time
sys.path.insert(0, "/Users/superhuap/Documents/ida/genshin/7.1/tools")
from gi71 import _raw, _module, _poolm, _info, h32, M32, decode_string

BASE = _info["image_base"]
POOLM = _info["pool_meta_base"]

T_TYPEDEF = 528 + (h32(180) - 330781793) & M32
T_M26     = 528 + (h32(364) - 483030612) & M32
T_MP4     = 528 + (h32(148) ^ 0x4A4C0A71) & M32
TYPE_COUNT = ((h32(8) - 1823609295) & M32) >> 2

ASM_POOL = _info["g_52F8"] - POOLM
MP_ARR = struct.unpack_from("<Q", _module, _info["g_5298"] - BASE + 96)[0]
MP_ARR_RVA = MP_ARR - BASE

def u32(o): return struct.unpack_from("<I", _raw, o)[0]
def u16(o): return struct.unpack_from("<H", _raw, o)[0]
def u8(o):  return _raw[o]
def mu64(rva): return struct.unpack_from("<Q", _module, rva)[0]
def pu32(o): return struct.unpack_from("<I", _poolm, o)[0]

def k1(i): return ((((860405619 * i) & 0xFFFFFFFF) ^ 0x73758947) + 1547935323) & 0xFFFFFFFF
def v25(i): return (((( -16525 * i) & 0xFFFFFFFF) ^ 0x8947) - 24997) & 0xFFFF
def kbits(i): return ((((115 * i) & 0xFFFFFFFF) ^ 0x47) + 91) & 0xFFFFFFFF

def pool_str(ptr):
    off = ptr - POOLM
    if off < 0 or off >= len(_poolm): return None
    end = _poolm.find(b"\0", off, off + 256)
    if end < 0: end = off + 64
    return _poolm[off:end].decode("utf-8", "replace")

def dec(idx):
    try:
        b = decode_string(idx)
        return b.decode("utf-8", "replace")
    except Exception:
        return "?"

# ---------------- 程序集(池,image 表取名) ----------------
def assemblies():
    IMG_POOL = _info["g_5308"] - POOLM
    out = []
    for i in range(75):
        o = ASM_POOL + 88 * i
        typeStart = pu32(o + 56) ^ 0x4B1CB1C1
        typeCount = pu32(o + 36) ^ 0x6A3E22EA
        # 名字: 找指向此 assembly 的 image (image+8 - bias = assembly ptr)
        name = None
        for j in range(75):
            io = IMG_POOL + 88 * j
            aptr = struct.unpack_from("<Q", _poolm, io + 8)[0] - 0x1D2861AD1B868E81
            if aptr - POOLM == o:
                name = pool_str(struct.unpack_from("<Q", _poolm, io + 64)[0] - 0x783FCBBE2E713C7F)
                break
        out.append({"idx": i, "name": name, "typeStart": typeStart, "typeCount": typeCount})
    return out

# ---------------- typedef ----------------
def typedef(i):
    o = T_TYPEDEF + 70 * i
    return {
        "namespace": dec((u32(o) - 1145778368) & M32),
        "name":      dec((u32(o + 36) - 72511848) & M32),
        "byvalType": u32(o + 4) ^ 0xDA4711B,
        "declaring": (u32(o + 16) - 1950851500) & M32,
        "element":   (u32(o + 24) - 1031049247) & M32,
        "methodStart": u32(o + 12) ^ 0x4D8127F2,
        "methodCount": (u16(o + 48) + 4806) & 0xFFFF,
        "flags": u16(o + 58),
        "ifaceStart": (u16(o + 54) + 6631) & 0xFFFF if False else (struct.unpack_from("<h", _raw, o + 54)[0] + 6631),
        "ifaceCount": u8(o + 69) ^ 0xBA,
    }

# ---------------- 方法 ----------------
def method(i):
    o = T_M26 + 26 * i
    r = {
        "name": dec(k1(i) ^ ((u32(o) - 1524016681) & M32)),
        "decl": u32(o + 12) ^ k1(i) ^ 0x59244785,
        "slot": ((u16(o + 16) - 25344) & 0xFFFF) ^ v25(i),
        "flags": u16(o + 22) ^ v25(i) ^ 0x8F60,
    }
    mp_idx = u32(T_MP4 + 4 * i)
    if mp_idx != 0xFFFFFFFF:
        r["rva"] = mu64(MP_ARR_RVA + 8 * mp_idx) - BASE
    return r

# ---------------- main ----------------
def main(out_dir="/Users/superhuap/Documents/ida/genshin/7.1/dump_out"):
    import os
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()

    asms = assemblies()
    print(f"[+] {len(asms)} assemblies (pool)")
    for a in asms[:5]:
        print(f"    {a['name']}: types [{a['typeStart']}, {a['typeStart']+a['typeCount']})")

    print(f"[+] decoding {TYPE_COUNT} typedefs…")
    types = []
    bad = 0
    for i in range(TYPE_COUNT):
        try:
            types.append(typedef(i))
        except Exception as e:
            types.append(None); bad += 1
    print(f"    bad={bad}, {time.time()-t0:.1f}s")

    # 方法总量 = max(methodStart + methodCount)
    METHOD_COUNT = 0
    for i in range(TYPE_COUNT):
        t = types[i]
        if t and t["methodStart"] != 0xFFFFFFFF:
            METHOD_COUNT = max(METHOD_COUNT, t["methodStart"] + t["methodCount"])
    print(f"[+] method count (from typedef ranges): {METHOD_COUNT}")

    print(f"[+] decoding methods…")
    methods = []
    for i in range(METHOD_COUNT):
        try:
            methods.append(method(i))
        except Exception:
            methods.append(None)
    print(f"    done {time.time()-t0:.1f}s")

    # dump.cs
    print("[+] writing dump.cs …")
    lines = []
    for a in asms:
        lines.append(f"// Image {a['idx']}: {a['name']} - {a['typeCount']} types")
    lines.append("")
    vis = {0x0: "private", 0x1: "private protected", 0x2: "internal", 0x3: "protected",
           0x4: "protected internal", 0x5: "private protected", 0x6: "public", 0x7: "public"}
    cur_asm = None
    for i, t in enumerate(types):
        if t is None: continue
        if t["methodStart"] == 0xFFFFFFFF: continue
        fl = t["flags"]
        # 找所属 image
        img = None
        for a in asms:
            if a["typeStart"] <= i < a["typeStart"] + a["typeCount"]:
                img = a; break
        if img != cur_asm:
            cur_asm = img
            if img: lines.append(f"\n// Image: {img['name']}")
        ns = t["namespace"]
        if ns: lines.append(f"\nnamespace {ns}")
        lines.append(f"class {t['name']} // TypeDef: {i} flags: 0x{fl:04X}")
        lines.append("{")
        for k in range(t["methodStart"], t["methodStart"] + t["methodCount"]):
            if k >= len(methods): break
            m = methods[k]
            if m is None or m.get("decl") != i: continue
            mf = m["flags"]
            macc = {0:"private",1:"private protected",2:"internal",3:"protected",4:"protected internal",6:"public"}.get(mf & 7, "")
            stat = " static" if mf & 0x10 else ""
            virt = "" if mf & 0x40 else ""
            rva = m.get("rva")
            rvah = f" // RVA: 0x{rva:X}" if rva else ""
            lines.append(f"\t{macc}{stat}{virt} void {m['name']}(){rvah}")
        lines.append("}")
    with open(f"{out_dir}/dump.cs", "w") as f:
        f.write("\n".join(lines))
    print(f"    dump.cs: {len(lines)} lines")

    # JSON
    print("[+] writing dump.json …")
    with open(f"{out_dir}/dump.json", "w") as f:
        json.dump({
            "assemblies": asms,
            "types": [t if t else None for t in types],
            "methods": methods,
        }, f, ensure_ascii=False)
    print(f"[+] DONE in {time.time()-t0:.1f}s -> {out_dir}")

if __name__ == "__main__":
    main()
