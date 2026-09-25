#!/usr/bin/env python3
"""方法表(26B @364)解码 + 方法名验证。"""
import struct, sys
sys.path.insert(0, "/Users/superhuap/Documents/ida/genshin/7.1/tools")
from gi71 import _raw, _module, _info, h32, M32, decode_string

T_TYPEDEF = 528 + (h32(180) - 330781793) & M32
T_M26     = 528 + (h32(364) - 483030612) & M32    # 26B 方法记录
T_MP4     = 528 + (h32(148) ^ 0x4A4C0A71) & M32   # 4B → methodPointer 间接表
T_M16     = 528 + (h32(516) - 450622139) & M32    # 4B 编码方法槽表
BASE = _info["image_base"]

# qword_145AD5298 结构在模块 RVA 0x5AD5298? 不对 — 5298 是指针槽
# 从 info.json: g_5298 = 0x7FF75E57E370 → RVA = 0x2DDE370
RVA_5298 = _info["g_5298"] - BASE
MP_ARR = struct.unpack_from("<Q", _module, RVA_5298 + 96)[0]   # methodPointers 数组 VA

def u32(off): return struct.unpack_from("<I", _raw, off)[0]
def u16(off): return struct.unpack_from("<H", _raw, off)[0]
def u8(off):  return _raw[off]
def mu64(rva): return struct.unpack_from("<Q", _module, rva)[0]

def v25(i):  return (((( -16525 * i) & 0xFFFFFFFF) ^ 0x8947) - 24997) & 0xFFFF
def k1(i):   return ((((860405619 * i) & 0xFFFFFFFF) ^ 0x73758947) + 1547935323) & 0xFFFFFFFF
def kdecl(i): return k1(i) ^ 0x59244785
def kbits(i): return ((((115 * i) & 0xFFFFFFFF) ^ 0x47) + 91) & 0xFFFFFFFF

def method(i):
    o = T_M26 + 26 * i
    r = {}
    r["nameIdx"] = k1(i) ^ ((u32(o) - 1524016681) & M32)    # sub_140528080
    r["f4"] = u32(o + 4)        # 疑似 returnTypeIdx
    r["f8"] = u32(o + 8)        # 疑似 paramStart
    r["decl"] = u32(o + 12) ^ kdecl(i)
    r["slot"] = ((u16(o + 16) - 25344) & 0xFFFF) ^ v25(i)
    r["f18"] = u16(o + 18) ^ v25(i) ^ 0x41FB
    r["f20"] = u16(o + 20) ^ v25(i) ^ 0xD73C
    r["flags"] = u16(o + 22) ^ v25(i) ^ 0x8F60   # 实为 MethodAttributes
    # methodPointer
    mp_idx = u32(T_MP4 + 4 * i)
    r["mp_idx"] = mp_idx
    if mp_idx != 0xFFFFFFFF:
        mp_arr_rva = MP_ARR - BASE
        r["mp"] = mu64(mp_arr_rva + 8 * mp_idx)
    return r

def typedef_ms(i):
    """typedef 的 methodStart26/methodCount。"""
    o = T_TYPEDEF + 70 * i
    return u32(o + 12) ^ 0x4D8127F2, (u16(o + 48) + 4806) & 0xFFFF

print(f"26B 方法表 @0x{T_M26:X}, MP4@0x{T_MP4:X}")
print(f"5298 struct RVA=0x{RVA_5298:X}, methodPointers 数组 VA=0x{MP_ARR:X}\n")

# 找 System.Object:遍历 mscorlib (typeStart=0..1492) 找 name=="Object"
for ti in range(0, 1493):
    o = T_TYPEDEF + 70 * ti
    nameIdx = (u32(o + 36) - 72511848) & M32
    nm = decode_string(nameIdx)
    if nm == b"Object":
        nsIdx = None
        ms, mc = typedef_ms(ti)
        print(f"System.Object: typeIdx={ti}, methodStart={ms}, methodCount={mc}")
        for k in range(ms, ms + mc):
            m = method(k)
            name = decode_string(m["nameIdx"])
            try: name = name.decode()
            except: name = repr(name)
            print(f"  [{k:6d}] {name:32} decl={m['decl']:6d} slot={m['slot']:4d} "
                  f"flags=0x{m['flags'] & 0xFFFF:04X} f20=0x{m['f20']:04X} "
                  f"mp={'0x%X' % m['mp'] if 'mp' in m else 'None'}")
        break
