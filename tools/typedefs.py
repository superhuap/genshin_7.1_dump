#!/usr/bin/env python3
"""typedef 表(70B @180)离线解码 + 验证。"""
import struct, sys
sys.path.insert(0, "/Users/superhuap/Documents/ida/genshin/7.1/tools")
from gi71 import _raw, _module, h32, M32, decode_string

# 表文件偏移 = 528 + hdr值(相对52C0)
T_TYPEDEF = 528 + (h32(180) - 330781793) & M32     # 70B typedef
T_M12     = 528 + (h32(144) - 1222291392) & M32    # 12B method-info
T_14B     = 528 + (h32(192) - 1630172749) & M32    # 14B
T_U16     = 528 + (h32(236) - 1757766433) & M32    # u16
T_10B     = 528 + (h32(288) - 499562099) & M32     # 10B
T_4B      = 528 + (h32(424) ^ 0x13FD57CF) & M32    # 4B indirection
T_G12     = 528 + (h32(472) ^ 0x1F85ABE5) & M32    # 12B generic
T_M4      = 528 + (h32(516) - 450622139) & M32     # 4B method encoded
T_PTI     = 528 + (h32(376) - 1377001944) & M32    # 4B per-type idx → M12
T_GENRNG  = 528 + (h32(232) ^ 0x4870FAF8) & M32    # 8B generic ranges

TYPE_COUNT = ((h32(8) - 1823609295) & M32) >> 2

def u32(off): return struct.unpack_from("<I", _raw, off)[0]
def u16(off): return struct.unpack_from("<H", _raw, off)[0]
def u8(off):  return _raw[off]

def typedef(i):
    o = T_TYPEDEF + 70 * i
    r = {}
    r["nameIdx"]     = (u32(o + 36) - 72511848) & M32
    r["byvalType"]   = u32(o + 4) ^ 0xDA4711B       # → 16B type 表
    r["type2"]       = u32(o + 20) ^ 0x67A02A49
    r["declaring"]   = (u32(o + 16) - 1950851500) & M32   # -1 哨兵=1950851499
    r["element"]     = (u32(o + 24) - 1031049247) & M32   # -1 哨兵=1031049246
    r["f40"]         = (u32(o + 40) - 1096399758) & M32
    r["genericCls"]  = u32(o + 44) ^ 0x5591B379
    r["methodStart"] = u32(o + 32) ^ 0x2E8C0EB8
    r["methodCnt"]   = (u8(o + 65) - 114) & 0xFF
    r["cnt66"]       = (u8(o + 66) - 3) & 0xFF
    r["cnt48"]       = (u16(o + 48) + 4806) & 0xFFFF
    r["flags58"]     = u16(o + 58)
    r["f62"]         = u16(o + 62)
    # method-info 记录
    pti = (u32(T_PTI + 4 * i) - 0) & M32
    r["pti"] = pti
    if pti != 0xFFFFFFFF and pti < 0x200000:
        mo = T_M12 + 12 * pti
        r["mi_d0"]  = u32(mo)          # → class+186
        r["mi_b4"]  = u8(mo + 4)
        r["mi_b6"]  = u8(mo + 6)
        r["mi_b7"]  = u8(mo + 7)
    return r

print(f"typedef 表 @0x{T_TYPEDEF:X}, typeCount={TYPE_COUNT}")
print(f"M12@0x{T_M12:X} 14B@0x{T_14B:X} M4@0x{T_M4:X} PTI@0x{T_PTI:X}\n")

print("== mscorlib 前 30 个类型(typeStart=0, typeCount=1493) ==")
for i in range(30):
    r = typedef(i)
    name = decode_string(r["nameIdx"])
    try: name = name.decode("utf-8", "replace")
    except: pass
    print(f"  [{i:4d}] {name!r:34} mStart={r['methodStart']:6d} mCnt={r['methodCnt']:3d} "
          f"c66={r['cnt66']:3d} c48={r['cnt48']:4d} decl={r['declaring'] if r['declaring']<0x80000000 else -1:6d} "
          f"fl={r['flags58'] & 0xFFFF:04X} pti={r['pti']} mi0={r.get('mi_d0','-')}")
