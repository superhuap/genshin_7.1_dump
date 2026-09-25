#!/usr/bin/env python3
"""从池 dump 直接读取已构建的 image/assembly 表(运行期已解码,仅指针XOR混淆)。"""
import struct, json, sys
sys.path.insert(0, "/Users/superhuap/Documents/ida/genshin/7.1/tools")
from gi71 import _poolm, _info, _raw, _module, decode_string

POOLM = _info["pool_meta_base"]
IMG = _info["g_5308"] - POOLM     # image 表池内偏移
ASM = _info["g_52F8"] - POORM if False else _info["g_52F8"] - POOLM

def p64(off): return struct.unpack_from("<Q", _poolm, off)[0]
def p32(off): return struct.unpack_from("<I", _poolm, off)[0]

def pool_str(ptr):
    """从池读 NUL 结尾字符串。"""
    off = ptr - POOLM
    if off < 0 or off >= len(_poolm): return None
    end = _poolm.find(b"\0", off)
    if end < 0: end = off + 64
    return _poolm[off:end]

X64  = 0x783FCBBE2E713C7F   # image +64 name ptr
X48  = 0x3351BD851F7B567F   # image +48 nameNoExt ptr
X8   = 0x1D2861AD1B868E81   # image +8 assembly ptr

print("== 池内 image 表 (75 x 88B) ==")
print(f"{'i':>3} {'name64':28} {'name48':28} +16/+20(+16q)  +32      +36      +24      +72")
for i in range(75):
    o = IMG + 88 * i
    name64 = pool_str(p64(o + 64) ^ X64)
    name48 = pool_str(p64(o + 48) ^ X48)
    f16 = p32(o + 16); f20 = p32(o + 20)
    f32 = p32(o + 32); f36 = p32(o + 36); f24 = p32(o + 24); f72 = p32(o + 72)
    n64 = (name64 or b"").decode("ascii", "replace")
    n48 = (name48 or b"").decode("ascii", "replace")
    print(f"{i:3d} {n64:28} {n48:28} {f16:8X} {f20:8X} {f32:8X} {f36:8X} {f24:8X} {f72:8X}")

print("\n== 池内 assembly 表 (75 x 88B) 前 10 ==")
for i in range(10):
    o = ASM + 88 * i
    # assembly +64 = name ptr ^ 0x2C559A9973CA0315 (Block 0 sentinel)
    name = pool_str(p64(o + 64) ^ 0x2C559A9973CA0315)
    vals = struct.unpack_from("<22I", _poolm, o)
    print(f"asm{i:3d}: name={name!r}")
    print(f"        {[hex(v) for v in vals]}")
