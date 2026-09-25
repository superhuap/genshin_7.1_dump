#!/usr/bin/env python3
"""探索 gi_dump:提取静态注册结构 + 检查池内干净表。"""
import struct, json, sys
from pathlib import Path

DUMP = Path("/Users/superhuap/Documents/ida/genshin/7.1/gi_dump")
BASE = 0x7FF75C2A0000

info = json.loads((DUMP / "info.json").read_text())
module = (DUMP / "module.bin").read_bytes()
poolm = (DUMP / "pool_metadata.bin").read_bytes()
POOLM_BASE = info["pool_meta_base"]          # 0x50000000000

def mod_u64(rva):  return struct.unpack_from("<Q", module, rva)[0]
def mod_u32(rva):  return struct.unpack_from("<I", module, rva)[0]
def poolm_u64(va): return struct.unpack_from("<Q", poolm, va - POOLM_BASE)[0]
def poolm_u32(va): return struct.unpack_from("<I", poolm, va - POOLM_BASE)[0]
def to_rva(va):
    if BASE <= va < BASE + info["image_size"]: return va - BASE
    return None

print("== 静态结构 @52A0 (RVA 0x2870A88) ==")
r = 0x2870A88
for i in range(0, 0x100, 8):
    v = mod_u64(r + i)
    print(f"  +0x{i:02X}: 0x{v:016X}  (rva={to_rva(v) if isinstance(v,int) else ''}")

print("\n== 静态结构 @52A8 (RVA 0x2870B28) ==")
r = 0x2870B28
for i in range(0, 0x100, 8):
    v = mod_u64(r + i)
    print(f"  +0x{i:02X}: 0x{v:016X}")

print("\n== 'header' 副本 @52B8 (RVA 0x27D4BD0) 前 0x220 字节 ==")
r = 0x27D4BD0
for i in range(0, 0x110, 8):
    lo = mod_u32(r + i); hi = mod_u32(r + i + 4)
    print(f"  +0x{i:03X}: {lo:08X} {hi:08X}")
