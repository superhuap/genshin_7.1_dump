#!/usr/bin/env python3
"""检查池内干净表:52F8/5308 (75x88B) + 字符串扫描。"""
import struct, json, re
from pathlib import Path

DUMP = Path("/Users/superhuap/Documents/ida/genshin/7.1/gi_dump")
info = json.loads((DUMP / "info.json").read_text())
poolm = (DUMP / "pool_metadata.bin").read_bytes()
POOLM = info["pool_meta_base"]

def pu32(va): return struct.unpack_from("<I", poolm, va - POOLM)[0]
def pu64(va): return struct.unpack_from("<Q", poolm, va - POOLM)[0]

print("== 52F8 表 (75 x 88B) 前 6 条 ==")
t = info["g_52F8"]
for rec in range(6):
    off = (t - POOLM) + rec * 88
    row = poolm[off:off+88]
    print(f"  rec{rec}: {row[:44].hex(' ')}")
    vals = struct.unpack_from("<17I", row, 0)
    print(f"        u32: {['%08X'%v for v in vals]}")
    print(f"        str? {row[44:88].hex(' ')}")

print("\n== 5308 表 (75 x 88B) 前 3 条 ==")
t = info["g_5308"]
for rec in range(3):
    off = (t - POOLM) + rec * 88
    row = poolm[off:off+88]
    vals = struct.unpack_from("<17I", row, 0)
    print(f"  rec{rec}: {['%08X'%v for v in vals]}")

print("\n== 池内 ASCII 字符串扫描(前 2 万条样本)==")
pat = re.compile(rb"[\x20-\x7E]{6,64}")
hits = []
for m in pat.finditer(poolm):
    hits.append((m.start(), m.group()))
    if len(hits) >= 20000: break
print(f"  total(样本上限2万): {len(hits)}")
for off, s in hits[:40]:
    print(f"  +0x{off:X}: {s[:64].decode('ascii', 'replace')}")

# 字符串密集区统计(按 4KB 窗口计可打印字符比例)
print("\n== 字符串密集窗口(可打印比例>60%的前20个 64KB 窗口)==")
win = 1 << 16
dense = []
for w in range(0, min(len(poolm), 1 << 27), win):
    chunk = poolm[w:w+win]
    printable = sum(1 for x in chunk if 0x20 <= x <= 0x7E)
    if printable / len(chunk) > 0.6:
        dense.append((w, printable / len(chunk)))
for w, r in dense[:20]:
    print(f"  pool+0x{w:X}: {r:.0%}")
print(f"  dense windows total: {len(dense)}")
