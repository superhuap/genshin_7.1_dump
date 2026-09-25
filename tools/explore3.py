#!/usr/bin/env python3
"""在 pool_metadata 中寻找结构化记录(候选 typeDef 88B 数组)。"""
import struct, json
from pathlib import Path

DUMP = Path("/Users/superhuap/Documents/ida/genshin/7.1/gi_dump")
info = json.loads((DUMP / "info.json").read_text())
poolm = (DUMP / "pool_metadata.bin").read_bytes()
POOLM = info["pool_meta_base"]
N = len(poolm)

def looks_like_typedef_run(off):
    """检查 off 处 88B 记录是否像 Il2CppTypeDefinition(连续多条)。"""
    ok = 0
    for k in range(6):
        o = off + k * 88
        if o + 88 > N: break
        d = struct.unpack_from("<16i", poolm, o)
        # 16 个 int 字段应多为小非负索引或 -1
        good = sum(1 for v in d if -1 <= v < 0x400000)
        cnts = struct.unpack_from("<8H", poolm, o + 64)
        cgood = sum(1 for v in cnts if v < 0x2000)
        if good >= 14 and cgood >= 6:
            ok += 1
    return ok >= 5

print("扫描 88B 对齐的 typeDef 候选区…")
hits = []
for off in range(0, N - 88 * 8, 4):
    if looks_like_typedef_run(off):
        hits.append(off)
        if len(hits) > 40: break
for h in hits[:20]:
    print(f"  pool+0x{h:X}")
    for k in range(2):
        d = struct.unpack_from("<16i8H2I", poolm, h + k * 88)
        print(f"    rec{k}: ints={d[:16]}")
        print(f"          u16={d[16:24]} bit=0x{d[24]:08X} token=0x{d[25]:08X}")

# 也扫 12B 记录(methodSpec 风格: int,int,int)与 56B(method def)
print("\n扫描 12B methodSpec 候选区(int,int,int 且值域合理, 连续 64 条)…")
hits12 = []
for off in range(0, min(N, 1 << 26) - 12 * 64, 4):
    good = 0
    for k in range(64):
        a, b, c = struct.unpack_from("<3i", poolm, off + k * 12)
        if -1 <= a < 0x800000 and -1 <= b < 0x800000 and -1 <= c < 0x800000:
            good += 1
    if good == 64:
        hits12.append(off)
        if len(hits12) > 20: break
for h in hits12[:10]:
    print(f"  pool+0x{h:X}: {struct.unpack_from('<9i', poolm, h)}")
