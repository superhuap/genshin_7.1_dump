#!/usr/bin/env python3
"""gi_dump 诊断/转换骨架。

用法:
    python3 convert.py <gi_dump 目录>

第一阶段:验证 dump 完整性、解析 info.json、检查 raw_global.bin 的魔数
(磁盘上文件以 "MHY\\0" 开头且整体加密;运行期缓冲可能已被就地解密,
 也可能仍是密文——由本脚本判定),打印各池统计。
第二阶段(待真实 dump 到手后迭代):从池与全局表重建标准 metadata。
"""
import json
import struct
import sys
from pathlib import Path

MHY = b"MHY\x00"
KNOWN_ENTROPY_MARKERS = ("MHY", "FAB11BAF", "2CFEFC2E")


def entropy(buf: bytes, n: int = 4096) -> float:
    if not buf:
        return 0.0
    from collections import Counter
    c = Counter(buf[:n])
    total = min(n, len(buf))
    ent = 0.0
    for v in c.values():
        p = v / total
        if p:
            ent -= p * __import__("math").log2(p)
    return ent


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def u64(b, off):
    return struct.unpack_from("<Q", b, off)[0]


def main(dump_dir: str):
    d = Path(dump_dir)
    if not d.is_dir():
        sys.exit(f"not a directory: {d}")

    info_path = d / "info.json"
    if not info_path.exists():
        sys.exit("info.json missing - dump incomplete?")
    info = json.loads(info_path.read_text())

    print("== info.json ==")
    for k, v in info.items():
        print(f"  {k:24s} = 0x{v:X}" if isinstance(v, int) else f"  {k:24s} = {v}")

    # --- globals blob ---
    glo = (d / "globals.bin").read_bytes()
    base_off = info["globals_blob_rva"] - info["image_base"]

    def g64(rva):
        return u64(glo, rva - info["globals_blob_rva"])

    print("\n== globals ==")
    for rva in range(info["globals_blob_rva"], info["globals_blob_rva"] + len(glo), 8):
        v = u64(glo, rva - info["globals_blob_rva"])
        print(f"  0x{0x140000000 + rva:09X} = 0x{v:016X}")

    # --- raw global buffer state ---
    raw_p = d / "raw_global.bin"
    if raw_p.exists():
        b = raw_p.read_bytes()
        head = b[:64]
        print(f"\n== raw_global.bin ({len(b)} bytes) ==")
        print("  head:", head.hex())
        print(f"  entropy[0:4k]   = {entropy(b):.2f}")
        print(f"  entropy[0x200000:] = {entropy(b[0x200000:]):.2f}")
        if b.startswith(MHY):
            print("  => still encrypted on-disk form (MHY magic present)")
        else:
            print("  => DECRYPTED in memory! sanity/version dword:",
                  hex(u32(b, 0)), hex(u32(b, 4)))
    else:
        print("\nraw_global.bin missing")

    # --- pools ---
    for name in ("pool_metadata", "pool_genericclass", "pool_genericmethod"):
        p = d / f"{name}.bin"
        if p.exists():
            b = p.read_bytes()
            nz = sum(1 for x in b[:1 << 20] if x)  # sample nonzero
            print(f"\n== {name}.bin ({len(b)} bytes, nonzero sample {nz}/{min(len(b),1<<20)}) ==")
            print("  head:", b[:48].hex())

    # --- module ---
    mod = d / "module.bin"
    if mod.exists():
        print(f"\nmodule.bin: {mod.stat().st_size} bytes")
        m = mod.read_bytes()[:2]
        print("  MZ ok:", m == b"MZ")

    print("\n[骨架] 结构重建逻辑待真实 dump 到手后迭代。")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
