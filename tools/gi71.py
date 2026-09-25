#!/usr/bin/env python3
"""Genshin 7.1 global-metadata 离线解码工具包(持续完善)。"""
import struct, json
from pathlib import Path

DUMP = Path("/Users/superhuap/Documents/ida/genshin/7.1/gi_dump")
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

_module = (DUMP / "module.bin").read_bytes()
_raw = (DUMP / "raw_global.bin").read_bytes()
_poolm = (DUMP / "pool_metadata.bin").read_bytes()
_info = json.loads((DUMP / "info.json").read_text())
_startup = open("/Users/superhuap/Documents/ida/genshin/7.1/startup-metadata.dat", "rb").read()

H_EMB = 0x27D4BD0          # exe 内嵌混淆 header RVA
STR_QWORD0_OFF = None      # 运行期计算

# ---------------- 内嵌 header(528B)字段公式(来自 init/访问者反编译) ----
# (offset, op, const)  op: 'sub' = v-const, 'xor' = v^const
HEADER_FIELDS = {
    8:   ("sub", 1823609295),   # (v-c)>>2 = typeCount
    44:  ("sub", 610644003),    # /0x28 = 汇编数
    120: ("sub", 432378149),    # startup 44B 表偏移
    144: ("sub", 1222291392),   # g 12B 表
    172: ("xor", 0x7D85E99F),   # startup int 表
    180: ("sub", 330781793),    # g 70B 字段表
    184: ("sub", 1241239214),   # startup int 表
    192: ("sub", 1630172749),   # g 14B 表
    212: ("sub", 585353259),    # 14B 计数
    220: ("sub", 1009555078),   # >>4 = image 数
    224: ("sub", 486952835),    # size
    236: ("sub", 1757766433),   # g u16 表
    280: ("sub", None),         # (v>>2)^0x11BB5358 usage计数
    288: ("sub", 499562099),    # g 10B 表
    304: ("sub", 565220529),    # /14
    308: ("xor", 0x558E11EC),   # startup {start,count}
    384: ("sub", 898198093),    # startup int 数组
    388: ("sub", 1080211659),   # 字符串数据区!
    392: ("xor", 0x1B58E334),   # usage 计数
    424: ("xor", 0x13FD57CF),   # g 4B 表
    436: ("sub", 267406932),    # /3 缓存计数
    440: ("sub", 768000888),    # startup 16B 表
    472: ("xor", 0x1F85ABE5),   # g 12B 泛型核心表
    504: ("sub", 2051052385),   # startup
    516: ("sub", 450622139),    # g 4B 方法索引表
    524: ("sub", 248195061),    # startup 字符串表
}

def h32(off):
    return struct.unpack_from("<I", _module, H_EMB + off)[0]

def hdr(off):
    """解码内嵌 header 字段。"""
    v = h32(off)
    f = HEADER_FIELDS.get(off)
    if f is None:
        return v
    op, c = f
    if c is None:
        return v
    return (v - c) & M32 if op == "sub" else v ^ c

# ---------------- 字符串解码(sub_14050F280 精确复刻) ----------------------
_STR_BASE = None
_STEP = 0x6B0B40C349AE61E5
_C0 = struct.unpack("<2Q", _module[0x39085D0:0x39085E0])   # {0, STEP}
_C1 = struct.unpack("<2Q", _module[0x39085E0:0x39085F0])
_C2 = struct.unpack("<2Q", _module[0x39085F0:0x3908600])

def _str_region_file_off():
    # 52C0 = 文件基址+528; 源 = 52C0 + (header@388 + 0xBF9D4735) + idx24
    return 528 + ((h32(388) + 0xBF9D4735) & M32)

def _key0(idx):
    return (0x5C2B4E660E2D0544 * (((0x694418957C890198 * idx) & M64) ^ 0x55A357D81EF0E48B)) & M64

def _swap32(q):
    return ((q & 0xFFFFFFFF) << 32) | (q >> 32)

def decode_string(index):
    """index: 32位打包索引 [31:24]=长度 [23:0]=字节偏移。返回解码字符串。"""
    if index == 0xFFFFFFFF or index < 0:
        return b""
    ln = (index >> 24) & 0xFF
    idx24 = index & 0xFFFFFF
    if ln == 0:
        return b""
    blocks = (ln + 7) >> 3
    base = _str_region_file_off() + idx24
    out = bytearray()
    k0 = _key0(idx24)
    if blocks < 8:
        # 纯线性: key_i = key0 + i*STEP
        k = k0
        for i in range(blocks):
            c = struct.unpack_from("<Q", _raw, base + 8 * i)[0]
            out += struct.pack("<Q", (c ^ k) & M64)
            k = (k + _STEP) & M64
    else:
        # SSE: 前 blocks&~1 块用状态机, 其余线性
        n_sse = blocks & ~1
        S0 = [(k0 + _C0[0]) & M64, (_swap32(k0) + _C0[1]) & M64]
        iters = 0
        j = 0
        while j < n_sse:
            K = [(S0[0] + iters * _C2[0]) & M64, (S0[1] + iters * _C2[1]) & M64]
            for sub in range(min(4, n_sse - j)):
                if sub < 2:
                    key = K[sub]
                else:
                    key = (K[sub - 2] + _C1[sub - 2]) & M64
                c = struct.unpack_from("<Q", _raw, base + 8 * (j + sub))[0]
                out += struct.pack("<Q", (c ^ key) & M64)
            j += 4
            iters += 1
        for i in range(n_sse, blocks):
            c = struct.unpack_from("<Q", _raw, base + 8 * i)[0]
            k = (k0 + _STEP * i) & M64
            out += struct.pack("<Q", (c ^ k) & M64)
    s = bytes(out[:ln])
    return s

def decode_string_at(offset, length):
    return decode_string((length << 24) | (offset & 0xFFFFFF))

# ---------------- 镜像表(startup 16B + 44B → 88B image 记录) -------------
def _v144(i):
    return ((-1889820753 * i + 992946705) & M32) ^ 0x151AADA5

def _v146(i):
    v = (53443 * i + 499759382) & M32
    v = (638429142 * v) & M64          # 64位中间
    v >>= 19
    v = (1048266170 * v + 0xE6CC8E163578) & M64
    return v >> 20

_K70 = struct.unpack("<2I", _module[0x3908670:0x3908678])
_K80 = struct.unpack("<2I", _module[0x3908680:0x3908688])

def decode_images():
    """从 startup-metadata 解码 75 条 image 记录(与池中 5308 表对齐验证)。"""
    n = 75
    t16 = (hdr(440) - 768000888 if False else (h32(440) - 768000888) & M32)
    t44 = (h32(120) - 432378149) & M32
    imgs = []
    for i in range(n):
        v144 = _v144(i); v146 = _v146(i)
        r16 = _startup[t16 + 16 * i: t16 + 16 * i + 16]
        r44 = _startup[t44 + 44 * i: t44 + 44 * i + 44]
        f = {}
        f["+0"]  = ((struct.unpack_from("<I", r16, 12)[0] ^ 0x4F2F94C7) - v144 + 633535241) & M32
        d0, d1 = struct.unpack_from("<2I", r16, 0)
        f["+16"] = (((d0 ^ _K70[0]) - v144) & M32) ^ _K80[0]
        f["+20"] = (((d1 ^ _K70[1]) - v144) & M32) ^ _K80[1]
        f["+24"] = (((struct.unpack_from("<I", r44, 20)[0] ^ 0x37A6CDCF) - v146) & M32) ^ 0x1928A675
        f["+28"] = (struct.unpack_from("<I", r44, 24)[0] - v146 + 1269573744) & M32
        f["+32"] = (struct.unpack_from("<I", r44, 12)[0] - v146 + 1408943775) & M32
        f["+36"] = (((struct.unpack_from("<I", r44, 32)[0] ^ 0x17547D30) - v146) & M32) ^ 0x3F29DDF2
        f["+40"] = ((struct.unpack_from("<I", r44, 0)[0] ^ 0x4CBB8EA0) - v146 + 1448417134) & M32
        f["+56"] = (((struct.unpack_from("<I", r44, 16)[0] - v146 - 1030361528) & M32)) ^ 0xF048648
        f["+72"] = (struct.unpack_from("<I", r44, 4)[0] - v146 + 801907957) & M32
        # +64/+48 = 字符串索引(sub_14050F280 参数, 未经解码返回)
        f["+64idx"] = (struct.unpack_from("<I", r44, 8)[0] - v146 - 105501123) & M32
        f["+48idx"] = ((struct.unpack_from("<I", r44, 28)[0] ^ 0x5D9F2783) - v146) & M32
        f["+76lo"] = struct.unpack_from("<I", r44, 36)[0]
        f["+76hi"] = struct.unpack_from("<I", r44, 40)[0]
        f["v144"], f["v146"] = v144, v146
        imgs.append(f)
    return imgs

if __name__ == "__main__":
    print("== 内嵌 header 已知字段解码 ==")
    for off in sorted(HEADER_FIELDS):
        try:
            v = hdr(off)
            print(f"  @{off:3d}: 0x{v:X} ({v})")
        except Exception as e:
            print(f"  @{off:3d}: ERR {e}")
    print(f"\n字符串区文件偏移: 0x{_str_region_file_off():X}")
    print(f"C0={_C0} C1={[hex(x) for x in _C1]} C2={[hex(x) for x in _C2]}")
    print(f"K70={_K70} K80={_K80}")

    print("\n== 字符串抽样 ==")
    for off, ln in [(6289, 7), (6321, 9), (15840, 10), (6131, 8)]:
        print(f"  off={off}: {decode_string_at(off, ln)!r}")

    print("\n== 镜像表解码(前 5) ==")
    imgs = decode_images()
    for i, f in enumerate(imgs[:5]):
        s64 = decode_string(f["+64idx"])
        s48 = decode_string(f["+48idx"])
        print(f"  img{i}: +16/20={f['+16']}/{f['+20']} +32={f['+32']} +36={f['+36']} "
              f"name64={s64!r} name48={s48!r}")
