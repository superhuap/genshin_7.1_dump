// string.cpp —— 7.1 字符串 blob 解码
//
// index: [31:24]=长度  [23:0]=blob 内偏移;  0x8 与 0xFFFFFFFF 表示空串。
// 源位置 = ctx.strBlob + off
// k0     = 0x5C2B4E660E2D0544 * ((0x694418957C890198*off) ^ 0x55A357D81EF0E48B)
// stride = [SSE+8]                     线性步进
// 常量   = [SSE+0],[SSE+16],[SSE+24],[SSE+32],[SSE+40]   (c0, c1, c3, c2, c4)
//
// blocks < 8 : 纯线性 (c ^ k, k += stride)
// blocks >= 8: 前 (blocks & ~1) 块走 SSE 状态机, 剩余块回到线性
//
// v5 改动: SSE 常量改从 ctx.exeImage 取(运行期映射 或 磁盘副本都行),
//          源位置改用 ctx.strBlob(v5 不再有 ctx.strRegion)。
#include "dumper.h"
#include <cstring>
#include <cstdio>

namespace gs {

static uint64_t key0_of(uint32_t off) {
    return 0x5C2B4E660E2D0544ULL *
           (((0x694418957C890198ULL * off) & 0xFFFFFFFFFFFFFFFFULL) ^ 0x55A357D81EF0E48BULL);
}
static uint64_t swap32(uint64_t q) { return (q << 32) | (q >> 32); }

// IDA 已确认的兜底常数(exe 里那 48B 读不到时用)
static const uint64_t kFbStride = 0x6B0B40C349AE61E5ULL;

struct SseConst { uint64_t c0, stride, c1, c3, c2, c4; bool ok; };
static SseConst g_sse = { 0, kFbStride, 0, 0, 0, 0, false };

static void InitSse(const GameCtx& ctx) {
    if (g_sse.ok) return;
    // SSE 常量是 exe 映像里的静态数据, 用 AtRva 换算(运行期/磁盘两种形态都成立)
    const uint8_t* p = AtRva(ctx, kRvaSse);
    if (p && memReadable(p, 48)) {
        g_sse.c0     = rd64(p + 0);
        g_sse.stride = rd64(p + 8);
        g_sse.c1     = rd64(p + 16);
        g_sse.c3     = rd64(p + 24);
        g_sse.c2     = rd64(p + 32);
        g_sse.c4     = rd64(p + 40);
    }
    if (!g_sse.stride) g_sse.stride = kFbStride;
    g_sse.ok = true;
}

std::string DecodeString(const GameCtx& ctx, uint32_t index) {
    if (index == 0xFFFFFFFFu || index == 0x8u) return std::string();
    uint32_t ln  = (index >> 24) & 0xFF;
    uint32_t off = index & 0xFFFFFF;
    if (!ln || !ctx.strBlob) return std::string();
    InitSse(ctx);

    uint32_t blocks = (ln + 7) >> 3;
    const uint8_t* base = ctx.strBlob + off;
    if ((uint64_t)base + (uint64_t)blocks * 8 > ctx.strBlobEnd) return std::string();

    uint8_t  buf[1024];
    uint32_t cap = (uint32_t)sizeof(buf);
    uint32_t need = blocks * 8;
    if (need > cap) need = cap & ~7u;
    if (!need) return std::string();

    uint64_t k0 = key0_of(off);
    uint32_t j = 0;
    if (blocks < 8) {
        for (; j * 8 < need; ++j) {
            uint64_t k = k0 + g_sse.stride * (uint64_t)j;
            uint64_t v = rd64(base + 8ull * j) ^ k;
            memcpy(buf + 8 * j, &v, 8);
        }
    } else {
        uint32_t nSse = blocks & ~1u;
        uint64_t sw  = swap32(k0);
        uint64_t sA  = k0 + g_sse.c0;
        uint64_t sB  = sw + g_sse.c1;
        while (j < nSse && j * 8 < need) {
            uint64_t it = (uint64_t)(j >> 1);
            uint64_t K0 = sA + it * g_sse.c2;
            uint64_t K1 = sB + it * g_sse.c4;
            uint32_t n = need / 8 - j;
            if (n > 4) n = 4;
            if (n > nSse - j) n = nSse - j;
            for (uint32_t sub = 0; sub < n; ++sub) {
                uint64_t key = (sub < 2) ? (sub == 0 ? K0 : K1) : ((sub == 2 ? K0 : K1) + g_sse.c3);
                uint64_t v = rd64(base + 8ull * (j + sub)) ^ key;
                memcpy(buf + 8 * (j + sub), &v, 8);
            }
            j += n;
        }
        for (; j * 8 < need; ++j) {                       // 剩余块回到线性
            uint64_t k = k0 + g_sse.stride * (uint64_t)j;
            uint64_t v = rd64(base + 8ull * j) ^ k;
            memcpy(buf + 8 * j, &v, 8);
        }
    }
    return std::string((const char*)buf, ln);
}

// 名字里有相当一部分不是合法 UTF-8(v3 实测: 直接把原始字节写进 dump.cs 会留下
// 3420 行 U+FFFD 替换符, 而 v3 因为有回退是 0 行)。按 v3 的做法逐字节校验:
// 合法就原样返回, 不合法按 latin1 映射, 保证产物永远是合法文本。
static bool ValidUtf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        size_t need;
        if (c < 0x80)                          need = 0;
        else if ((c & 0xE0) == 0xC0)           need = 1;
        else if ((c & 0xF0) == 0xE0)           need = 2;
        else if ((c & 0xF8) == 0xF0)           need = 3;
        else return false;
        if (i + need >= n + 1) return false;
        for (size_t k = 1; k <= need; ++k)
            if (((unsigned char)s[i + k] & 0xC0) != 0x80) return false;
        i += need + 1;
    }
    return true;
}

std::string DecodeStringLossless(const GameCtx& ctx, uint32_t index) {
    std::string raw = DecodeString(ctx, index);
    if (raw.empty() || ValidUtf8(raw)) return raw;
    std::string out;
    out.reserve(raw.size() + 8);
    for (unsigned char c : raw) {
        if (c < 0x80) out += (char)c;
        else { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
    }
    return out;
}

} // namespace gs
