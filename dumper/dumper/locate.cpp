#include "dumper.h"
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdio>
#include <cstdarg>
#include <cstdlib>

namespace gs {

// ---- 进度输出 ----
static ProgressFn g_progress = nullptr;
void SetProgress(ProgressFn fn) { g_progress = fn; }
void Progress(const char* fmt, ...) {
    if (!g_progress) return;                       // 离线测试: 静默
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[strcspn(buf, "\r\n")] = 0;
    g_progress(buf);
}
uint64_t NowMs() {
#ifdef _WIN32
    return (uint64_t)GetTickCount();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

std::string hex64(uint64_t v) {
    char b[32]; snprintf(b, sizeof b, "0x%016llX", (unsigned long long)v); return b;
}
std::string dec(uint64_t v) {
    char b[32]; snprintf(b, sizeof b, "%llu", (unsigned long long)v); return b;
}
// asSigned=true 时按 int64 解释(用于 -1 这类"无偏移"哨兵)
std::string dec(uint64_t v, bool asSigned) {
    if (!asSigned) return dec(v);
    char b[32]; snprintf(b, sizeof b, "%lld", (long long)v); return b;
}
void AppendDiag(GameCtx& ctx, const std::string& s) { ctx.diag += s; }

// ---- 崩溃现场 ----
char     g_stage[128] = "init";
uint32_t g_stageIdx = 0;
uint64_t g_stageVal = 0;
void SetStage(const char* s, uint32_t idx, uint64_t val) {
    strncpy(g_stage, s, sizeof(g_stage) - 1);
    g_stage[sizeof(g_stage) - 1] = 0;
    g_stageIdx = idx;
    g_stageVal = val;
}


// native 回归: 把读进来的缓冲区登记进来, 让 memReadable 真的能判界。
// 真机上这块是空的 —— 走 VirtualQuery。
#ifndef _WIN32
namespace {
struct Region { const uint8_t* lo; const uint8_t* hi; };
std::vector<Region>& Regions() { static std::vector<Region> v; return v; }
}
void RegisterRegion(const void* p, size_t n) {
    Regions().push_back({(const uint8_t*)p, (const uint8_t*)p + n});
}
uint64_t g_memReadableCalls = 0;   // 诊断: 真机上每次都是一次 VirtualQuery
bool memReadable(const void* p, size_t n) {
    ++g_memReadableCalls;
    const uint8_t* b = (const uint8_t*)p;
    if (!p || !n) return false;
    for (const Region& r : Regions())
        if (b >= r.lo && b + n <= r.hi) return true;
    return false;
}
#else
uint64_t g_memReadableCalls = 0;
bool memReadable(const void* p, size_t n) {
    ++g_memReadableCalls;
    const uint8_t* b = (const uint8_t*)p;
    size_t left = n;
    while (left) {
        MEMORY_BASIC_INFORMATION mi;
        if (!VirtualQuery(b, &mi, sizeof(mi))) return false;
        if (mi.State != MEM_COMMIT) return false;
        if (mi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        if (!(mi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            return false;
        uintptr_t end = (uintptr_t)mi.BaseAddress + mi.RegionSize;
        if (end <= (uintptr_t)b) return false;
        size_t chunk = end - (uintptr_t)b;
        if (chunk >= left) return true;
        left -= chunk; b += chunk;
    }
    return true;
}
#endif

// ---------------------------------------------------------------- 特性登记 --
static const FeatureInfo kFeatures[FEAT__COUNT] = {
    { "真实字段偏移",   "hdr+316 (4B)",        true,  "7.1 = hdr+296^0x0F92DC85, 经 desc12[hidx4[ti]]+8 索引; 偏移域含 16B 对象头" },
    { "字段定义 12B",   "hdr+332",             false, "7.1 = hdr+144+0x0B7255040 (每类型描述符), 已用于取偏移, 其余字段未解" },
    { "枚举成员",       "hdr+464 (8B)",        true,  "7.1 = 字段表本身(按 value__ 判枚举) + 常量表 hdr+316^0x593DE464" },
    { "字段默认值",     "hdr+480/32/384/180",  false, "7.1 表已定位(hdr+428/216), 但值语义是 RVA 列表不是常量 -> 见 FORMULAS 13" },
    { "枚举字面值",     "hdr+12/432",          true,  "同一张常量表: 值字节在 hdr+160^0x3F525210, 按底层类型宽度读" },
    { "泛型实例展开",   "hdr+280 (16B)",       false, "7.1 静态表无实参; 堆表链已定位(g_52F8 区)但实参下标换算未验证 -> 强制关闭, 输出 genericinst@N" },
    { "接口方法 slot",  "hdr+504 (6B)",        false, "7.1 元数据里没有: 接口表只存 Il2CppClass, slot 运行期算(FORMULAS 19.1)" },
    { "数组/泛型元素",  "hdr+72 (14B)",        false, "未移植" },
};
const FeatureInfo& FeatureById(int id) {
    if (id < 0 || id >= FEAT__COUNT) { static FeatureInfo bad{"?","?",false,"?"}; return bad; }
    return kFeatures[id];
}


// ---------------------------------------------------------------- 表定位 ----
// h32 = 528B header 的第 field 字节
static uint32_t H32(const GameCtx& ctx, int field) { return rd32(ctx.hdr + field); }

// 表基址的通用形态: table = blob + 528 + (h32(field) OP CONST)
uint8_t* ResolveTable(const GameCtx& ctx, TableSpec s) {
    uint32_t h = H32(ctx, s.field);
    uint32_t off = (s.op == '-') ? (h - s.konst) : (s.op == '^' ? (h ^ s.konst) : (h + s.konst));
    return ctx.blob + kHeaderBytes + (uint64_t)off;
}

// RVA -> 指针。⚠️ RVA(虚拟地址偏移)**不是**文件偏移(原始偏移), 两者差一个
//    section 内的 delta, 必须过 section 表换算。7.1 的 section 表是**正常**的
//    13 段(.text/.rdata/.data/pdata/.../il2cpp/.upx0/.reloc/.rsrc), 不是加密的。
//    例: RVA 0x2870B90(真 MPT) 在 .rdata, 文件偏移 = 0x021A9000 + (0x2870B90-0x21AA000)。
//    运行期映像则 RVA == 偏移, 不必换算。
const uint8_t* AtRva(const GameCtx& ctx, uint64_t rva) {
    if (!ctx.exeLo) return nullptr;
    if (ctx.exeMapped) {
        // 运行期映像按 RVA 连续映射, 一次整数比较就够 —— 不要在这里 memReadable,
        // 它在热路径上(每次解析复合类型都要走)且真机是 VirtualQuery。
        if (rva + 16 > ctx.imageSize) return nullptr;
        return ctx.exeLo + rva;
    }
    for (int i = 0; i < ctx.sectionCount; ++i) {
        const GameCtx::Section& s = ctx.sections[i];
        if (rva < s.va || rva >= (uint64_t)s.va + s.vsize) continue;
        uint64_t delta = rva - s.va;
        if (delta >= s.rawSize) return nullptr;         // 落在未初始化区(.bss)
        return ctx.exeLo + s.raw + delta;
    }
    return nullptr;
}

// ⚠️ 不要额外要求 16 字节对齐 —— 复合类型(PTR/BYREF/SZARRAY/ARRAY)指向的元素记录
//    在文件里并不保证 16B 对齐。加了对齐要求会把一批字段类型从 "array<...>" 退化成 "?"
//    (v3 实测: 字段语义一致率从 99.741% 掉下来)。边界检查本身就足够区分两种 VA 形态:
//    运行期 base 高达 0x7FF6ACFD0000, `va - kImageBase` 会远远落到 SizeOfImage 之外。
//    对齐只用来在"两个候选都在界内"时挑更可信的那个。
uint64_t RvaFromVa(const GameCtx& ctx, uint64_t va) {
    if (!va || !ctx.exeLo || !ctx.imageSize) return 0;
    uint64_t cand[2];
    int n = 0;
    uint64_t primary = 0;
    if (va >= ctx.vaBias) { primary = va - ctx.vaBias; cand[n++] = primary; }
    if (va >= kImageBase) {
        uint64_t alt = va - kImageBase;
        if (alt != primary) cand[n++] = alt;
    }
    for (int i = 0; i < n; ++i)                                   // 先取界内的
        if (cand[i] + 16 <= ctx.imageSize) return cand[i];
    for (int i = 0; i < n; ++i) {                                 // 退而求其次
        if (cand[i] + 16 <= ctx.imageSize && (cand[i] % 16) == 0) return cand[i];
    }
    return 0;
}

// ============================================================================
//  纯内存初始化(照搬 7.0 dumper 的 InitCtx 骨架)
// ============================================================================

// 表基址的边界哨兵: 沿可读页走到分配末尾。7.0 用它做快速边界检查, 比每次
// memReadable 便宜一个数量级(热路径上要跑几十万次)。
static uint64_t RegionEnd(const uint8_t* p) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQuery(p, &mi, sizeof(mi))) return 0;
    if (mi.State != MEM_COMMIT) return 0;
    return (uint64_t)mi.BaseAddress + mi.RegionSize;
#else
    // 离线测试: 用登记的缓冲区模拟, 这样 memReadable 调用次数与真机可比
    for (const Region& r : Regions())
        if (p >= r.lo && p < r.hi) return (uint64_t)r.hi;
    return 0;
#endif
}

// 探测一个 32B 记录堆表能放下多少条: 从 base 开始, 只要 (base + n*32 + 32) 仍可读就算一条。
// 泛型表是运行期堆分配, 没有计数全局, 只能这样探(与 7.0 的 probeTypeIndexSpace 同思路)。
// 探测一个 32B 记录堆表能放下多少条。
// ⚠️ 性能: memReadable 在真机是 VirtualQuery(约 1us/次)。**不能**每条都调 ——
//    上限 4M 就是 4 秒纯系统调用, 足以让"解算全部类型"卡住不动。
//    所以先用 RegionEnd 拿到整个分配区的边界, 只在跨页时才做 VirtualQuery。
static uint64_t ProbeRecCount(const uint8_t* base, uint32_t recSize, uint64_t cap) {
    if (!base) return 0;
    uint64_t limit = cap;
    uint64_t e = RegionEnd(base);                   // 一次性, 覆盖整个 region
    if (e > (uint64_t)base) {
        uint64_t byRegion = ((e - (uint64_t)base) / recSize) + 1;
        if (byRegion < limit) limit = byRegion;
    }
    // 跨 region 连续分配时最多再探 64 个 region 边界就收手
    uint64_t n = 0, regions = 0;
    uint64_t page = 0x1000;
    while (n < limit) {
        // 同一 region 内直接推算, 不进 VirtualQuery
        if (e && (uint64_t)base + (n + 1) * recSize <= e) { ++n; continue; }
        if ((n * recSize) / page != ((n + 1) * recSize) / page) {   // 跨页了才复查
            if (!memReadable(base + (n + 1) * (uint64_t)recSize, recSize)) break;
            if (++regions > 64) break;
        }
        uint64_t ne = RegionEnd(base + n * (uint64_t)recSize);
        if (ne > e) e = ne;
        if (e && ne == 0) break;
        ++n;
    }
    return n;
}

// ---- 88B 程序集表 (g_52F8, stride 0x58) ----
// 2026-09-26 IDA sub_1404C43D0 / sub_14050CD10 + heap dump 双重验证:
//   +0x24 u32 ^ 0x6A3E22EA         = typeCount
//   +0x38 u32 ^ 0x4B1CB1C1         = typeStart
//   +0x28 u64 - 0x2432F7B06693D92B = dllName ("mscorlib.dll")
//   +0x30 u64 ^ 0x5AEB1E2239920311 = &img88[imageIndex]
static bool DecodeAsm88(GameCtx& ctx) {
    const uint8_t* tab = ctx.asm88Tab;
    if (!tab || !memReadable(tab, (uint64_t)kAsmImgStride * kAsmImgCount)) return false;
    uint64_t prevEnd = 0;
    bool first = true;
    for (uint32_t i = 0; i < kAsmImgCount; ++i) {
        const uint8_t* e = tab + (uint64_t)kAsmImgStride * i;
        if (!memReadable(e, kAsmImgStride)) break;
        AsmRec a;
        a.index      = i;
        a.typeCount  = rd32(e + kAsmTypeCountOff) ^ kAsmTypeCountK;
        a.typeStart  = rd32(e + kAsmTypeStartOff) ^ kAsmTypeStartK;
        uint64_t np  = rd64(e + kAsmDllNameOff) - kAsmDllNameK;
        // 自检: 区间必须首尾相接且不越界, 否则整张表不可信
        if (a.typeStart > 0x1000000u || a.typeCount > 0x1000000u) return false;
        if (!first && a.typeStart != prevEnd) return false;
        if (a.typeCount && (uint64_t)a.typeStart + a.typeCount > 0x1000000ull) return false;
        // ⚠️ 必须要求每条 typeCount > 0。
        // 之前只查"首尾相接", 于是一张**全 0 的退化表**(游戏刚把 count 写成 75、
        // 还没填表内容时)能整条通过: tc 全 0 时链条检查退化成"所有 ts 相等",
        // 恒真。真机上就是这样产出了 typeCount=0 的空 dump(21 项 FAIL)。
        if (a.typeCount == 0) return false;
        prevEnd = a.typeStart + a.typeCount;
        first = false;
        if (np && memReadable((const void*)np, 1)) {
            const char* s = (const char*)np;
            size_t n = 0; while (n < 128 && s[n]) ++n;   // 手工取长度, 不碰 CRT
            a.dllName.assign(s, n);
        }
        // imageIndex 直接从指针反推(该字段在实测里恒等于 i, 但不假设)
        uint64_t ip = rd64(e + kAsmImgPtrOff) ^ kAsmImgPtrK;
        if (ctx.img88Tab && ip >= (uint64_t)ctx.img88Tab) {
            uint64_t d = ip - (uint64_t)ctx.img88Tab;
            if (d % kAsmImgStride == 0) a.imageIndex = (uint32_t)(d / kAsmImgStride);
        }
        ctx.asms.push_back(a);
    }
    return ctx.asms.size() == kAsmImgCount;
}

// ---- 88B 镜像表 (g_5308, stride 0x58) ----
//   +0x40 u64 - 0x783FCBBE2E713C7F = simpleName ("mscorlib")
//   +0x48 u64 - 0x3351BD851F7B567F = culture ("")
static bool DecodeImg88(GameCtx& ctx) {
    const uint8_t* tab = ctx.img88Tab;
    if (!tab || !memReadable(tab, (uint64_t)kAsmImgStride * kAsmImgCount)) return false;
    for (uint32_t i = 0; i < kAsmImgCount; ++i) {
        const uint8_t* e = tab + (uint64_t)kAsmImgStride * i;
        if (!memReadable(e, kAsmImgStride)) break;
        ImgRec im;
        im.index = i;
        auto grab = [&](uint32_t off, uint64_t key) -> std::string {
            uint64_t p = rd64(e + off) - key;
            if (!p || !memReadable((const void*)p, 1)) return std::string();
            const char* s = (const char*)p;
            size_t n = 0; while (n < 256 && s[n]) ++n;
            return std::string(s, n);
        };
        im.name    = grab(kImgNameOff, kImgNameK);
        im.culture = grab(kImgCultureOff, kImgCultureK);
        ctx.imgs.push_back(im);
    }
    return ctx.imgs.size() == kAsmImgCount;
}

// 纯内存初始化。**不读任何磁盘文件。**
// g_overrideBase 非空时用它当模块基址(native 回归测试注入 module.bin 用);
// 否则 GetModuleHandleW。两条路径走的是**同一段解码代码**。
uint8_t* g_overrideBase = nullptr;
void SetBaseOverride(uint8_t* p) { g_overrideBase = p; }

bool InitCtxMemory(GameCtx& ctx) {
    ctx.diag.clear(); ctx.err.clear(); ctx.valid = false;
    ctx.asms.clear(); ctx.imgs.clear();

    uint8_t* base = g_overrideBase;
#ifdef _WIN32
    if (!base) {
        base = (uint8_t*)GetModuleHandleW(L"GenshinImpact.exe");
        if (!base) base = (uint8_t*)GetModuleHandleW(NULL);
    }
#endif
    if (!base) { ctx.err = "cannot resolve module base"; return false; }
    ctx.base    = base;
    ctx.exeLo   = base;
    ctx.imageLo = base;
    ctx.exeMapped = true;          // 运行期映像: RVA 即偏移, 不需要 section 表
    ctx.vaBias  = (uint64_t)base;   // data 字段已被 PE 重定位到 base+rva
    AppendDiag(ctx, "moduleBase=" + hex64((uint64_t)base) + "\n");

    // SizeOfImage(in-image guard 用)
    {
        uint64_t peOff = rd32(base + 0x3C);
        if (memReadable(base + peOff, 0x100))
            ctx.imageSize = rd32(base + peOff + 0x50);
    }
    if (ctx.imageSize <= 0x1000 || ctx.imageSize > 0x80000000ull) {
        ctx.err = "implausible SizeOfImage " + hex64(ctx.imageSize);
        return false;
    }
    AppendDiag(ctx, "sizeOfImage=" + hex64(ctx.imageSize) + "\n");

    // ---- 三个核心全局 ----
    uint64_t hdrRaw  = rd64(base + kRvaHeaderPtr);
    uint64_t blobRaw = rd64(base + kRvaMappedMeta);
    AppendDiag(ctx, "hdr=" + hex64(hdrRaw) + " blobPtr=" + hex64(blobRaw) + "\n");
    if (!hdrRaw || !blobRaw || hdrRaw < 0x10000 || blobRaw < 0x10000) {
        ctx.err = "metadata globals not initialized (g_52B8/g_52C0) - "
                  "inject earlier or metadata init not finished";
        return false;
    }
    ctx.hdr  = (uint8_t*)hdrRaw;
    // ⚠️ g_52C0 指向 header **之后**, 内容起点要减 528
    ctx.blob = (uint8_t*)(blobRaw - kHeaderBytes);
    ctx.blobSize = 0x4EE4538ull;   // 7.1 实测常量: 0x4AD60090..0x4FC445C8
    if (rd32(ctx.hdr) != kHeaderMagic) {
        ctx.err = "header magic mismatch: " + hex64(rd32(ctx.hdr)) +
                  " want " + hex64(kHeaderMagic);
        return false;
    }
    AppendDiag(ctx, "header magic OK, blob=" + hex64((uint64_t)ctx.blob) +
                    " size=" + dec(ctx.blobSize) + "\n");
    ctx.ownsBlob = false;          // 借用游戏映射, FreeCtx 不得 free

    // 字符串表必须**先于**镜像表解码: image 名字是 88B 表里的**裸字符串指针**,
    // 不走 DecodeString, 但 strBlobEnd 是后面所有边界检查的基础。
    ctx.strBlob     = ResolveTable(ctx, kT_strblob);
    ctx.strBlobEnd  = (uint64_t)ctx.blob + ctx.blobSize;

    // ---- 16B Il2CppType 记录数组(在 exe 映像里) ----
    {
        const uint8_t* q = base + kRvaTypeStruct + kTypeArrayOff;
        if (!memReadable(q, 8)) { ctx.err = "type struct unreadable"; return false; }
        uint64_t va = rd64(q);
        if (va < (uint64_t)base || va > (uint64_t)base + ctx.imageSize) {
            ctx.err = "type array VA out of image: " + hex64(va);
            return false;
        }
        ctx.typeRecTab = (uint8_t*)va;
        ctx.typeRecRva = va - (uint64_t)base;
        if (!memReadable(ctx.typeRecTab, 16)) { ctx.err = "type record array unreadable"; return false; }
        // 探测 16B 数组能放下多少条 —— TypeRecord() 的快路径要用, 避免热路径上
        // 每次都进 VirtualQuery(真机 ~1us x 千万次 = 几分钟)。
        // ⚠️ 必须夹紧: RegionEnd 给的是**整个 region** 的末端, 可能比真实数组大得多
        // (7.1 的 .rdata 是一个大 region)。不夹紧就会把越界的索引也判成"可读",
        // 于是读到垃圾类型记录 -> 各种离谱的 kind/计数 -> 卡死或崩。
        uint64_t imgEnd = (uint64_t)base + ctx.imageSize;
        uint64_t te = RegionEnd(ctx.typeRecTab);
        if (!te || te > imgEnd) te = imgEnd;            // 不得超过映像
        if (te < (uint64_t)ctx.typeRecTab + 16) te = (uint64_t)ctx.typeRecTab + 16;
        ctx.typeRecEnd = te;
        // 上限与 TypeRecord() 里的 index>0x1FFFFF 保持一致
        ctx.typeRecCount = (ctx.typeRecEnd - (uint64_t)ctx.typeRecTab) / 16;
        if (ctx.typeRecCount > 0x200000ull) ctx.typeRecCount = 0x200000ull;
        AppendDiag(ctx, "typeRecTab=" + hex64(va) + " (RVA " + hex64(ctx.typeRecRva) +
                        ") count=" + dec(ctx.typeRecCount) + "\n");
    }

    // ---- 运行期堆上的 88B 程序集/镜像表 ----
    ctx.asm88Count = rd32(base + kRvaAsmCount);
    ctx.img88Count = rd32(base + kRvaImgCount);
    ctx.asm88Tab = (uint8_t*)rd64(base + kRvaAsmTable);
    ctx.img88Tab = (uint8_t*)rd64(base + kRvaImgTable);
    AppendDiag(ctx, "asm88=" + hex64((uint64_t)ctx.asm88Tab) + " x" + dec(ctx.asm88Count) +
                    "  img88=" + hex64((uint64_t)ctx.img88Tab) + " x" + dec(ctx.img88Count) + "\n");
    if (ctx.asm88Count != kAsmImgCount || ctx.img88Count != kAsmImgCount) {
        ctx.err = "asm/img count mismatch: " + dec(ctx.asm88Count) + "/" + dec(ctx.img88Count) +
                  " want " + dec(kAsmImgCount);
        return false;
    }
    if (!DecodeImg88(ctx) || !DecodeAsm88(ctx)) {
        // 把表指针带进错误信息: 等待循环每次轮询都会打印 last=<err>。
        // 指针在变 => 只是表还没填完(H1, 继续等即可);
        // 指针一直不动且恒为 75 条 => 多半是全局 RVA 指错了(H2, 得回 IDA 重新定位)。
        ctx.err = "88B asm/img table not filled yet (tab=" + hex64((uint64_t)ctx.asm88Tab) +
                  " img=" + hex64((uint64_t)ctx.img88Tab) +
                  " decoded=" + dec((uint64_t)ctx.asms.size()) + "/" + dec(kAsmImgCount) + ")";
        return false;
    }
    for (const AsmRec& a : ctx.asms) ctx.typeCount += a.typeCount;
    AppendDiag(ctx, "asms=" + dec(ctx.asms.size()) + " imgs=" + dec(ctx.imgs.size()) +
                    " typeCount=" + dec(ctx.typeCount) + "\n");
    // 兜底: 88B 表存在但没解出任何类型 => 一定没填完, 当成"未就绪"继续等,
    // 绝不能拿它去生成空 dump。
    if (ctx.typeCount == 0) {
        ctx.err = "88B asm table present (tab=" + hex64((uint64_t)ctx.asm88Tab) +
                  ") but 0 types decoded - not filled yet";
        return false;
    }
    // program 集名: 88B 表给的是 dllName("mscorlib.dll"), 沿用 image 的 simpleName
    for (size_t i = 0; i < ctx.asms.size() && i < ctx.imgs.size(); ++i)
        if (ctx.asms[i].dllName.empty()) ctx.asms[i].dllName = ctx.imgs[i].name;

    Progress("[init] 88B decode done, memReadable=%llu", (unsigned long long)g_memReadableCalls);
    // ---- GENERICINST 堆表 ----
    //
    // ⚠️ **默认关闭, 且不要试图靠自检打开它。**
    // 实参下标的换算 `idx = (args[i] - typeArray) / 16` 依赖 typeArray,
    // 而 typeArray 的来源(sub_1404E3CC0 @0x1404E3E7B 那段)我读错了:
    // 那段是 `sub rax,rcx ; shr rax,1 ; imul ecx,eax,8AF8AF8B` —— 指针差做下标变换,
    // 不是取 16B 数组基址。按字面算出的地址在 blob 末端之外 ~4GB, 但真机上它
    // 恰好落在可读堆页上, memReadable 会**误判通过**, 于是特性被错误开启,
    // 产出垃圾下标 -> 递归失控 -> "解算全部类型" 卡死(2026-09-26 真机复现)。
    //
    // 这里仍然把 desc/table 读出来打进 diag(便于继续逆向), 但特性保持关闭,
    // 输出退回 genericinst@N 占位 —— 少一条信息远好过卡死或输出假类型名。
    {
        uint64_t desc = rd64(base + kRvaGenericDesc);
        ctx.genDesc  = (uint8_t*)desc;
        if (desc && memReadable((const void*)desc, 48)) {
            uint64_t tab = rd64((const uint8_t*)desc + 8);
            if (tab && memReadable((const void*)tab, kGenRecSize)) {
                ctx.genTable = (uint8_t*)tab;
                ctx.genTableCount = ProbeRecCount(ctx.genTable, kGenRecSize, 1u << 22);
            }
        }
        AppendDiag(ctx, "genericDesc=" + hex64(desc) + " genericTable=" +
                        hex64((uint64_t)ctx.genTable) + " entries=" +
                        dec(ctx.genTableCount) +
                        "  -> typeArray 换算未验证, FEAT_GENERIC_INST 强制关闭\n");
    }

    Progress("[init] globals+88B ok, memReadable=%llu", (unsigned long long)g_memReadableCalls);
    // ---- 给 IDA 的运行期地址表(exe 内静态数组) ----
    // 真方法指针表 = 0x2870B90 (见 dumper.h 的判据); 另一张是泛型桩表
    ctx.methodCodeTab = (uint8_t*)(base + kRvaMethodCodePtrs);
    if (!memReadable(ctx.methodCodeTab, 16)) {
        ctx.err = "method address tables unreadable";
        return false;
    }
    AppendDiag(ctx, "methodCodeTab(真 MPT)=" + hex64((uint64_t)ctx.methodCodeTab) +
                    "  [勿用] 泛型桩表@" + hex64(kRvaMethodThunkPtrs) + "\n");

    // ---- 12 张已验证表 ----
    ctx.typedefTab    = ResolveTable(ctx, kT_typedef);
    ctx.methodTab     = ResolveTable(ctx, kT_method);
    ctx.mptrTab       = ResolveTable(ctx, kT_mptr);
    ctx.fieldTab      = ResolveTable(ctx, kT_field);
    ctx.propTab       = ResolveTable(ctx, kT_prop);
    ctx.eventTab      = ResolveTable(ctx, kT_event);
    ctx.paramTab      = ResolveTable(ctx, kT_param);
    ctx.ifaceTab      = ResolveTable(ctx, kT_iface);
    ctx.fdesc12Tab    = ResolveTable(ctx, kT_fdesc12);
    ctx.fhidx4Tab     = ResolveTable(ctx, kT_fhidx4);
    ctx.fieldOffTable = ResolveTable(ctx, kT_fieldoff);
    ctx.tokentypeTab  = ResolveTable(ctx, kT_tokentype);
    ctx.enumValTab    = ResolveTable(ctx, kT_enumval);
    ctx.enumValBlob   = ResolveTable(ctx, kT_enumvalblob);
    ctx.enumValCount  = (H32(ctx, kEnumValCountField) ^ kEnumValCountK) / 12u;

    // blobEnd: 走可读页到分配末尾, 后面所有边界检查用它
    ctx.blobEnd = RegionEnd(ctx.blob);
    if (!ctx.blobEnd || ctx.blobEnd < (uint64_t)ctx.blob + ctx.blobSize)
        ctx.blobEnd = (uint64_t)ctx.blob + ctx.blobSize;   // 探测失败就用已知长度
    AppendDiag(ctx, "blobEnd=" + hex64(ctx.blobEnd) + "\n");

    Progress("[init] tables resolved, memReadable=%llu", (unsigned long long)g_memReadableCalls);
    // 表必须落在 blob 内
    struct Chk { const char* n; const uint8_t* p; uint64_t need; };
    const Chk chks[] = {
        { "typedef",  ctx.typedefTab,  70ull * ctx.typeCount },
        { "strBlob",  ctx.strBlob,      64 },
        { "enumVal",  ctx.enumValTab,   12ull * ctx.enumValCount },
    };
    for (const Chk& c : chks) {
        if (!c.p || (uint64_t)c.p + c.need > ctx.blobEnd) {
            ctx.err = std::string("table out of blob: ") + c.n;
            return false;
        }
    }

    Progress("[init] chks ok, memReadable=%llu", (unsigned long long)g_memReadableCalls);
    // ---- 特性登记 ----
    for (int i = 0; i < FEAT__COUNT; ++i) ctx.features[i] = false;
    if (ctx.fieldOffTable && ctx.fdesc12Tab && ctx.fhidx4Tab) {
        struct Anchor { const char* name; uint32_t td; int j0; int expect[8]; };
        const Anchor anch[] = {
            { "System.Reflection.Assembly", 532,  0, { 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48 } },
            { "UnityEngine.Vector3",        2332, 11, { 0x10, 0x14, 0x18 } },
            { "UnityEngine.Vector2",        2536, 9,  { 0x10, 0x14 } },
        };
        bool ok = true; int checked = 0;
        for (const Anchor& a : anch) {
            if (a.td >= ctx.typeCount) continue;
            int32_t ab = FieldAttrBase(ctx, a.td);
            if (ab < 0) { ok = false; break; }
            for (int k = 0; k < 8 && a.expect[k]; ++k) {
                const uint8_t* p = ctx.fieldOffTable + 4ull * ((uint64_t)ab + a.j0 + (uint32_t)k);
                if ((uint64_t)p + 4 > ctx.blobEnd) { ok = false; break; }
                if ((int32_t)(rd32(p) & 0xFFFFFF) != a.expect[k]) { ok = false; break; }
                ++checked;
            }
            if (!ok) break;
        }
        ctx.features[FEAT_FIELD_OFFSET] = (ok && checked >= 12);
        AppendDiag(ctx, ctx.features[FEAT_FIELD_OFFSET]
            ? "FEAT_FIELD_OFFSET 开启: 锚点全部命中\n"
            : "fieldOff 锚点未命中 -> 保持关闭\n");
    }
    if (ctx.enumValTab && ctx.enumValBlob && ctx.enumValCount) {
        bool asc = true; uint32_t prev = 0;
        for (uint32_t i = 0; i < ctx.enumValCount; ++i) {
            uint32_t k = rd32(ctx.enumValTab + 12ull * i);
            if (i && k <= prev) { asc = false; break; }
            prev = k;
        }
        int32_t s0 = asc ? (int32_t)rd32(ctx.enumValTab + 4) : -1;
        bool inRange = (s0 >= 0) && ((uint64_t)ctx.enumValBlob + s0 + 8 <= ctx.blobEnd);
        ctx.features[FEAT_ENUM_MEMBERS] = ctx.features[FEAT_ENUM_VALUES] = (asc && inRange);
        AppendDiag(ctx, std::string("枚举特性 ") + (asc && inRange ? "开启" : "关闭") +
                        ": 常量表 " + dec(ctx.enumValCount) + " 条\n");
    }
    // 泛型实例: 实参下标换算(typeArray)尚未验证, 强制关闭。
    // 保留赋值意图但明确关掉, 免得以后有人以为它可用。
    ctx.features[FEAT_GENERIC_INST] = false;

    ctx.methodCountTotal = 0; ctx.fieldCountTotal = 0;
    for (uint32_t i = 0; i < ctx.typeCount; ++i) {
        const uint8_t* r = ctx.typedefTab + 70ull * i;
        if ((uint64_t)(r + 70) > ctx.blobEnd) break;
        ctx.methodCountTotal += (uint16_t)(rd16(r + 48) + 4806u);
        ctx.fieldCountTotal  += (uint16_t)(rd16(r + 56) ^ 0x51A8u);
    }

    // ---- 方法地址表健康检查 ----
    // 真 MPT 的每个方法都应有自己唯一的代码体。若出现大量重复, 说明又拿错了表
    // (历史上就曾把泛型桩表 0x27D4DE0 当成 MPT, 导致 99.9% 方法地址错误,
    //  普通属性 getter 指向 `*a5 = a1()` 那种"从参数取方法指针"的派发桩)。
    {
        uint64_t inImg = 0, zero = 0, oob = 0;
        for (uint32_t k = 0; k < ctx.methodCountTotal; ++k) {
            uint64_t a = rd64(ctx.methodCodeTab + 8ull * k);
            if (!a) ++zero;
            else if (a >= ctx.vaBias && a - ctx.vaBias < ctx.imageSize) ++inImg;
            else ++oob;
        }
        std::vector<uint32_t> rv;
        rv.reserve(ctx.methodCountTotal);
        for (uint32_t k = 0; k < ctx.methodCountTotal; ++k) {
            uint64_t a = rd64(ctx.methodCodeTab + 8ull * k);
            if (a >= ctx.vaBias && a - ctx.vaBias < ctx.imageSize) rv.push_back((uint32_t)(a - ctx.vaBias));
        }
        std::sort(rv.begin(), rv.end());
        uint32_t dupAddr = 0, maxDup = 0;
        for (size_t i = 0; i < rv.size(); ) {
            size_t j = i; while (j < rv.size() && rv[j] == rv[i]) ++j;
            uint32_t n = (uint32_t)(j - i);
            if (n > 1) { ++dupAddr; if (n > maxDup) maxDup = n; }
            i = j;
        }
        ctx.mptInImage = inImg; ctx.mptDistinct = (uint32_t)rv.size();
        ctx.mptDupAddr = dupAddr; ctx.mptMaxDup  = maxDup;
        AppendDiag(ctx, "MPT@" + hex64(kRvaMethodCodePtrs) + ": 界内 " + dec(inImg) +
                        " / 不同 " + dec((uint64_t)rv.size()) + " / 零 " + dec(zero) +
                        " / 界外 " + dec(oob) +
                        " | 重复地址 " + dec(dupAddr) + "(最大重数 " + dec(maxDup) + ")\n");
    }

    ctx.valid = true;
    return true;
}

// ---------------------------------------------------------------------------
// 纯内存入口(照搬 7.0): 只读运行期全局, **不搜路径、不读任何磁盘文件**。
// 可反复调用做轮询等待; 每次失败只填 ctx.err。
bool InitCtx(GameCtx& ctx) {
    return InitCtxMemory(ctx);
}

void FreeCtx(GameCtx& ctx) {
    if (ctx.ownsBlob)    free(ctx.blob);
    if (ctx.ownsExe)     free(ctx.imageLo);
    ctx.blob = ctx.hdr = ctx.imageLo = ctx.exeLo = ctx.base = nullptr;
    ctx.ownsBlob = ctx.ownsExe = false;
    ctx.imageSize = ctx.vaBias = 0;
    ctx.valid = false;
}

} // namespace gs
