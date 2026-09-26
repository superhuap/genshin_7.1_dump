#pragma once

// ============================================================================
//  gsdump6 —— 7.0 dumper 代码为基线, 适配 7.1, **纯内存**
//
//  架构(照搬 7.0, 7.0 本来就是纯内存 dumper):
//    InitCtx 只做三件事:
//      base = GetModuleHandleW(L"GenshinImpact.exe")
//      hdr  = *(u64*)(base + kRvaHeaderPtr)
//      blob = *(u64*)(base + kRvaMappedMeta) - 528
//    所有表 = blob + 528 + (h32(field) OP CONST), 每表一次 XOR/减法, 只算一次。
//    **完全不读 global-metadata.dat / startup-metadata.dat 磁盘文件。**
//    blob 是游戏已经映射好的内存, 82MB 读盘成本为零 —— 这就是 7.0"瞬间完成"的原因。
//
//  7.1 与 7.0 的关键结构差异(全部已实测):
//    - 7.0 的 hdr/blob/pool 是三个独立全局; 7.1 合并成 g_52B8/g_52C0 一对,
//      且 blob 指针指向 **header 之后**(所以要 -528)。
//    - 7.1 把程序集/镜像表搬到了运行期堆, 88B/条(不是 7.0 的 40B/44B),
//      启动后依然存活 => 晚注入也能读, 不需要抢 startup 窗口。
//    - 7.1 的 16B Il2CppType 数组在 exe 映像里(RVA 0x2E1EA20), 不在堆上。
//
//  数值/公式全部换成 7.1(v3 实测 + v4 native 回归 + 本轮 IDA 定案),
//  formulaCheck 必须保持 47 PASS / 0 FAIL。
// ============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>

namespace gs {

// ---- 崩溃/停滞现场 ----
// 记录"当前正在干什么", 崩溃时一并写进 crash.txt。
// 2026-09-26 真机 AV 光有 exception_code + addr 定位不了: 有 ASLR,
// 必须知道故障地址相对**哪个模块**、偏移多少, 以及当时正在解算什么。
extern char     g_stage[128];
extern uint32_t g_stageIdx;
extern uint64_t g_stageVal;
void SetStage(const char* s, uint32_t idx = 0, uint64_t val = 0);


// 解码/写盘阶段会周期性回调它。真机跑一次要几十秒到几分钟, 没有进度点就无法
// 区分"慢"和"卡死" —— 2026-09-26 就因为缺这个, 只能靠猜。
// 约定: 只传 ASCII, 内部自己格式化(不要在这里用 %ls)。
using ProgressFn = void (*)(const char* line);
void SetProgress(ProgressFn fn);
void Progress(const char* fmt, ...);
uint64_t NowMs();      // 毫秒计时(可移植), 用于进度/停滞检测
extern uint64_t g_memReadableCalls;
extern uint64_t g_genCalls;   // 诊断: 统计 VirtualQuery 次数

// ---------------------------------------------------------------- exe 常量 --
static constexpr uint64_t kImageBase = 0x140000000ULL; // PE 首选基址, 仅诊断用
// "被 >= N 个方法共用"的代码地址才算共享桩。实测重数分布:
//   1->645861(唯一)  2->1682  3->588  4->285 ... >=20->396 个地址覆盖 53511 个方法
// 取 2 = 只要不是一对一就标出来, 让消费方自己决定要不要跳过。

// ---- 运行期全局(7.1)。全部来自 IDA 确认 + gi_dump 运行期值交叉验证 ----
// g_52B8/g_52C0 是一对: 528B header 指针 + blob 指针(指向 header 之后, 故 -528)。
static constexpr uint64_t kRvaHeaderPtr  = 0x5AD52B8ULL; // -> 528B 混淆 header
static constexpr uint64_t kRvaMappedMeta = 0x5AD52C0ULL; // -> blob 基址(已含 header 偏移)
static constexpr uint64_t kHeaderBytes   = 528;          // blob 指针比内容起点大 528
static constexpr uint32_t kHeaderMagic   = 0x0059484Du;  // "MHY\0" 小端
// 16B Il2CppType 记录数组: 静态结构 g_52A0 (RVA kRvaTypeStruct) 的第 72 字节存该数组 RVA。
static constexpr uint64_t kRvaTypeStruct = 0x2870A88ULL;
static constexpr uint32_t kTypeArrayOff  = 72;
// ---- 运行期堆上的 88B 表(2026-09-26 IDA + heap dump 双重验证) ----
// 关键: stride 是 **88 (0x58)**, 不是 7.0 的 40/44。表在 CRT 堆上, startup 释放后仍存活。
static constexpr uint64_t kRvaAsmCount = 0x5AD52F0ULL; // dword = 75
static constexpr uint64_t kRvaAsmTable = 0x5AD52F8ULL; // 75 x 88B 程序集表
static constexpr uint64_t kRvaImgCount = 0x5AD5300ULL; // dword = 75
static constexpr uint64_t kRvaImgTable = 0x5AD5308ULL; // 75 x 88B 镜像表
static constexpr uint32_t kAsmImgStride = 88;
static constexpr uint32_t kAsmImgCount  = 75;
// asm88 字段(相对表项起点)
static constexpr uint32_t kAsmTypeCountOff = 0x24; static constexpr uint32_t kAsmTypeCountK = 0x6A3E22EAu;
static constexpr uint32_t kAsmDllNameOff   = 0x28; static constexpr uint64_t kAsmDllNameK   = 0x2432F7B06693D92Bull;
static constexpr uint32_t kAsmImgPtrOff    = 0x30; static constexpr uint64_t kAsmImgPtrK    = 0x5AEB1E2239920311ull;
static constexpr uint32_t kAsmTypeStartOff = 0x38; static constexpr uint32_t kAsmTypeStartK = 0x4B1CB1C1u;
// img88 字段(相对表项起点)
static constexpr uint32_t kImgNameOff   = 0x40; static constexpr uint64_t kImgNameK   = 0x783FCBBE2E713C7Full;
static constexpr uint32_t kImgCultureOff= 0x48; static constexpr uint64_t kImgCultureK= 0x3351BD851F7B567Full;
// ---- GENERICINST 堆表 (sub_1404E3CC0 case 21, 指令级定案) ----
//   typeArray = blob + (i32)(h32(0xB4) + 0xEC48AB9F)      // 16B Il2CppType 数组
//   desc      = *(u64*)(base + kRvaGenericDesc)
//   table     = *(u64*)(desc + 8)
//   rec       = table + (int32)data * 32                  // movsxd = 有符号
//   argc      = *(u32*)(rec + 8)      args = *(u64*)(rec + 0x10)
//   args[i]   = Il2CppType*  ->  下标 = (args[i] - typeArray) / 16
static constexpr uint64_t kRvaGenericDesc = 0x5AD4E98ULL;
static constexpr uint32_t kGenRecSize  = 32;
static constexpr uint32_t kGenMaxArgs  = 64;    // argc 上限(防御坏数据)
// 字符串 SSE 常量(运行期从映像里读, 磁盘模式读不到时用兜底常数)
static constexpr uint64_t kRvaSse = 0x39085D0ULL;
// ---- 给 IDA 恢复符号用的运行期地址表(exe 里的静态数组, 7.1 的 MPT) ----
// ⚠️⚠️ 这两张表**曾经搞反过**, 代价是 99.9% 的方法指向错误代码(2026-09-26 修正)。
//
// 真方法指针表(MPT) = 0x2870B90: 8B/条, 下标 = 全局成员号。
//   判据 1(统计): 711,021 条界内地址**两两不同**(零重复), 100% 16B 对齐,
//                 散布全图 0x6C04000..0x19DA4520。
//   判据 2(语义): mi=3042 = System.String::get_Length -> 字节 `8b 41 10 c3`
//                 = `mov eax,[rcx+0x10]; ret`, 正好读 m_stringLength(偏移 0x10)。
//                 mi=2917 = get_Chars(int) -> `cmp [rcx+0x10],edx` 边界检查 +
//                 `movzx eax,word [rcx+rcx*2+0x14]` 读 m_firstChar。
//   覆盖率 711,021/733,442 = 96.9%。
static constexpr uint64_t kRvaMethodCodePtrs = 0x2870B90ULL;

// 另一张表 = 0x27D4DE0: 同样 8B/条, 但只有 649,615 个不同值, 3,754 个地址被
// 最多 2,141 个方法共用, 且 7.5% 挤在 0x43xxxx..0x47xxxx 一条窄带里 —— 这是
// **泛型/共享派发桩表**。用它当方法地址, 普通属性 getter 会指向
// `*a5 = a1()` 这种"从参数取真实方法指针再调"的桩。
// 保留它仅供诊断/交叉验证, 不再作为方法代码地址。
static constexpr uint64_t kRvaMethodThunkPtrs = 0x27D4DE0ULL;
// 16B Il2CppType 指针表: *(u64*)(base + 0x2870AD0) 与 typeRecTab 同址(见 locate.cpp)
// 兼容旧名(公式推导文档用)
// 528B header 在映像里的位置。dumper 本身不直接用(它走 g_52B8 全局),
// 但 tools/nativetest.cpp 离线复现时要用它把 header 填进全局。
static constexpr uint64_t kRvaHeader = 0x27D4BD0ULL;

// ---------------------------------------------------------------- 基础读 ---
inline uint8_t  rd8 (const void* p) { return *(const uint8_t*)p;  }
inline uint16_t rd16(const void* p) { return *(const uint16_t*)p; }
inline uint32_t rd32(const void* p) { return *(const uint32_t*)p; }
inline uint64_t rd64(const void* p) { return *(const uint64_t*)p; }

// ------------------------------------------------------ 7.1 混淆原语 -------
// ⚠️ field_key 里的 34782*i 必须保持 64 位: 34782*123483 ≈ 2^32,
//    截断后索引 >= 123483 的 316,689 个字段全部解错。
inline uint32_t field_key(uint32_t i) {
    uint64_t v = ((uint64_t)34782 * (uint64_t)i) ^ 0x59B1DB19ULL;
    return (uint32_t)((((uint64_t)1824013172 * v) >> 16) + 1410079245u);
}
inline uint32_t method_key(uint32_t i) {
    return (uint32_t)(((uint32_t)((uint64_t)860405619 * i) ^ 0x73758947u) + 1547935323u);
}
inline uint32_t method_key16(uint32_t i) {
    return ((((uint32_t)((0u - 16525u) * i) ^ 0x8947u) - 24997u) & 0xFFFFu);
}
inline uint32_t prop_key(uint32_t i) {
    uint64_t v = ((0x17A5419F8A28ULL * (uint64_t)i) >> 9);
    return (uint32_t)((((uint64_t)976451930 * v) >> 12) & 0xFFFFFFFFu) ^ 0x70BE4B04u;
}
inline uint32_t event_key(uint32_t i) {
    return (uint32_t)(((uint32_t)(0u - 1599256506u) * i + 1725894951u) ^ 0x1B23E40Fu);
}
uint32_t param_key_of(uint32_t idx); // 定义在 meta.cpp

// ---------------------------------------------------------------- 表基址 ---
// 统一形态: table = blob + 528 + (h32(field) OP CONST)
// h32 读的是 exe 里那个 528B header 的第 field 字节。
// startup-metadata.dat 里的表(无 +528)。
struct TableSpec { int field; char op; uint32_t konst; };

static constexpr TableSpec kT_typedef  = { 180, '-', 330781793u  }; // 70B/条
static constexpr TableSpec kT_method   = { 364, '-', 483030612u  }; // 26B/条
static constexpr TableSpec kT_mptr     = { 148, '^', 0x4A4C0A71u }; // 4B/条 方法->代码槽位
static constexpr TableSpec kT_field    = { 396, '-', 336578260u  }; // 8B/条
static constexpr TableSpec kT_prop     = { 336, '-', 473781129u  }; // 10B/条
static constexpr TableSpec kT_event    = { 488, '^', 0x100547B1u }; // 14B/条
static constexpr TableSpec kT_param    = { 276, '^', 0x3E5D33E6u }; // 8B/条 {typeIdx,nameIdx}
static constexpr TableSpec kT_iface    = { 516, '-', 450622139u  }; // 4B/条
static constexpr TableSpec kT_fieldoff = { 296, '^', 0x0F92DC85u  };// 4B/条 **真实字段偏移** + 标志位
// --- 真实字段偏移链 (sub_140512870 SetupFields, 2026-09-26 IDA 确认 + 全量实测) ---
//   attrBase(ti) = i32( desc12[ i32(hidx4[ti]) ] + 8 )
//   e(ti,j)      = fattr4[ attrBase(ti) + j ]
//   实例字段 ⟺ 0 < e < 0x1000000, 此时 e 就是真实实例偏移
//   e == 0 或 e>>24 != 0 ⟹ static/const(不占实例空间); 高字节是 FieldAttributes 位,
//                          其中 0x01 = 0x1000000 另有"有常量"含义(仅 74 个字段)
// 注意 hidx4 的索引变换是**恒等**: (35*ti) * 0x8AF8AF8B, 而 35 * 0x8AF8AF8B ≡ 1 (mod 2^32),
// 0x8AF8AF8B 就是 35 的模逆元 —— 一段伪装成哈希的恒等变换。
// 实测(判据全部来自数据内在性质, 见 FORMULAS §12.5):
//   327,555 实例字段 / 112,617 static-const, 合计 440,172
//   实例偏移按字段序严格升序无重复 : 47,789 / 47,828 = 99.92%
//   含 static 的类型里 static 全在前 : 14,747 / 14,747 = 100.00%
//   引用类型最小实例偏移 >= 0x10     : 56,341 / 56,341 = 100.00%
//   值类型最小实例偏移 == 0x10       : 12,433 / 12,434 = 99.99%
// ⚠️ 偏移域含 16 字节 Il2CppObject 头: 引用类型和值类型一律 0x10 起(见 FORMULAS §12.4)。
static constexpr TableSpec kT_fdesc12  = { 144, '+', 0x0B7255040u };// 12B/条 每类型字段描述符
static constexpr TableSpec kT_fhidx4   = { 376, '+', 0x0ADEC9E28u };// 4B/条  typeIndex -> 描述符下标
// --- 枚举 / 常量值链 (sub_14051A510, 2026-09-26 IDA 确认) ---
//   enumTab[i] = { u32 全局字段号(fieldStart+j), i32 值字节偏移, i32 未知(≈70) }
//   key 严格升序(75,548 条) -> 可直接二分;  值字节在 valBlob + slot, 按底层类型宽度读
//   slot 步长 = 值宽度(4 字节枚举步长 4, 8 字节枚举步长 8) -> 槽位互不重叠
static constexpr TableSpec kT_enumval    = { 316, '^', 0x593DE464u };// 12B/条 常量索引表
static constexpr TableSpec kT_enumvalblob= { 160, '^', 0x3F525210u };// 值字节区
static constexpr int kEnumValCountField = 84;                        // 条数 = (h32(84) ^ 0x23E67A90)/12
static constexpr uint32_t kEnumValCountK = 0x23E67A90u;
static constexpr TableSpec kT_tokentype= { 412, '^', 0x30F4D28Eu };// 8B/条 token->类型(bsearch)
static constexpr TableSpec kT_strblob  = { 388, '+', 0xBF9D4735u  };// 字符串 blob 源(加法)

// 7.1 的程序集/镜像表在**运行期堆**上, 88B/条(见 kRvaAsmTable/kRvaImgTable),
// 不再需要 startup 里的 40B/44B 静态表。
static constexpr uint32_t kAsmCount = 75, kImageCount = 75;

// ---------------------------------------------------------------- 类型枚举 --
enum TypeEnum : uint8_t {
    TE_END = 0x00, TE_VOID = 0x01, TE_BOOLEAN = 0x02, TE_CHAR = 0x03,
    TE_I1 = 0x04, TE_U1 = 0x05, TE_I2 = 0x06, TE_U2 = 0x07,
    TE_I4 = 0x08, TE_U4 = 0x09, TE_I8 = 0x0A, TE_U8 = 0x0B,
    TE_R4 = 0x0C, TE_R8 = 0x0D, TE_STRING = 0x0E, TE_PTR = 0x0F, TE_BYREF = 0x10,
    TE_VALUETYPE = 0x11, TE_CLASS = 0x12, TE_VAR = 0x13, TE_ARRAY = 0x14,
    TE_GENERICINST = 0x15, TE_TYPEDBYREF = 0x16, TE_I = 0x18, TE_U = 0x19,
    TE_OBJECT = 0x1C, TE_SZARRAY = 0x1D, TE_MVAR = 0x1E,
    TE_ENUM = 0x55,
};
const char* TypeKindName(uint8_t k);

// ---------------------------------------------------------------- 特性开关 --
// 7.0 dumper 有 7.0 专属的"进阶特性表", 它们的 hdr 偏移/常数在 7.1 全部要重推。
// 这里显式登记, 让 formulaCheck / report 如实报"未移植", 而不是拿猜的常数
// 悄悄输出一堆垃圾值 —— 这类 bug 最难查, 宁可缺着。
enum Feature {
    FEAT_FIELD_OFFSET  = 0, // 真实字段偏移     7.0: hdr+316 (4B)
    FEAT_FIELD_DEF     = 1, // 字段定义 12B     7.0: hdr+332
    FEAT_ENUM_MEMBERS  = 2, // 枚举成员 8B       7.0: hdr+464
    FEAT_FIELD_DEFVAL  = 3, // 字段默认值        7.0: hdr+480/32/384/180
    FEAT_ENUM_VALUES   = 4, // 枚举字面值        7.0: hdr+12/432
    FEAT_GENERIC_INST  = 5, // 泛型实例展开 16B  7.0: hdr+280
    FEAT_IFACE_SLOT    = 6, // 接口方法 slot 6B  7.0: hdr+504
    FEAT_ELEM_14       = 7, // 数组/泛型元素 14B 7.0: hdr+72
    FEAT__COUNT        = 8,
};
struct FeatureInfo { const char* name; const char* v70; bool ported; const char* note; };
const FeatureInfo& FeatureById(int id);

// ---------------------------------------------------------------- 上下文 -----
struct AsmRec { uint32_t index = 0, typeStart = 0, typeCount = 0, imageIndex = 0;
               std::string dllName; };
struct ImgRec { uint32_t index = 0; std::string name, culture; };

struct GameCtx {
    // ---- 输入缓冲 ----
    uint8_t* base      = nullptr;  // 模块基址(运行期)
    uint8_t* exeLo     = nullptr;  // exe 起点(运行期=模块 base; 磁盘=文件缓冲首字节)
    bool     exeMapped = false;    // true=运行期映像(RVA 即偏移); false=磁盘文件(要过 section 表)
    uint8_t* hdr       = nullptr;  // AtRva(kRvaHeader) -> 528B
    uint8_t* imageLo   = nullptr;  // 同 exeLo, 保留旧名
    uint64_t imageSize = 0;       // SizeOfImage
    uint64_t vaBias    = 0;       // 16B 记录里 data 字段的基准:
                                   //   磁盘模式 = kImageBase (文件 VA)
                                   //   运行期   = 模块 base   (已被 PE 重定位)
    // 磁盘模式的 section 表(RVA -> 文件偏移)
    struct Section { uint32_t va, vsize, raw, rawSize; };
    Section sections[32];
    int sectionCount = 0;
    uint8_t* blob      = nullptr;  // global-metadata.dat 内容(运行期=借用游戏映射)
    uint64_t blobSize  = 0;
    uint64_t blobEnd   = 0;         // blob 分配的末尾(7.0 的快速边界哨兵)
    bool ownsExe = false, ownsBlob = false;

    // ---- 已验证的 12 张表 ----
    uint8_t* typedefTab  = nullptr; // 70B
    uint8_t* methodTab   = nullptr; // 26B
    uint8_t* methodCodeTab = nullptr; // 8B/条 方法->代码地址(thunk, 供 IDA 定位)
    // 被多个方法共用的代码地址(rva, 方法数), 按方法数降序。
    // IL2CPP 里泛型方法共享同一个派发桩(桩从参数取真实方法指针再调),
    // 所以同一个 rva 会被几十~几千个方法指向 —— 实测最高 2141 个。
    // 这些地址**不是**解码错误, 但拿它们套 IDA 符号会把几万个方法挤到
    // 几百个地址上, 反而污染反编译结果, 所以要单独标出来给脚本过滤。
    // MPT 健康统计(见 locate.cpp): 真表应"不同地址数 == 界内条目数"
    uint32_t mptInImage = 0, mptDistinct = 0, mptDupAddr = 0, mptMaxDup = 0;
    uint8_t* mptrTab     = nullptr; // 4B
    uint8_t* fieldTab    = nullptr; // 8B
    uint8_t* propTab     = nullptr; // 10B
    uint8_t* eventTab    = nullptr; // 14B
    uint8_t* paramTab    = nullptr; // 8B
    uint8_t* ifaceTab    = nullptr; // 4B
    uint8_t* fdesc12Tab  = nullptr; // 12B/条 每类型字段描述符
    uint8_t* fhidx4Tab   = nullptr; // 4B/条  typeIndex -> 描述符下标
    uint8_t* tokentypeTab = nullptr; // 8B
    uint8_t* strBlob     = nullptr; // 字符串 blob
    uint8_t* typeRecTab  = nullptr; // 16B Il2CppType 记录数组(在 exe 映像里, RVA 0x2E1EA20)
    uint64_t typeRecRva  = 0;      // 上面那个数组的 RVA(诊断用)
    // 16B 数组所在 region 的末尾。TypeRecord() 每秒被调用上百万次,
    // 每次 memReadable 都是一次 VirtualQuery(真机 ~1us) => 会把 dump 拖成分钟级。
    // 先用这两个整数做范围判定, 落在区内就直接返回, 不碰系统调用。
    uint64_t typeRecEnd  = 0;
    uint64_t typeRecCount = 0;
    // ---- 运行期堆上的 88B 程序集/镜像表(纯内存模式的权威来源) ----
    uint8_t* asm88Tab    = nullptr; // kRvaAsmTable, 75 x 88B
    uint8_t* img88Tab    = nullptr; // kRvaImgTable, 75 x 88B
    uint32_t asm88Count  = 0;
    uint32_t img88Count  = 0;
    // ---- GENERICINST 堆表 ----
    uint8_t* genTable    = nullptr; // 32B/条 泛型实例表(base, 非 desc)
    uint8_t* genDesc     = nullptr; // 48B 描述符(诊断用)
    uint64_t genTableCount = 0;     // 探测到的条目数(可读页范围内)
    uint8_t* typeArray   = nullptr; // 16B Il2CppType 数组绝对地址(泛型实参下标换算用)

    uint32_t typeCount   = 0;
    uint32_t methodCountTotal = 0;
    uint32_t fieldCountTotal  = 0;

    // ---- 7.0 特性表: 未移植的一律 nullptr ----
    uint8_t* fieldOffTable    = nullptr; // = kT_fieldoff, 4B/条 真实偏移


    uint8_t* fieldDefValTable = nullptr; uint32_t fieldDefValCount = 0;



    uint8_t* fieldDefIdxTable = nullptr; uint32_t fieldDefIdxCount = 0;

    uint8_t* enumDefIdxTable  = nullptr; uint32_t enumDefIdxCount  = 0;
    uint8_t* enumValTab       = nullptr; // = kT_enumval, 12B/条 {u32 全局字段号, i32 值偏移, i32 ?}
    uint8_t* enumValBlob      = nullptr; // = kT_enumvalblob, 值字节区
    uint32_t enumValCount     = 0;


    bool features[FEAT__COUNT] = {false};

    // ---- 字符串 blob ----
    uint64_t strBlobEnd  = 0;

    std::vector<AsmRec> asms;
    std::vector<ImgRec> imgs;

    // 值类型 size/align 缓存(字段偏移推算要用)
    std::unordered_map<uint32_t, uint32_t> sizeCache;
    std::unordered_map<uint32_t, uint8_t>  kindMap; // tdIdx -> 16B 记录 kind
    std::unordered_map<uint32_t, uint32_t> genericDefMap;

    bool valid = false;
    std::string err;
    std::string diag;
};

bool InitCtx(GameCtx& ctx);            // 纯内存入口(唯一产品路径)
bool InitCtxMemory(GameCtx& ctx);      // 同上, 显式名(便于测试/文档)
// native 回归: 注入模块基址(module.bin), 走与真机完全相同的解码路径
void SetBaseOverride(uint8_t* p);
#ifndef _WIN32
void RegisterRegion(const void* p, size_t n);   // 离线测试: 登记可读缓冲区
#endif
void FreeCtx(GameCtx& ctx);
bool memReadable(const void* p, size_t n);
// 廉价边界判定: blob 是**单个连续分配**, 已知起点和长度, 所以绝大多数表的
// 越界检查只需要两次整数比较。
// ⚠️ 不要在热路径上用 memReadable 代替它: 真机每次都是一次 VirtualQuery,
//    一次完整 dump 要调用 2690 万次 => 光系统调用就是 40 秒起(实测换算)。
inline bool inBlob(const GameCtx& c, const void* p, uint64_t n) {
    const uint8_t* b = (const uint8_t*)p;
    return b >= c.blob && (uint64_t)(b - c.blob) + n <= c.blobSize;
}
// 同理: exe 映像按 RVA 连续映射
std::string dec(uint64_t v);
std::string dec(uint64_t v, bool asSigned);
std::string hex64(uint64_t v);
void AppendDiag(GameCtx& ctx, const std::string& s);

// 表定位: 通用形态 table = blob + 528 + (h32(field) OP CONST)
uint8_t* ResolveTable(const GameCtx& ctx, TableSpec s);
// 16B 记录 data 字段(复合类型指向元素记录) -> RVA。磁盘/运行期两种 VA 形态都认。
uint64_t RvaFromVa(const GameCtx& ctx, uint64_t va);
// RVA -> 可读指针。运行期映像直接 +rva; 磁盘文件要过 section 表做 RVA->文件偏移。
const uint8_t* AtRva(const GameCtx& ctx, uint64_t rva);

// ---------------------------------------------------------------- 解码器 -----
std::string DecodeString(const GameCtx& ctx, uint32_t token);
// 同上, 但保证返回合法 UTF-8(非法字节按 latin1 映射)—— 写产物时用这个
std::string DecodeStringLossless(const GameCtx& ctx, uint32_t token);

const uint8_t* TypeRecord(const GameCtx& ctx, uint32_t idx);
bool     IsValueType(const GameCtx& ctx, uint32_t typeIdx);
uint32_t TypeSizeAlign(const GameCtx& ctx, uint32_t typeIdx);
std::string TypeNameByIdx(const GameCtx& ctx, uint32_t typeIdx);
std::string Elem14Name(const GameCtx& ctx, uint32_t idx);   // FEAT_ELEM_14 未移植则返回 ""
std::string TypeParentName(const GameCtx& ctx, uint32_t tdIdx);
uint16_t    TypeDepth(const GameCtx& ctx, uint32_t tdIdx);

std::string MemberName(const GameCtx& ctx, uint32_t idx);
uint32_t MethodReturnTypeIndex(const GameCtx& ctx, uint32_t idx);
uint16_t MethodSlot(const GameCtx& ctx, uint32_t idx);
uint16_t FieldFlags(const GameCtx& ctx, uint32_t idx);
uint32_t MethodParamStart(const GameCtx& ctx, uint32_t idx);
uint32_t MethodParamCount(const GameCtx& ctx, uint32_t idx);
struct ParamInfo { std::string name, type; };
ParamInfo ParamDecode(const GameCtx& ctx, uint32_t sigIdx);

// ---- GENERICINST (kind 0x15) 运行期堆表解码 ----
struct GenericInst {
    bool     resolved = false;   // 整条链是否解出(否则调用方退回 genericinst@N)
    uint32_t defTypeIdx = 0xFFFFFFFFu;  // 泛型定义的 16B 记录索引
    std::vector<std::string> args;     // 实参类型名(已按 16B 下标解析)
};
// data 是**有符号 int32**(movsxd)。全链自检失败时返回 resolved=false。
GenericInst GenericInstanceOf(const GameCtx& ctx, int32_t data, int depth);

uint32_t IfaceTypeIndex(const GameCtx& ctx, uint32_t tdIdx, uint32_t j);
int16_t  IfaceSlot(const GameCtx& ctx, uint32_t tdIdx, uint32_t j);

struct PropRaw { std::string name, type; uint32_t getter, setter, attrs;
                 uint16_t getterSlot = 0xFFFF, setterSlot = 0xFFFF; };
struct EvRaw   { std::string name, type; uint32_t add, remove, raise; };
struct IfaceRaw{ std::string name; uint32_t idx; int16_t slot; };
PropRaw PropDecode(const GameCtx& ctx, uint32_t idx);
EvRaw   EvDecode(const GameCtx& ctx, uint32_t idx);

// 7.0 的字段三件套: 名称/类型 + 真实偏移 + 默认值
// 真实字段偏移 (sub_140512870 确认的 attrBase 链)
struct FieldSlot {
    bool     valid = false;   // attrBase 链是否解出
    bool     hasOffset = false; // 低 24 位是真实实例偏移(否则该字段无实例偏移)
    bool     hasDefault = false;
    uint8_t  flags = 0;       // fattr4 的高字节(bit24=有默认值, bit25/bit26=字段属性位)
    uint32_t offset = 0xFFFFFFFFu;  // 真实实例偏移
    uint32_t defSlot = 0;           // 默认值槽号(bit24 置位时有效)
};
FieldSlot FieldSlotOf(const GameCtx& ctx, uint32_t tdIdx, uint32_t j);
int32_t  FieldAttrBase(const GameCtx& ctx, uint32_t tdIdx);
uint32_t FieldOffset(const GameCtx& ctx, uint32_t tdIdx, uint32_t j);
struct DefValHit {
    bool found = false; uint64_t value = 0; uint32_t size = 0;
};
DefValHit FieldDefaultValue(const GameCtx& ctx, uint32_t key);
uint64_t FieldEnumSlotValue(const GameCtx& ctx, uint32_t idx);
// --- 枚举成员常量值 (sub_14051A510) ---
// globalFieldIdx = fieldStart + j;  width = 底层类型字节数(1/2/4/8)
bool FieldConstValue(const GameCtx& ctx, uint32_t globalFieldIdx, int width,
                     uint64_t* out);
uint32_t EnumValCount(const GameCtx& ctx);
// 值类型字节宽度: 底层类型 kind -> 字节数(未知返回 0)
uint32_t PrimWidthOfRecord(const GameCtx& ctx, uint32_t typeRec);

struct FieldRaw {
    std::string name, type;
    uint32_t typeRec = 0;
    uint64_t value = 0; uint32_t valueSize = 0;
    int      offset = -1; bool offsetKnown = false;
    bool     offsetFromTable = false;   // 偏移来自 metadata 偏移表(而非 CLI 布局推算)
    bool     hasDefault = false;        // 偏移表 bit24 置位
    uint32_t defSlot = 0;               // 默认值槽号
    bool     isStatic = false; bool isConst = false;
};

// ---------------------------------------------------------------- 输出结构 --
struct FieldInfo { FieldRaw f; };
struct MethodInfo {
    std::string name, ret;
    // 方法代码地址相对模块基址; 0 = 无实现(抽象/未生成/纯虚)。
    // ⚠️ 只能从**真 MPT** kRvaMethodCodePtrs 取 —— 另一张 0x27D4DE0 是泛型桩表,
    // 用它会让普通属性 getter 指向 `*a5 = a1()` 那种派发桩(见 dumper.h 常量区)。
    uint64_t rva = 0;
    uint16_t flags = 0;
    std::vector<ParamInfo> params;
};
struct TypeInfo {
    std::string ns, name, parent;
    std::string image;          // image=simpleName("mscorlib")
    // Il2CppDumper 的 "// Image N: name - start:count" 需要程序集序号和类型区间,
    // 只存 image 名字串不够(名字不唯一, 且拿不到 typeStart/typeCount)。

    uint32_t asmIdx   = 0xFFFFFFFFu;  // 在 ctx.asms 里的下标
    uint32_t tdIdx = 0;

    bool isValueType = false;
    bool isEnum = false;              // 有 value__ 实例字段(枚举判据, 见 FORMULAS §15)
    std::string underlying;           // 枚举底层类型名
    uint32_t instanceSize = 0, align = 0;
    std::vector<FieldInfo>  fields;
    std::vector<IfaceRaw>   ifaces;
    std::vector<PropRaw>    props;
    std::vector<EvRaw>      evs;
    std::vector<FieldRaw>   enumVals;
    std::vector<MethodInfo> methods;

};

// 逐类型回调。**不保留全部类型** —— 只把当前类型交给 sink, 随后立刻释放。
//
// ⚠️ 2026-09-26 真机事故: 之前把 88,902 个 TypeInfo 全部累积在一个 vector 里
// (实测峰值 RSS 868MB), 在被注入的游戏进程里这份堆结构会被破坏, 写 dump.cs 时
// 读到的 &t 变成野指针 -> 0xC0000005。改成边解码边输出后, 同时只存活一个类型,
// 峰值内存从 868MB 降到几 MB, 根本不存在被破坏的累积结构。
using TypeSink = void (*)(void* user, const TypeInfo& t, uint32_t index);
bool DecodeAllTypes(GameCtx& ctx, TypeSink sink, void* user);
// 字段偏移交叉验证统计
struct OffStat { uint64_t offAgree = 0, offDisagree = 0, offNoTable = 0, fieldsWithDefault = 0;
                 uint64_t enumTypes = 0, enumMembers = 0, enumConstTable = 0; };
const OffStat& FieldOffsetStats();
bool RunDump(GameCtx& ctx, const std::wstring& outDir);

} // namespace gs
