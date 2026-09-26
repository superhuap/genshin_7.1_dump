// meta.cpp —— 7.0 dumper 的解码器结构, 公式全部换成 7.1
//
// IDA 来源(v3 实测 + v4 native 全量回归验证):
//   sub_140512870 SetupFields     -> 字段表/字段名/字段类型
//   sub_140514630 SetupMethods    -> 方法表/方法名/返回类型/flags/参数
//   sub_1405151D0 SetupProperties -> 属性名/getter/setter
//   sub_140514CF0 SetupEvents     -> 事件名/类型/adder/remover/invoker
//   sub_14050F280                 -> 16B Il2CppType 数组的类型名
//   sub_1405282B0 / sub_140528560 -> 字符串 blob(见 string.cpp)
//
// 相对 v4 的两处结构性差别:
//   1. 16B 类型记录数组改从 exe 映像的静态数组取(RVA 0x2E1EA20), 不碰运行期 Class 池
//   2. 复合类型 data 字段走 RvaFromVa(), 磁盘/运行期两种 VA 形态都认
#include "dumper.h"
#include <cctype>
#include <cstdlib>
#include <map>

namespace gs {

// ---------------------------------------------------------------- 混淆原语 --
uint32_t param_key_of(uint32_t idx) {
    uint64_t v = ((41617ull * idx + 1219887025ull) & 0xFFFFFFFFFFFFFFFFull) ^ 0x19E1D47Aull;
    return (uint32_t)(((((uint64_t)1457992407ull * v) & 0xFFFFFFFFFFFFFFFFull) >> 21) + 2068375556ull) & 0xFFFFFFFFu;
}

const char* TypeKindName(uint8_t k) {
    switch (k) {
        case TE_VOID: return "void";   case TE_BOOLEAN: return "bool";
        case TE_CHAR: return "char";   case TE_I1: return "sbyte";
        case TE_U1: return "byte";     case TE_I2: return "short";
        case TE_U2: return "ushort";   case TE_I4: return "int";
        case TE_U4: return "uint";     case TE_I8: return "long";
        case TE_U8: return "ulong";    case TE_R4: return "float";
        case TE_R8: return "double";   case TE_STRING: return "string";
        case TE_OBJECT: return "object";
        case TE_TYPEDBYREF: return "System.TypedReference";
        case TE_PTR: return "ptr";      case TE_BYREF: return "byref";
        case TE_VALUETYPE: return "valuetype"; case TE_CLASS: return "class";
        case TE_VAR: return "var";      case TE_ARRAY: return "array";
        case TE_GENERICINST: return "genericinst"; case TE_SZARRAY: return "szarray";
        case TE_I: return "nint";      case TE_U: return "nuint";
        case TE_ENUM: return "enum";    case TE_MVAR: return "mvar";
        default: return "?";
    }
}
static const char* primitive_name(uint8_t te) {
    switch (te) {
        case TE_VOID: return "void";     case TE_BOOLEAN: return "bool";
        case TE_CHAR: return "char";     case TE_I1: return "sbyte";
        case TE_U1: return "byte";       case TE_I2: return "short";
        case TE_U2: return "ushort";     case TE_I4: return "int";
        case TE_U4: return "uint";       case TE_I8: return "long";
        case TE_U8: return "ulong";      case TE_R4: return "float";
        case TE_R8: return "double";     case TE_STRING: return "string";
        case TE_OBJECT: return "object"; case TE_TYPEDBYREF: return "System.TypedReference";
        default: return nullptr;
    }
}

// ---------------------------------------------------------------- 16B 记录 --
const uint8_t* TypeRecord(const GameCtx& ctx, uint32_t index) {
    if (!ctx.typeRecTab || index > 0x1FFFFF) return nullptr;
    const uint8_t* p = ctx.typeRecTab + 16ull * index;
    // 快路径: 落在已探测的 region 内 -> 纯整数比较, 不做 VirtualQuery。
    // 这一项在真机上决定了 dump 是 30 秒还是 30 分钟。
    if (ctx.typeRecEnd && (uint64_t)(p + 16) <= ctx.typeRecEnd) return p;
    if (ctx.typeRecCount && index < ctx.typeRecCount) return p;
    return memReadable(p, 16) ? p : nullptr;
}
// 复合类型(PTR/BYREF/SZARRAY/ARRAY)的 data 是指向元素记录的 VA
static const uint8_t* recAtVa(const GameCtx& ctx, uint64_t va) {
    uint64_t rva = RvaFromVa(ctx, va);
    if (!rva) return nullptr;
    const uint8_t* p = AtRva(ctx, rva);
    return p;   // AtRva 已做映像范围判定, 不再叠加 memReadable(热路径)
}
static uint32_t recIndexAtVa(const GameCtx& ctx, uint64_t va) {
    const uint8_t* p = recAtVa(ctx, va);
    if (!p || !ctx.typeRecTab || p < ctx.typeRecTab) return 0xFFFFFFFFu;
    uint64_t d = (uint64_t)(p - ctx.typeRecTab);
    if (d % 16) return 0xFFFFFFFFu;
    return (uint32_t)(d / 16);
}

static std::string TypeDefFullName(const GameCtx& ctx, uint32_t index) {
    if (!ctx.typedefTab || index >= ctx.typeCount) return "?";
    const uint8_t* r = ctx.typedefTab + 70ull * index;
    if (!inBlob(ctx, r, 70)) return "?";
    std::string ns = DecodeStringLossless(ctx, rd32(r) - 1145778368u);
    std::string nm = DecodeStringLossless(ctx, rd32(r + 36) - 72511848u);
    if (nm.empty() && ns.empty()) return "?";
    if (ns.empty() || ns == "?") return nm;
    return ns + "." + nm;
}

// ---------------------------------------------------------------------------
// GENERICINST (kind 0x15) —— 运行期堆表
//
// 指令级依据 sub_1404E3CC0 case 21 (0x1404E3DC7 起):
//   mov  rax, cs:qword_145AD4E98      ; desc
//   mov  rax, [rax+8]                 ; table
//   movsxd rcx, dword ptr [r15]       ; data = **有符号** int32
//   shl  rcx, 5                       ; *32
//   mov  rsi, [rax+rcx+8]             ; argsNode
//   ...  cmp r14d, [rsi]              ; argc = *(u32*)argsNode
//       mov rax, [rsi+8]              ; args  = *(u64*)(argsNode+8)
//       mov rcx, [rax+rcx*8]          ; args[i] = Il2CppType*
//   mov  ecx, [rax+rcx]               ; *(u32*)rec = 泛型定义的 16B 记录索引
// 随后 sub_14051CD50(defIdx) 取定义名, 并把 (rec - table)/32 写回做缓存。
//
// 实参是**裸指针**指向 16B Il2CppType 数组, 所以下标 = (args[i] - typeArray) / 16。
// 全链任何一步不自洽就返回 resolved=false, 调用方退回 genericinst@N ——
// 宁可少一条信息, 也不能输出假类型名(这类 bug 最难查)。
// ---------------------------------------------------------------------------
uint64_t g_genCalls = 0;      // 诊断: GenericInstanceOf 被调了多少次

// ⚠️ depth 必须**单调传递**下去。
// 之前实参解析走 TypeNameByIdx(), 它内部是 TypeNameOfRecord(..., 0) —— 把 depth
// 重置为 0。于是 TypeNameOfRecord(0,d) 展开出 GenericInstanceOf, 实参再回到
// TypeNameOfRecord(0,0), 每层重新长一棵完整子树 => 递归是**指数型**。
// 实测: 一个 2 条目的合成自引用表把 GenericInstanceOf 调了 1016 万次, 真机上
// 表现就是"解算全部类型"永远卡住(2026-09-26)。
// 现在 depth 一路 depth+1 传下去, 严格受 TypeNameOfRecord 的 depth>8 限制。
static std::string TypeNameOfRecord(const GameCtx& ctx, uint32_t recIndex, int depth);

GenericInst GenericInstanceOf(const GameCtx& ctx, int32_t data, int depth) {
    GenericInst g;
    ++g_genCalls;
    if (!ctx.features[FEAT_GENERIC_INST] || !ctx.genTable || !ctx.typeArray) return g;
    if (depth > 8) return g;                      // 环形: 放弃展开, 调用方退回占位

    // 负下标是从表基址往回索引(全库 1,451 条), 一律按绝对偏移处理。
    int64_t off = (int64_t)data * (int64_t)kGenRecSize;
    if (off < 0) off = -off;                       // 向下越界的记录取镜像位置
    const uint8_t* rec = ctx.genTable + off;
    if (!memReadable(rec, kGenRecSize)) return g;
    // 条目必须落在已探测范围内
    if (ctx.genTableCount && (uint64_t)off / kGenRecSize >= ctx.genTableCount) return g;

    uint32_t defRec = rd32(rec + 0);                // 泛型定义的 16B 记录索引
    if (!memReadable(ctx.typeArray + (uint64_t)defRec * 16, 16)) return g;

    const uint8_t* argsNode = (const uint8_t*)rd64(rec + 8);
    if (!argsNode || !memReadable(argsNode, 16)) return g;
    uint32_t argc = rd32(argsNode + 0);
    const uint8_t* args = (const uint8_t*)rd64(argsNode + 8);
    if (argc > kGenMaxArgs) return g;               // 坏数据
    if (argc && (!args || !memReadable(args, (uint64_t)argc * 8))) return g;

    // 先把实参全部解析成 16B 下标, 有一项失败就整体放弃
    std::vector<uint32_t> idx(argc);
    for (uint32_t i = 0; i < argc; ++i) {
        uint64_t p = rd64(args + 8ull * i);
        if (p < (uint64_t)ctx.typeArray) return g;
        uint64_t d = p - (uint64_t)ctx.typeArray;
        if (d & 15) return g;                       // 必须 16B 对齐
        uint64_t k = d >> 4;
        if (!memReadable(ctx.typeArray + k * 16, 16)) return g;
        idx[i] = (uint32_t)k;
    }

    g.defTypeIdx = defRec;
    g.args.reserve(argc);
    for (uint32_t i = 0; i < argc; ++i) {
        std::string a = TypeNameOfRecord(ctx, idx[i], depth + 1);
        if (a.empty()) return g;                    // 解析出空名 = 不可信
        g.args.push_back(a);
    }
    g.resolved = true;
    return g;
}

static std::string TypeNameOfRecord(const GameCtx& ctx, uint32_t recIndex, int depth) {
    if (depth > 8) return "?";
    // 记录现场: AV 多半发生在读某个 16B 记录时, 有 recIndex + data 才查得动
    SetStage("TypeNameOfRecord", recIndex, (uint64_t)(uintptr_t)ctx.typeRecTab);
    const uint8_t* rec = TypeRecord(ctx, recIndex);
    if (!rec) return "?";
    uint64_t data = rd64(rec);
    SetStage("TypeNameOfRecord.data", recIndex, data);
    uint8_t  te   = rd8(rec + 10);
    if (const char* prim = primitive_name(te)) return prim;
    switch (te) {
        case TE_VALUETYPE: case TE_CLASS: case TE_ENUM:
            return (data < ctx.typeCount) ? TypeDefFullName(ctx, (uint32_t)data) : "?";
        case TE_I: return (data < ctx.typeCount) ? TypeDefFullName(ctx, (uint32_t)data) : "System.IntPtr";
        case TE_U: return (data < ctx.typeCount) ? TypeDefFullName(ctx, (uint32_t)data) : "System.UIntPtr";
        // 元素记录解不出来时**保留外层包装**(渲染成 array<?> / T[] 而不是 ?):
        // "是个数组但元素未知" 比笼统的 "?" 信息量大。v3 在这种地方会读到
        // .data 未初始化区的零记录并渲染成 array<type?(0x00)>, 那是假信息。
        case TE_PTR: case TE_BYREF: case TE_SZARRAY: {
            uint32_t ei = recIndexAtVa(ctx, data);
            std::string inner = (ei == 0xFFFFFFFFu) ? std::string("?")
                                                     : TypeNameOfRecord(ctx, ei, depth + 1);
            return te == TE_PTR ? inner + "*" : te == TE_BYREF ? inner + "&" : inner + "[]";
        }
        case TE_ARRAY: {
            uint32_t ei = recIndexAtVa(ctx, data);
            return "array<" + ((ei == 0xFFFFFFFFu) ? std::string("?")
                                                   : TypeNameOfRecord(ctx, ei, depth + 1)) + ">";
        }
        // ⚠️ data 是**有符号** int32(反汇编里是 `movsxd rcx, dword ptr [r15]`),
        // 全库 439,914 条 GENERICINST 里 1,451 条高位非 0 = 负数, 是从表基址往回索引。
        // 按 u64 打印会把负数显示成 1.8e19 那种天量, 看不出是负的。
        case TE_GENERICINST: {
            GenericInst gi = GenericInstanceOf(ctx, (int32_t)(uint32_t)data, depth + 1);
            if (!gi.resolved) return "genericinst@" + dec((uint64_t)(int64_t)(int32_t)(uint32_t)data);
            std::string full = TypeNameOfRecord(ctx, gi.defTypeIdx, depth + 1);
            if (full.empty() || full[0] == '?') return full;
            full += "<";
            for (size_t i = 0; i < gi.args.size(); ++i) {
                if (i) full += ",";
                full += gi.args[i];
            }
            full += ">";
            return full;
        }
        case TE_VAR:  return "!"  + dec(data);
        case TE_MVAR: return "!!" + dec(data);
        default: return std::string("type?(") + TypeKindName(te) + ")";
    }
}
std::string TypeNameByIdx(const GameCtx& ctx, uint32_t typeIdx) {
    return TypeNameOfRecord(ctx, typeIdx, 0);
}
std::string Elem14Name(const GameCtx& ctx, uint32_t idx) {
    if (!ctx.features[FEAT_ELEM_14]) return std::string();   // 未移植, 如实返回空
    (void)idx; return std::string();
}

// ---------------------------------------------------------- kind/size 缓存 --
namespace {
struct KindMap {
    std::map<uint32_t, uint8_t> kindOf;                        // tdIdx -> 16B kind 字节
    std::map<uint32_t, std::pair<uint32_t, uint32_t>> vtLayout; // tdIdx -> (size, align)
    bool ready = false;
};
KindMap g_k;

void BuildKindMap(const GameCtx& ctx) {
    if (g_k.ready) return;
    // byvalType 覆盖 struct 与原始类型, 是值类型判定的主要依据
    for (uint32_t i = 0; i < ctx.typeCount; ++i) {
        const uint8_t* td = ctx.typedefTab + 70ull * i;
        if (!inBlob(ctx, td, 70)) break;
        uint32_t byval = rd32(td + 4) ^ 0x0DA4711Bu;
        const uint8_t* r = TypeRecord(ctx, byval);
        if (r) g_k.kindOf[i] = rd8(r + 10);
    }
    g_k.ready = true;
}
} // namespace

// ⚠️ 不能只看 kind 表: 原始类型没有"VALUETYPE 记录反引用自己"这种结构
//    (全表 683,574 条里 data==System.Int32 && kind∈(VT,CL,EN) 的记录数 = 0),
//    只看它 System.Int32 会被误判成 class。byvalType 那条记录才是关键。
bool IsValueType(const GameCtx& ctx, uint32_t typeIndex) {
    if (typeIndex < ctx.typeCount && ctx.typedefTab) {
        const uint8_t* td = ctx.typedefTab + 70ull * typeIndex;
        uint32_t byval = rd32(td + 4) ^ 0x0DA4711Bu;
        const uint8_t* r = TypeRecord(ctx, byval);
        if (r) {
            uint8_t te = rd8(r + 10);
            switch (te) {
                case TE_VALUETYPE: case TE_ENUM: return true;
                case TE_BOOLEAN: case TE_CHAR: case TE_I1: case TE_U1:
                case TE_I2: case TE_U2: case TE_I4: case TE_U4:
                case TE_I8: case TE_U8: case TE_R4: case TE_R8:
                case TE_I: case TE_U: return true;
                case TE_CLASS: case TE_OBJECT: case TE_STRING: case TE_SZARRAY:
                case TE_PTR: case TE_BYREF: case TE_ARRAY: case TE_GENERICINST: return false;
                default: break;
            }
        }
    }
    BuildKindMap(ctx);
    auto it = g_k.kindOf.find(typeIndex);
    uint8_t k = (it == g_k.kindOf.end()) ? 0 : it->second;
    return k == TE_VALUETYPE || k == TE_ENUM;
}

static uint32_t FieldTypeRec(const GameCtx& ctx, uint32_t typeIndex, uint32_t fieldIdx) {
    const uint8_t* r = ctx.typedefTab + 70ull * typeIndex;
    uint32_t fs = rd32(r + 28) ^ 0x29010897u;
    const uint8_t* rec = ctx.fieldTab + 8ull * (fs + fieldIdx);
    return (field_key(fs + fieldIdx) ^ rd32(rec) ^ 0x2D27D873u) & 0xFFFFFFFFu;
}

static uint32_t TypeSize(const GameCtx& ctx, uint32_t recIndex, uint32_t* alignOut) {
    uint32_t al = 1, sz = 0;
    const uint8_t* rec = TypeRecord(ctx, recIndex);
    if (rec) {
        uint8_t te = rd8(rec + 10);
        if (primitive_name(te)) {
            switch (te) {
                case TE_VOID: sz = 0; al = 1; break;
                case TE_BOOLEAN: case TE_I1: case TE_U1: sz = 1; al = 1; break;
                case TE_CHAR: case TE_I2: case TE_U2: sz = 2; al = 2; break;
                case TE_I4: case TE_U4: case TE_R4: sz = 4; al = 4; break;
                default: sz = 8; al = 8; break;
            }
        } else if (te == TE_VALUETYPE || te == TE_ENUM) {
            auto it = g_k.vtLayout.find((uint32_t)rd32(rec));
            if (it != g_k.vtLayout.end()) { sz = it->second.first; al = it->second.second; }
            else                          { sz = 8; al = 8; }
        } else { sz = 8; al = 8; }
    } else { sz = 8; al = 8; }
    if (alignOut) *alignOut = al;
    return sz;
}

uint32_t TypeSizeAlign(const GameCtx& ctx, uint32_t typeIndex) {
    BuildKindMap(ctx);
    auto it = g_k.vtLayout.find(typeIndex);
    if (it != g_k.vtLayout.end()) return it->second.first;
    if (!ctx.typedefTab || typeIndex >= ctx.typeCount) return 8;
    const uint8_t* r = ctx.typedefTab + 70ull * typeIndex;
    uint32_t fc = rd16(r + 56) ^ 0x51A8u;
    if (fc > 4096) return 8;
    uint32_t off = 0, al = 1;
    for (uint32_t q = 0; q < fc; ++q) {
        uint32_t ftr = FieldTypeRec(ctx, typeIndex, q);
        const uint8_t* tr = TypeRecord(ctx, ftr);
        if (tr && (rd16(tr + 8) & 0x8000)) continue;                 // const 不占位
        if (tr && (rd8(tr + 10) == TE_CLASS || rd8(tr + 10) == TE_VALUETYPE) && rd64(tr) == typeIndex)
            continue;                                                   // 自引用 => static
        uint32_t a2 = 1, s2 = TypeSize(ctx, ftr, &a2);
        if (a2 > al) al = a2;
        off = (off + a2 - 1) & ~(a2 - 1);
        off += s2;
    }
    off = (off + al - 1) & ~(al - 1);
    g_k.vtLayout[typeIndex] = { off, al };
    return off;
}

// ---------------------------------------------------------------- 继承链 ----
std::string TypeParentName(const GameCtx& ctx, uint32_t tdIdx) {
    if (!ctx.typedefTab || tdIdx >= ctx.typeCount) return std::string();
    const uint8_t* td = ctx.typedefTab + 70ull * tdIdx;
    uint32_t pr = (rd32(td + 16) - 1950851500u) & 0xFFFFFFFFu;
    if (pr == 0xFFFFFFFFu) return std::string();
    const uint8_t* rec = TypeRecord(ctx, pr);
    if (!rec) return std::string();
    uint8_t te = rd8(rec + 10);
    if (te != TE_CLASS && te != TE_VALUETYPE) return std::string();
    uint64_t d = rd64(rec);
    if (d >= ctx.typeCount) return std::string();
    // 递归解析成 typedef 名(基类记录里存的可能是 CLASS 记录)
    return TypeDefFullName(ctx, (uint32_t)d);
}
uint16_t TypeDepth(const GameCtx& ctx, uint32_t tdIdx) {
    uint16_t d = 0;
    uint32_t cur = tdIdx;
    for (int guard = 0; guard < 64; ++guard) {
        if (!ctx.typedefTab || cur >= ctx.typeCount) break;
        const uint8_t* td = ctx.typedefTab + 70ull * cur;
        uint32_t pr = (rd32(td + 16) - 1950851500u) & 0xFFFFFFFFu;
        const uint8_t* rec = TypeRecord(ctx, pr);
        if (!rec) break;
        uint8_t te = rd8(rec + 10);
        if (te != TE_CLASS && te != TE_VALUETYPE) break;
        uint64_t nx = rd64(rec);
        if (nx >= ctx.typeCount || nx == cur) break;
        cur = (uint32_t)nx;
        if (++d > 63) break;
    }
    return d;
}

// ---------------------------------------------------------------- 方法 ------
uint32_t MethodRetOf(const GameCtx& ctx, uint32_t i) {
    const uint8_t* r = ctx.methodTab + 26ull * i;
    return (rd32(r + 8) ^ method_key(i) ^ 0x3F7BDF39u) & 0xFFFFFFFFu;
}
std::string MemberName(const GameCtx& ctx, uint32_t i) {
    const uint8_t* r = ctx.methodTab + 26ull * i;
    return DecodeStringLossless(ctx, (method_key(i) ^ ((rd32(r) - 1524016681u) & 0xFFFFFFFFu)));
}
uint16_t MethodFlags(const GameCtx& ctx, uint32_t i) {
    const uint8_t* r = ctx.methodTab + 26ull * i;
    return (uint16_t)(rd16(r + 22) ^ (uint16_t)method_key16(i) ^ 0x8F60u);
}
uint32_t MethodParamStart(const GameCtx& ctx, uint32_t i) {
    const uint8_t* r = ctx.methodTab + 26ull * i;
    return (method_key(i) ^ ((rd32(r + 4) - 257927898u) & 0xFFFFFFFFu)) & 0xFFFFFFFFu;
}
uint32_t MethodParamCount(const GameCtx& ctx, uint32_t i) {
    const uint8_t* r = ctx.methodTab + 26ull * i;
    return (uint8_t)((method_key(i) ^ ((rd8(r + 24) - 31) & 0xFF)) & 0xFF);
}
uint16_t MethodSlot(const GameCtx& ctx, uint32_t i) {
    if (!ctx.mptrTab) return 0xFFFFu;
    const uint8_t* p = ctx.mptrTab + 4ull * i;
    if (!inBlob(ctx, p, 4)) return 0xFFFFu;
    return (uint16_t)rd32(p);
}
uint32_t MethodReturnTypeIndex(const GameCtx& ctx, uint32_t i) { return MethodRetOf(ctx, i); }
uint16_t FieldFlags(const GameCtx& ctx, uint32_t idx) { (void)ctx; (void)idx; return 0; }

ParamInfo ParamDecode(const GameCtx& ctx, uint32_t sigIdx) {
    ParamInfo pi;
    const uint8_t* p = ctx.paramTab + 8ull * sigIdx;
    if (!inBlob(ctx, p, 8)) return pi;
    uint32_t pk = param_key_of(sigIdx);
    pi.name = DecodeStringLossless(ctx, (pk ^ ((rd32(p + 4) - 1764493660u) & 0xFFFFFFFFu) ^ 0x4CDBD093u));
    uint32_t ti = (rd32(p) ^ pk ^ 0x31BF59F3u) & 0xFFFFFFFFu;
    pi.type = TypeNameOfRecord(ctx, ti, 0);
    return pi;
}

// ---------------------------------------------------------------- 接口 ------
uint32_t IfaceTypeIndex(const GameCtx& ctx, uint32_t tdIdx, uint32_t j) {
    if (!ctx.ifaceTab || !ctx.typedefTab || tdIdx >= ctx.typeCount) return 0xFFFFFFFFu;
    const uint8_t* td = ctx.typedefTab + 70ull * tdIdx;
    uint32_t start = (uint32_t)((int32_t)(int16_t)(rd16(td + 54) + 6631)) & 0xFFFFFFFFu;
    const uint8_t* p = ctx.ifaceTab + 4ull * (start + j);
    if (!inBlob(ctx, p, 4)) return 0xFFFFFFFFu;
    return rd32(p);
}
int16_t IfaceSlot(const GameCtx& ctx, uint32_t tdIdx, uint32_t j) {
    if (!ctx.features[FEAT_IFACE_SLOT]) return -1;      // 7.1 未移植
    (void)tdIdx; (void)j; return -1;
}

// ------------------------------------------------------------ 属性 / 事件 ----
// 判据必须与 v3 的 _ident 严格一致(^[.A-Za-z_<>$][A-Za-z0-9_`\[\]<>{}$.]{0,80}$),
// 否则纠偏时挑中的候选 propStart 与 v3 不同, 闭包/状态机类的属性名会整段错位。
// 实测: 判据放宽(允许空格/不限首字符)会让属性语义一致率从 ~100% 掉到 88.7%。
static bool PropRecordOk(const GameCtx& ctx, uint32_t i) {
    const uint8_t* o = ctx.propTab + 10ull * i;
    if (!inBlob(ctx, o, 10)) return false;
    uint32_t k = prop_key(i);
    std::string nm = DecodeString(ctx, (k ^ ((rd32(o) - 1953953095u) & 0xFFFFFFFFu)));
    if (nm.empty() || nm.size() > 81) return false;                 // 首字符 + 最多 80
    auto ok1 = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
               c == '<' || c == '>' || c == '$' || c == '.';
    };
    auto okN = [&](char c) {
        return ok1(c) || (c >= '0' && c <= '9') || c == '`' || c == '[' || c == ']';
    };
    if (!ok1(nm[0])) return false;
    for (size_t k2 = 1; k2 < nm.size(); ++k2) if (!okN(nm[k2])) return false;
    uint32_t getter = ((rd16(o + 6) ^ (uint16_t)k) ^ 0xE5A2u) & 0xFFFFu;
    return getter == 0xFFFFu || getter < 4096;
}
PropRaw PropDecode(const GameCtx& ctx, uint32_t idx) {
    PropRaw p;
    const uint8_t* o = ctx.propTab + 10ull * idx;
    if (!inBlob(ctx, o, 10)) return p;
    uint32_t k  = prop_key(idx);
    uint16_t kl = (uint16_t)k;
    p.name   = DecodeStringLossless(ctx, (k ^ ((rd32(o) - 1953953095u) & 0xFFFFFFFFu)));
    p.getter = ((rd16(o + 6) ^ kl) ^ 0xE5A2u) & 0xFFFFu;
    p.setter = ((uint16_t)(rd16(o + 8) - 23324u) ^ kl) & 0xFFFFu;
    p.attrs  = 0;
    p.type   = "?";   // 由调用方用 getter 返回类型填(7.0 同款约定)
    return p;
}
EvRaw EvDecode(const GameCtx& ctx, uint32_t idx) {
    EvRaw e;
    const uint8_t* o = ctx.eventTab + 14ull * idx;
    if (!inBlob(ctx, o, 14)) return e;
    uint32_t k  = event_key(idx);
    uint16_t kl = (uint16_t)k;
    e.remove = (rd16(o + 8)  ^ kl ^ 0xEE66u) & 0xFFFFu;
    e.raise  = ((uint16_t)(rd16(o + 10) - 30703u) ^ kl) & 0xFFFFu;
    e.add    = (rd16(o + 12) ^ kl ^ 0xBEA7u) & 0xFFFFu;
    e.name   = DecodeStringLossless(ctx, (k ^ ((rd32(o + 4) - 1037298109u) & 0xFFFFFFFFu)));
    e.type   = TypeNameOfRecord(ctx, (k ^ ((rd32(o) - 452544412u) & 0xFFFFFFFFu)) & 0xFFFFFFFFu, 0);
    return e;
}


// ------------------------------------------------ 真实字段偏移 (sub_140512870) --
// IDA 反汇编(0x140512b54..0x140512cbd)还原出的完整链:
//   r9  = blob528 + h32(376) + 0x0ADEC9E28          (4B/条, hidx4)
//   r8  = blob528 + h32(144) + 0x0B7255040          (12B/条, desc12)
//   idx = i32( hidx4[ ((70*ti)>>1) * 0x8AF8AF8B ] )  <- 0x8AF8AF8B 是 35 的模逆元, 整体等价 ti
//   desc = desc12 + 12*idx
//   attrBase = i32( desc + 8 )
//   e    = fattr4[ attrBase + j ]                    fattr4 = blob528 + (h32(296) ^ 0x0F92DC85)
//
// ⚠️ 早先判定"attrBase 索引链对不上"是**判据选错**: 当时用
//    `attrBase(i+1) == attrBase(i)+fieldCount(i)` 做连续性检查, 只有 11% 通过。
//    但 hidx4 是一张真实的重排表(hidx4[0..3]=0, hidx4[4]=1, ...), desc12 的分配顺序
//    与 typedef 顺序本来就不一致, 连续性不是必要条件。换成"偏移是否构成合法布局"后
//    立刻自证: 73,986 个有实例字段的类型里 88.30% 按字段序严格升序无重复。
int32_t FieldAttrBase(const GameCtx& ctx, uint32_t tdIdx) {
    if (!ctx.fhidx4Tab || !ctx.fdesc12Tab || tdIdx >= ctx.typeCount) return -1;
    // 索引变换 ((70*ti)>>1)*0x8AF8AF8B 恒等于 ti, 这里保留原始形式以便对照反汇编
    uint32_t ti = tdIdx;
    int32_t di = (int32_t)rd32(ctx.fhidx4Tab + 4ull * ti);
    if (di < 0) return -1;
    const uint8_t* desc = ctx.fdesc12Tab + 12ull * (uint32_t)di;
    if ((uint64_t)(desc + 12) > (uint64_t)ctx.blob + ctx.blobSize) return -1;
    return (int32_t)rd32(desc + 8);
}
FieldSlot FieldSlotOf(const GameCtx& ctx, uint32_t tdIdx, uint32_t j) {
    FieldSlot fs;
    if (!ctx.features[FEAT_FIELD_OFFSET] || !ctx.fieldOffTable) return fs;
    int32_t ab = FieldAttrBase(ctx, tdIdx);
    if (ab < 0) return fs;
    uint64_t p = (uint64_t)ctx.fieldOffTable + 4ull * ((uint64_t)ab + j);
    if (p + 4 > (uint64_t)ctx.blob + ctx.blobSize) return fs;
    uint32_t e = rd32((const uint8_t*)p);
    fs.valid     = true;
    fs.flags     = (uint8_t)(e >> 24);
    fs.hasDefault = (e & 0x1000000u) != 0;
    // 实例字段 ⟺ 0 < e < 0x1000000, 此时低 24 位就是真实实例偏移。
    // e == 0 或高字节非 0 => static/const(不占实例空间)。低 24 位此时是别的含义
    // (static 存储区偏移 / 属性位), **不是**实例偏移, 不能拿来当偏移用。
    //
    // ⚠️ 判据换过两版, 两次都栽在"只取一部分标志位"上:
    //   v1  static = (e==0 || hi==0x01)  -> 实例升序仅 83.8%
    //   v2  static = (e==0 || hi!=0)     -> 实例升序 99.92%, static 前置 100%
    // 差别在于 hi 的 0x02 / 0x04 也都是 static 标记, 不止 0x01。
    fs.hasOffset = (e != 0) && ((e >> 24) == 0);
    fs.offset    = e & 0xFFFFFFu;
    fs.defSlot   = e & 0xFFFFFFu;
    return fs;
}
uint32_t FieldOffset(const GameCtx& ctx, uint32_t tdIdx, uint32_t j) {
    FieldSlot fs = FieldSlotOf(ctx, tdIdx, j);
    return fs.valid ? fs.offset : 0xFFFFFFFFu;
}
DefValHit FieldDefaultValue(const GameCtx& ctx, uint32_t key) {
    DefValHit h;
    if (!ctx.features[FEAT_FIELD_DEFVAL]) return h;
    (void)key; return h;
}
uint64_t FieldEnumSlotValue(const GameCtx& ctx, uint32_t idx) {
    if (!ctx.features[FEAT_ENUM_VALUES]) return 0;
    (void)idx; return 0;
}

// ---------------------------------------------------------------- 枚举常量 ----
// 来源: sub_14051A510 (EnumValue)。反汇编:
//   v2  = FieldInfo.declaring ^ 0x66E0FC4E3B7EF117
//   v3  = (FieldInfo* - v2->fields) >> 5          // 类内字段号(32B/条)
//   key = v3 + ( *(i32*)(v2->typedef + 28) ^ 0x29010897 )   // = 全局字段号 = fieldStart + j
//   p   = blob + (h32(316) ^ 0x593DE464);  end = p + 3*((h32(84) ^ 0x23E67A90)/12)
//   while (key != *p) { p += 3; if (p >= end) miss; }        // key 严格升序 -> 可二分
//   slot = p[1];  if (slot == -1) miss;
//   v    = blob + (h32(160) ^ 0x3F525210) + slot;             // 原始字节, 不解混淆
//   按底层类型宽度读: 1/2/4/8 字节
// 实测: 75,548 条, key 从 155 到 440164 严格升序, slot 严格递增且步长 = 值宽度
//       (4 字节枚举步长 4, 8 字节枚举步长 8) -> 槽位互不重叠, 按宽度读是安全的。
// oracle: ConsoleColor Black..White = 0..15 / AttributeTargets Assembly..All =
//         1,2,4,...,16384,32767 / RegistryHive = 0x80000000..0x80000006 —— 与 .NET 完全一致。
uint32_t EnumValCount(const GameCtx& ctx) { return ctx.enumValCount; }

uint32_t PrimWidthOfRecord(const GameCtx& ctx, uint32_t typeRec) {
    const uint8_t* r = TypeRecord(ctx, typeRec);
    if (!r) return 0;
    switch (rd8(r + 10)) {          // 16B 记录的 type 字节在 +10 (u64 data, u16 attrs, u8 type, u8 bits)
        case TE_BOOLEAN: case TE_I1: case TE_U1:            return 1;
        case TE_CHAR:  case TE_I2:   case TE_U2:            return 2;
        case TE_I4:    case TE_U4:   case TE_R4: case TE_ENUM: return 4;
        case TE_I8:    case TE_U8:   case TE_R8: case TE_I: case TE_U: return 8;
        default: return 0;
    }
}

bool FieldConstValue(const GameCtx& ctx, uint32_t globalFieldIdx, int width,
                     uint64_t* out) {
    if (!ctx.enumValTab || !ctx.enumValBlob || !ctx.enumValCount) return false;
    if (width != 1 && width != 2 && width != 4 && width != 8) return false;
    // key 严格升序 -> 二分
    uint32_t lo = 0, hi = ctx.enumValCount;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t k = rd32(ctx.enumValTab + 12ull * mid);
        if (k == globalFieldIdx) {
            int32_t slot = (int32_t)rd32(ctx.enumValTab + 12ull * mid + 4);
            if (slot < 0) return false;
            const uint8_t* p = ctx.enumValBlob + slot;
            if (p + (size_t)width > ctx.blob + ctx.blobSize) return false;
            uint64_t v = 0;
            for (int i = width - 1; i >= 0; --i) v = (v << 8) | p[i];
            if (out) *out = v;
            return true;
        }
        if (k < globalFieldIdx) lo = mid + 1; else hi = mid;
    }
    return false;
}

// 字段偏移交叉验证统计(偏移表 vs CLI 布局推算); OffStat 定义在 dumper.h
static OffStat g_stat;

// ---------------------------------------------------------------- 主解码 ----
bool DecodeAllTypes(GameCtx& ctx, TypeSink sink, void* user) {
    g_k = KindMap();
    g_stat = OffStat();
    Progress("[1/6] 建 kind 缓存 (%u 类型) ...", ctx.typeCount);
    BuildKindMap(ctx);
    uint32_t limit = ctx.typeCount;
    Progress("[1/6] kind 缓存完成");
    // 只保留当前类型, 不累积(见 dumper.h 的说明)
    TypeInfo t;

    uint64_t tick = NowMs();
    for (uint32_t i = 0; i < limit; ++i) {
        t = TypeInfo();                 // 释放上一类型的 vector/string
        if ((i & 0x3FF) == 0) {
            uint64_t el = NowMs() - tick;
            Progress("      解码 %u/%u  %.1f%%  %lums", i, limit,
                     100.0 * i / (limit ? limit : 1), (unsigned long)el);
            if (el > 600000) { ctx.err = "decode stalled at type " + dec(i); return false; }
        }
        SetStage("decode.type", i, 0);
        const uint8_t* r = ctx.typedefTab + 70ull * i;
        if (!inBlob(ctx, r, 70)) { ctx.err = "typedef record out of range at " + dec(i); return false; }
        t.tdIdx  = i;
        t.ns     = DecodeStringLossless(ctx, rd32(r) - 1145778368u);
        t.name   = DecodeStringLossless(ctx, rd32(r + 36) - 72511848u);
        uint32_t methodStart = (rd32(r + 12) ^ 0x4D8127F2u) & 0xFFFFFFFFu;
        uint32_t fieldStart  = (rd32(r + 28) ^ 0x29010897u) & 0xFFFFFFFFu;
        uint32_t propStart   = (rd32(r + 8)  - 1995389561u) & 0xFFFFFFFFu;
        uint32_t eventStart  = (uint32_t)((int32_t)(int16_t)(rd16(r + 52) + 3330)) & 0xFFFFFFFFu;
        uint16_t methodCount = (uint16_t)(rd16(r + 48) + 4806u);
        uint16_t fieldCount  = (uint16_t)(rd16(r + 56) ^ 0x51A8u);
        uint8_t  propCount   = (uint8_t)(rd8(r + 67) ^ 0x16u);
        uint8_t  ifaceCount  = (uint8_t)(rd8(r + 69) ^ 0xBAu);
        uint8_t  eventCount  = (uint8_t)(rd8(r + 68) + 113u);

        SetStage("decode.isValueType", i, 0);
        t.isValueType = IsValueType(ctx, i);
        SetStage("decode.parent", i, 0);
        t.parent = TypeParentName(ctx, i);
        SetStage("decode.asmLookup", i, 0);
        // asmIdx 供 emitCs 输出 Il2CppDumper 的 "// Image N: dll - start:count";
        // dll 名直接取 AsmRec.dllName, 不再往 TypeInfo 里存一份副本。
        for (const AsmRec& a : ctx.asms)
            if (i >= a.typeStart && i < a.typeStart + a.typeCount) {
                t.asmIdx = a.index;
                if (a.imageIndex < ctx.imgs.size()) t.image = ctx.imgs[a.imageIndex].name;
                break;
            }
        if (t.image.empty()) t.image = "?";

        // ---- 字段 + 偏移推算 ----
        bool vt = t.isValueType;
        if (vt) { t.instanceSize = TypeSizeAlign(ctx, i); t.align = 8; }
        else    { t.instanceSize = 0; }
        uint32_t off = vt ? 0u : 0x10u;      // 引用类型前面是 Il2CppObject 头
        t.fields.reserve(fieldCount);
        for (uint32_t q = 0; q < fieldCount; ++q) {
            SetStage("decode.field", i, fieldStart + q);
            const uint8_t* rec = ctx.fieldTab + 8ull * (fieldStart + q);
            if (!inBlob(ctx, rec, 8)) break;
            uint32_t k = field_key(fieldStart + q);
            FieldRaw f;
            f.name      = DecodeStringLossless(ctx, (((rd32(rec + 4) - 1475293452u) & 0xFFFFFFFFu) ^ k) ^ 0x2D027B84u);
            f.typeRec   = (k ^ rd32(rec) ^ 0x2D27D873u) & 0xFFFFFFFFu;
            f.type      = TypeNameOfRecord(ctx, f.typeRec, 0);
            const uint8_t* tr = TypeRecord(ctx, f.typeRec);
            f.isConst   = tr && (rd16(tr + 8) & 0x8000);
            // 自引用判据**只对值类型生效**: 值类型不可能含自身类型的实例字段, 所以
            // struct 里"字段类型解析回本类型"必然是 static(Vector2.upVector 就是)。
            // 类不能这么判(StringBuilder.m_ChunkPrevious 就是同类型实例字段)。
            // ⚠️ 条件方向别搞反: 早期写成 !vt, 导致 Vector3 的 9 个 static 字段全被
            //    分配实例偏移 0/12/24..108, 把 x/y/z 挤到 120/124/128。
            bool selfRef = false;
            if (tr && vt) {
                uint8_t te = rd8(tr + 10);
                if ((te == TE_CLASS || te == TE_VALUETYPE || te == TE_ENUM) && rd64(tr) == i)
                    selfRef = true;
                else if (te == TE_SZARRAY || te == TE_PTR || te == TE_BYREF || te == TE_ARRAY) {
                    const uint8_t* e = recAtVa(ctx, rd64(tr));
                    if (e) {
                        uint8_t e2 = rd8(e + 10);
                        if ((e2 == TE_CLASS || e2 == TE_VALUETYPE || e2 == TE_ENUM) && rd64(e) == i)
                            selfRef = true;
                    }
                }
            }
            // 真实偏移 (sub_140512870 的 4B 字段偏移表) 优先; 拿不到才退回 CLI 布局推算,
            // 并记录两者是否一致 —— 这是对"布局推算"和"偏移表"两条独立路径的交叉验证。
            FieldSlot fs = FieldSlotOf(ctx, i, q);
            f.hasDefault = fs.hasDefault;
            f.defSlot    = fs.defSlot;
            // 偏移表自带 static 判据(`0 < e < 0x1000000` 即实例字段), 实测 99.92% 自洽,
            // **完全取代**下面那个"自引用即 static"的启发式。启发式只在偏移表缺席时兜底 ——
            // 两者混用会把偏移表明明标成实例的字段误判成 static(实测多标 6 个)。
            if (fs.valid) {
                f.isStatic = !fs.hasOffset;
            } else {
                f.isStatic = f.isConst || (vt && selfRef);
            }
            if (fs.valid && fs.hasOffset) {
                f.offset = (int)fs.offset;
                f.offsetKnown = true;
                f.offsetFromTable = true;
                uint32_t al = 1;
                uint32_t sz = TypeSize(ctx, f.typeRec, &al);
                if (al > 8) al = 8;
                if (al < 1) al = 1;
                if (al & (al - 1)) al = 8;
                off = (off + al - 1) & ~(al - 1);
                if ((uint32_t)f.offset == off) g_stat.offAgree++;
                else g_stat.offDisagree++;
                off += sz;
            } else if (f.isStatic) {
                f.offset = -1;                   // static/const 无实例偏移
                f.offsetKnown = true;            // "确实没有实例偏移"也是已知状态
                g_stat.offNoTable++;
            } else {
                uint32_t al = 1;
                uint32_t sz = TypeSize(ctx, f.typeRec, &al);
                if (al > 8) al = 8;
                if (al < 1) al = 1;
                if (al & (al - 1)) al = 8;
                off = (off + al - 1) & ~(al - 1);
                f.offset = (int)off;
                f.offsetKnown = true;
                g_stat.offNoTable++;
                off += sz;
            }
            if (f.hasDefault) g_stat.fieldsWithDefault++;
            t.fields.push_back(FieldInfo{ f });
        }

        // ---- 枚举成员常量值 (sub_14051A510) ----
        // 枚举的判据是"有一个名为 value__ 的实例字段"(全库 8,123 个)。别用 16B 记录的
        // type==0x55 去判 —— 那 693 条绝大多数是误命中(ValueTuple / SafeFileHandle 等)。
        // 底层类型 = value__ 字段的类型, 决定常量值的字节宽度。
        {
            int32_t vtIdx = -1;
            for (uint32_t q = 0; q < t.fields.size(); ++q)
                if (t.fields[q].f.name == "value__") { vtIdx = (int32_t)q; break; }
            if (vtIdx >= 0) {
                t.isEnum = true;
                t.underlying = t.fields[vtIdx].f.type;
            }
            if (vtIdx >= 0 && ctx.features[FEAT_ENUM_VALUES]) {
                uint32_t width = PrimWidthOfRecord(ctx, t.fields[vtIdx].f.typeRec);
                if (width) {
                    t.isEnum = true;
                    t.underlying = t.fields[vtIdx].f.type;
                    g_stat.enumTypes++;
                    for (uint32_t q = 0; q < t.fields.size(); ++q) {
                        if ((int32_t)q == vtIdx) continue;
                        uint64_t v = 0;
                        if (!FieldConstValue(ctx, fieldStart + q, (int)width, &v)) continue;
                        FieldRaw e;
                        e.name       = t.fields[q].f.name;
                        e.value      = v;
                        e.valueSize  = width;
                        t.enumVals.push_back(e);
                        g_stat.enumMembers++;
                    }
                }
            }
        }

        // ---- 属性 ----
        if (propCount) {
            // 少数类型的 propStart 落在错位处(整段记录读歪), 就近纠正 —— 与 v3 同款。
            // 纠偏判据(PropRecordOk)必须和 v3 的 _ident 严格一致, 否则候选点不同。
            uint32_t start = propStart;
            if (!PropRecordOk(ctx, start))
                for (int sh = -16; sh <= 16; ++sh)
                    if (sh && PropRecordOk(ctx, (start + sh) & 0xFFFFFFFFu)) {
                        start = (start + sh) & 0xFFFFFFFFu;
                        break;
                    }
            t.props.reserve(propCount);
            for (uint32_t q = 0; q < propCount; ++q) {
                PropRaw p = PropDecode(ctx, (start + q) & 0xFFFFFFFFu);
                if (p.getter != 0xFFFFu) {
                    p.getterSlot = MethodSlot(ctx, methodStart + p.getter);
                    p.getter     = methodStart + p.getter;
                } else p.getter = 0xFFFFFFFFu;
                if (p.setter != 0xFFFFu) {
                    p.setterSlot = MethodSlot(ctx, methodStart + p.setter);
                    p.setter     = methodStart + p.setter;
                } else p.setter = 0xFFFFFFFFu;
                t.props.push_back(p);
            }
        }

        // ---- 事件 ----
        t.evs.reserve(eventCount);
        for (uint32_t q = 0; q < eventCount; ++q) {
            EvRaw e = EvDecode(ctx, (eventStart + q) & 0xFFFFFFFFu);
            e.add    = (e.add    == 0xFFFFu) ? 0xFFFFFFFFu : (e.add    + methodStart);
            e.remove = (e.remove == 0xFFFFu) ? 0xFFFFFFFFu : (e.remove + methodStart);
            e.raise  = (e.raise  == 0xFFFFu) ? 0xFFFFFFFFu : (e.raise  + methodStart);
            t.evs.push_back(e);
        }

        // ---- 接口 ----
        t.ifaces.reserve(ifaceCount);
        for (uint32_t q = 0; q < ifaceCount; ++q) {
            uint32_t ti = IfaceTypeIndex(ctx, i, q);
            IfaceRaw ir;
            ir.idx  = ti;
            ir.name = (ti == 0xFFFFFFFFu) ? "?" : TypeNameOfRecord(ctx, ti, 0);
            ir.slot = IfaceSlot(ctx, i, q);
            t.ifaces.push_back(ir);
        }

        SetStage("decode.evs", i, 0);
        for (EvRaw& e : t.evs) (void)e;
        // ---- 方法 ----
        t.methods.reserve(methodCount);
        for (uint32_t q = 0; q < methodCount; ++q) {
            uint32_t mi = methodStart + q;
            SetStage("decode.method", i, mi);
            MethodInfo m;
            m.name   = MemberName(ctx, mi);
            // 方法代码地址(给 IDA 恢复符号); 表在 exe 映像里, 越界即 0
            if (ctx.methodCodeTab && (uint64_t)mi * 8 + 8 <= 0x800000ull) {
                uint64_t a = rd64(ctx.methodCodeTab + 8ull * mi);
                // 只接受落在映像内的值, 避免把垃圾当成地址
                if (ctx.vaBias && a >= ctx.vaBias && a - ctx.vaBias < ctx.imageSize)
                    m.rva = a - ctx.vaBias;
            }
            m.flags  = MethodFlags(ctx, mi);
            m.ret    = TypeNameOfRecord(ctx, MethodRetOf(ctx, mi), 0);
            uint32_t pc = MethodParamCount(ctx, mi);
            uint32_t ps = MethodParamStart(ctx, mi);
            m.params.reserve(pc);
            for (uint32_t j = 0; j < pc; ++j) {
                SetStage("decode.param", i, ps + j);
                m.params.push_back(ParamDecode(ctx, ps + j));
            }
            t.methods.push_back(std::move(m));
        }

        // ---- 属性类型 = getter 的返回类型; 只有 setter 时退回 setter 的 ----
        // (setter 也返回 void, 所以 set-only 属性的类型是 void 而不是 "?")
        SetStage("decode.props", i, 0);
        for (PropRaw& p : t.props) {
            uint32_t src = (p.getter != 0xFFFFFFFFu) ? p.getter : p.setter;
            if (src != 0xFFFFFFFFu && src < ctx.methodCountTotal)
                p.type = TypeNameOfRecord(ctx, MethodRetOf(ctx, src), 0);
        }

        // ---- 交给 sink(写盘/统计), 之后 t 立即释放 ----
        SetStage("decode.sink", i, 0);
        if (sink) sink(user, t, i);
    }

    g_stat.enumConstTable = EnumValCount(ctx);
    return true;
}

const OffStat& FieldOffsetStats() { return g_stat; }

} // namespace gs
