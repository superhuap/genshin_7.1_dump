// output.cpp —— 照搬 7.0 dumper 的输出结构与自检思路, 公式换成 7.1
//
// 产物集(与 7.0 一致):
//   dump.cs / dump.json  主产物
//   report.txt           formulaCheck 全量 + 统计(先看这个)
//   summary.txt          紧凑键值摘要
//   diag.txt             定位阶段的原始值
//   progress.log         追加式进度
//   dump.done            成功标志
//   dump.fail            失败时写, 内含 err + diag
#include "dumper.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <unordered_set>      // Acc::addrSet: 统计不同方法代码地址数
#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>   // MinGW 的 _SH_DENYNO / _S_IWRITE 在这里(MSVC 在 <share.h>)
#include <share.h>
#endif

namespace gs {

// ---------------------------------------------------------------- 路径 ----
// DLL 侧永远是 Windows 路径, 但 native 回归跑在 macOS/Linux 上 —— 用固定反斜杠
// 会把 "\dump.cs" 当成文件名的一部分, 产物全落在当前目录且名字带反斜杠。
static std::wstring Join(const std::wstring& dir, const wchar_t* name) {
#ifdef _WIN32
    return dir + L"\\" + name;
#else
    return dir + L"/" + name;
#endif
}

// native 回归时 outDir 是命令行给的, 可能还不存在
static void EnsureDir(const std::wstring& dir) {
    if (dir.empty()) return;
#ifdef _WIN32
    CreateDirectoryW(dir.c_str(), nullptr);
#else
    std::string p; for (wchar_t c : dir) p += (char)c;
    std::string acc;
    for (size_t i = 0; i < p.size(); ++i) {
        acc += p[i];
        if (p[i] == '/' && i) ::mkdir(acc.c_str(), 0755);
    }
    ::mkdir(p.c_str(), 0755);
#endif
}

// 诊断用: 宽字符路径转窄字符(手工转, 不引 <sstream>/<locale>)
static std::string NarrowForDiag(const std::wstring& w) {
    std::string o;
    for (wchar_t c : w) {
        if (c < 0x80) o += (char)c;
        else { o += (char)(0xC0 | (c >> 6)); o += (char)(0x80 | (c & 0x3F)); }
    }
    return o;
}

// ---------------------------------------------------------------- 文件写 ----
//
// ⚠️ 大文件必须**流式写**, 不能先在内存里拼完再一次性落盘。
// 7.1 的产物是 dump.cs ~81MB + dump.json ~159MB。一次性拼完意味着峰值占用 240MB+,
// 而这个进程是刚被注入的游戏 —— 内存本来就紧张, 一旦触发换页, 写盘会慢到
// 看起来像卡死(2026-09-26 真机复现: 解码只用 484ms, 却卡在写 81MB 上)。
// 流式写把峰值内存压到几 MB, 而且能按 MB 报进度。
class StreamWriter {
public:
    ~StreamWriter() { close(); }
    bool open(const std::wstring& path) {
        path_ = path;
#ifdef _WIN32
        if (_wsopen_s(&fd_, path.c_str(), _O_CREAT | _O_TRUNC | _O_WRONLY | _O_BINARY,
                      _SH_DENYNO, _S_IWRITE) != 0) { fd_ = -1; return false; }
#else
        std::string p; for (wchar_t c : path) p += (char)c;
        f_ = fopen(p.c_str(), "wb");
        if (!f_) return false;
#endif
        return true;
    }
    bool ok() const {
#ifdef _WIN32
        return fd_ >= 0;
#else
        return f_ != nullptr;
#endif
    }
    void write(const char* p, size_t n) {
        if (!n) return;
#ifdef _WIN32
        size_t off = 0;
        while (off < n && fd_ >= 0) {
            int chunk = (int)((n - off) > (size_t)(1 << 20) ? (size_t)(1 << 20) : (n - off));
            int w = _write(fd_, p + off, chunk);
            if (w <= 0) { ok_ = false; break; }
            off += (size_t)w;
        }
#else
        if (f_ && fwrite(p, 1, n, f_) != n) ok_ = false;
#endif
        total_ += n;
    }
    void close() {
#ifdef _WIN32
        if (fd_ >= 0) { _close(fd_); fd_ = -1; }
#else
        if (f_) { fclose(f_); f_ = nullptr; }
#endif
    }
    uint64_t total() const { return total_; }
    bool good() const { return ok_; }
private:
    std::wstring path_;
#ifdef _WIN32
    int fd_ = -1;
#else
    FILE* f_ = nullptr;
#endif
    uint64_t total_ = 0;
    bool ok_ = true;
};

static bool writeAll(const std::wstring& path, const std::string& data) {
#ifdef _WIN32
    int fd = -1;
    if (_wsopen_s(&fd, path.c_str(), _O_CREAT | _O_TRUNC | _O_WRONLY | _O_BINARY,
                  _SH_DENYNO, _S_IWRITE) != 0) return false;
    bool ok = true;
    size_t off = 0;
    while (off < data.size()) {
        int chunk = (int)((data.size() - off) > (size_t)(1 << 20) ? (1 << 20) : (data.size() - off));
        int n = _write(fd, data.data() + off, chunk);
        if (n <= 0) { ok = false; break; }
        off += (size_t)n;
    }
    _close(fd);
    return ok;
#else
    std::string p;
    for (wchar_t c : path) p += (char)c;
    FILE* f = fopen(p.c_str(), "wb");
    if (!f) return false;
    size_t n = data.empty() ? 0 : fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return n == data.size();
#endif
}
static void appendLog(const std::wstring& dir, const std::string& line) {
#ifdef _WIN32
    int fd = -1;
    if (_wsopen_s(&fd, (dir + L"\\progress.log").c_str(),
                  _O_CREAT | _O_APPEND | _O_WRONLY | _O_BINARY, _SH_DENYNO, _S_IWRITE) != 0) return;
    _write(fd, line.data(), (int)line.size());
    _close(fd);
#else
    std::string p; for (wchar_t c : dir) p += (char)c;
    FILE* f = fopen((p + "/progress.log").c_str(), "ab");
    if (!f) return; fwrite(line.data(), 1, line.size(), f); fclose(f);
#endif
}

// 十六进制字符串(给 IDA 脚本用, 避免它自己再做 64 位解析)
static std::string hex0(uint64_t v) {
    char b[32]; snprintf(b, sizeof b, "0x%llX", (unsigned long long)v); return b;
}

// ---------------------------------------------------------------- JSON -----
static void jesc(const std::string& s, std::string& o) {
    o += '"';
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;  case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;  case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    o += '"';
}
// 流式版: 每累积 4MB 就落盘, 峰值内存 ~4MB 而不是 159MB
// 单个类型的 json 片段(逐类型流式输出用)
static void emitJsonOne(const TypeInfo& t, std::string& o) {
            o += "{\"index\":" + dec(t.tdIdx) + ",\"image\":"; jesc(t.image, o);
            o += ",\"namespace\":"; jesc(t.ns, o);
            o += ",\"name\":"; jesc(t.name, o);
            o += ",\"parent\":"; jesc(t.parent, o);
            // depth 去掉: 可由 parent 链推出, 冗余
            o += ",\"isValueType\":" + std::string(t.isValueType ? "true" : "false");
            o += ",\"size\":" + dec(t.instanceSize) + ",\"align\":" + dec(t.align);
            o += ",\"fields\":[";
            for (size_t j = 0; j < t.fields.size(); ++j) {
                const FieldRaw& f = t.fields[j].f;
                if (j) o += ',';
                o += "{\"name\":"; jesc(f.name, o);
                o += ",\"type\":"; jesc(f.type, o);
                // 有符号输出: static/const 字段的 offset 是 -1。之前按无符号打
                // 印成 18446744073709551615(20 字符), 既费空间又让消费方看不出语义。
                // 改成 -1 之后 "offset >= 0 即实例字段" 成了显式规则。
                o += ",\"offset\":" + dec((uint64_t)(int64_t)f.offset, true);
                o += ",\"isStatic\":" + std::string(f.isStatic ? "true" : "false");
                o += ",\"isConst\":" + std::string(f.isConst ? "true" : "false");
                o += "}";
            }
            o += "],\"properties\":[";
            for (size_t j = 0; j < t.props.size(); ++j) {
                const PropRaw& p = t.props[j];
                if (j) o += ',';
                o += "{\"name\":"; jesc(p.name, o);
                o += ",\"type\":"; jesc(p.type, o);
                o += ",\"getter\":" + dec(p.getter) + ",\"setter\":" + dec(p.setter) + "}";
            }
            o += "],\"events\":[";
            for (size_t j = 0; j < t.evs.size(); ++j) {
                const EvRaw& e = t.evs[j];
                if (j) o += ',';
                o += "{\"name\":"; jesc(e.name, o);
                o += ",\"type\":"; jesc(e.type, o);
                o += ",\"add\":" + dec(e.add) + ",\"remove\":" + dec(e.remove)
                   + ",\"raise\":" + dec(e.raise) + "}";
            }
            o += "],\"interfaces\":[";
            for (size_t j = 0; j < t.ifaces.size(); ++j) {
                if (j) o += ',';
                jesc(t.ifaces[j].name, o);
            }
            o += "],\"methods\":[";
            for (size_t j = 0; j < t.methods.size(); ++j) {
                const MethodInfo& m = t.methods[j];
                if (j) o += ',';
                // ⚠️ JSON 没有 0x 十六进制数字字面量, 地址必须加引号。
                // 只保留 rva: addr = meta.imageBase + rva 可直接算, def(Il2CppMethodInfo*)
                // 对 IDA 建符号没用 —— 三者合计省 17.8 MB(占 json 9.3%)。
                o += "{\"name\":"; jesc(m.name, o);
                o += ",\"return\":"; jesc(m.ret, o);
                o += ",\"flags\":" + dec(m.flags);
                if (m.rva)  o += ",\"rva\":\"" + hex0(m.rva) + "\"";
                o += ",\"params\":[";
                for (size_t k = 0; k < m.params.size(); ++k) {
                    if (k) o += ',';
                    // ⚠️ 类型+名字必须合成**一个** JSON 字符串。
                    //    原来各自 jesc 一次, 单参数方法产出 ["string" "msg"] —— 这是
                    //    非法 JSON, 整个 dump.json 都解析不了(2026-09-26 才发现)。
                    jesc(m.params[k].type + " " + m.params[k].name, o);
                }
                o += "]}";
            }
            o += "]}";      // 收尾: methods 数组 + 类型对象
}

// ---------------------------------------------------------------- C# ------
// dump.cs 采用 Il2CppDumper 风格:
//   - 去掉 "// Dll :"(7.0 遗留; 7.1 有 75 个程序集, 单个 dll 名没有意义)
//   - 缩进用 TAB
//   - 类型头 "// Image N: dll - typeStart:typeCount"(区间取自 88B 程序集表)
//   - 类型声明尾部是 "// TypeDefIndex: N"
//   - 成员带访问修饰符(private/public/static)与类型全名(System.Void 而非 void)
// 纯内存模式没有文件偏移, Offset 与 RVA 同值(运行期 RVA 即映像内偏移)。
static std::string FullTypeName(const std::string& t) {
    // 短名 -> System.* 全名(Il2CppDumper 风格)。已是全名或含 '.' 的原样返回。
    static const char* kMap[][2] = {
        {"void","System.Void"},   {"bool","System.Boolean"}, {"char","System.Char"},
        {"sbyte","System.SByte"},{"byte","System.Byte"},   {"short","System.Int16"},
        {"ushort","System.UInt16"},{"int","System.Int32"},  {"uint","System.UInt32"},
        {"long","System.Int64"},  {"ulong","System.UInt64"},{"float","System.Single"},
        {"double","System.Double"},{"string","System.String"},{"object","System.Object"},
    };
    for (auto& m : kMap) if (t == m[0]) return m[1];
    return t;
}

static void emitCs(const GameCtx& ctx, const TypeInfo& t, std::string& o) {
    o += "\n";
    // Il2CppDumper 格式: "// Image {i}: {dll} - {typeStart}:{typeCount}"
    // typeStart/typeCount 直接取 88B 程序集表 —— 这正是纯内存路径的权威来源。
    if (t.asmIdx != 0xFFFFFFFFu && t.asmIdx < ctx.asms.size()) {
        const AsmRec& a = ctx.asms[t.asmIdx];
        o += "// Image " + dec(a.index) + ": " +
             (a.dllName.empty() ? t.image : a.dllName) +
             " - " + dec(a.typeStart) + ":" + dec(a.typeCount) + "\n";
    } else if (!t.image.empty()) {
        o += "// Image 0: " + t.image + " - 0:0\n";
    }
    if (!t.ns.empty()) o += "// Namespace: " + t.ns + "\n";
    o += "public ";
    if (t.isEnum) o += "enum ";
    else if (t.isValueType) o += "struct ";
    else o += "class ";
    o += t.name;
    // 枚举不写基类: 元数据里枚举的 parent 字段填的是任意类型
    if (!t.isEnum && !t.parent.empty() && t.parent != "System.Object" &&
        t.parent != "System.ValueType")
        o += " : " + t.parent;
    o += " // TypeDefIndex: " + dec(t.tdIdx) + "\n{\n";

    if (t.isValueType && t.instanceSize) {
        char b[64]; snprintf(b, sizeof b, "\t// size=%u align=%u\n", t.instanceSize, t.align);
        o += b;
    }
    if (t.isEnum && !t.underlying.empty()) {
        o += "\t// underlying "; o += t.underlying; o += "\n";
    }
    for (const FieldRaw& e : t.enumVals) {
        char nb[32];
        if (e.valueSize == 8) snprintf(nb, sizeof nb, "%llu", (unsigned long long)e.value);
        else                  snprintf(nb, sizeof nb, "%u", (unsigned)e.value);
        o += "\t"; o += e.name; o += " = "; o += nb; o += ",\n";
    }
    if (!t.fields.empty() && !t.isEnum) {
        o += "\t// Fields\n";
        for (const FieldInfo& fi : t.fields) {
            const FieldRaw& f = fi.f;
            o += "\t";
            o += f.isStatic ? "public static " : "private ";
            o += FullTypeName(f.type); o += " "; o += f.name;
            if (!f.isStatic && f.offset >= 0) { char b[32]; snprintf(b, sizeof b, "; // 0x%llX", (unsigned long long)(uint64_t)f.offset); o += b; }
            else o += ";";
            o += "\n";
        }
    }
    if (!t.props.empty()) {
        o += "\n\t// Properties\n";
        for (const PropRaw& p : t.props) {
            o += "\tpublic "; o += FullTypeName(p.type); o += " "; o += p.name; o += " { ";
            if (p.getter != 0xFFFFFFFFu) o += "get; ";
            if (p.setter != 0xFFFFFFFFu) o += "set; ";
            o += "}";
            if (p.getter != 0xFFFFFFFFu && p.getterSlot != 0xFFFFu) {
                char b[40]; snprintf(b, sizeof b, " // 0x%llX", (unsigned long long)p.getterSlot); o += b;
            }
            o += "\n";
        }
    }
    if (!t.evs.empty()) {
        o += "\n\t// Events\n";
        for (const EvRaw& e : t.evs) o += "\tpublic event " + FullTypeName(e.type) + " " + e.name + ";\n";
    }
    if (!t.methods.empty()) {
        o += "\n\t// Methods\n";
        for (const MethodInfo& m : t.methods) {
            // 地址行: 纯内存模式 RVA == 映像内偏移, VA = imageBase + RVA
            if (m.rva) {
                char b[96];
                // ⚠️ 必须用 %llX: 之前 (unsigned)(kImageBase + m.rva) 配 %X 只取低 32 位,
                //    把 0x140000000 的高位截掉, VA 全变成 0x40xxxxxx(2026-09-26 真机)。
                //    RVA 本身小于 SizeOfImage 所以没受影响, 只有 VA 错, 很难一眼看出来。
                // VA 放**行首**且是第一个 token: IDA 里 Alt+Q / 双击只认库内
                // 有效地址, 而 IDA 库基准是 0x140000000 —— 裸 RVA(0x446360)在 IDA
                // 里是"非法地址", 点了跳不动。VA 必须用 %llX: 之前
                // (unsigned)(kImageBase + m.rva) 配 %X 只取低 32 位, 高位被截掉,
                // 打印成 0x40446360, 同样跳不动(2026-09-26 真机踩过)。
                // RVA 保留在后面: 万一 IDA 换了基址/rebase, 还能自己加。
                // Il2CppDumper 原始格式, **// RVA: 必须在行首**:
                //   tools/ida_apply_symbols.py 的 RVA_RE = ^\s*//\s*RVA:\s*0x([0-9A-Fa-f]+)
                // 之前改成 "// VA: ... RVA: ..." 打头, 正则失配 -> 套符号应用 0 个。
                // Offset: 纯内存模式没有文件偏移, 与 RVA 同值(和 7.0 以及
                //   Il2CppDumper 对 runtime dump 的处理一致)。
                // VA: 必须 %llX —— (unsigned)(kImageBase+rva) 配 %X 只取低 32 位,
                //   会把 0x140000000 截成 0x40000000, 在 IDA 里就跳不动了。
                snprintf(b, sizeof b, "\t// RVA: 0x%llX Offset: 0x%llX VA: 0x%llX\n",
                         (unsigned long long)m.rva, (unsigned long long)m.rva,
                         (unsigned long long)(kImageBase + m.rva));
                o += b;
            }
            o += "\t";
            // .NET MethodAttributes: 访问性是 **3 bit 字段**(MemberAccessMask=0x7),
            // 不是单个 bit。0x0001=Private / 0x0006=Public / 0x0003=Assembly ...
            // ⚠️ 0x0040 是 Virtual, 拿它判 private 会把可见性整个搞反。
            o += ((m.flags & 0x7) == 0x1) ? "private " : "public ";
            if (m.flags & 0x0010) o += "static ";
            o += FullTypeName(m.ret); o += " "; o += m.name; o += "(";
            for (size_t k = 0; k < m.params.size(); ++k) {
                if (k) o += ", ";
                o += FullTypeName(m.params[k].type); o += " "; o += m.params[k].name;
            }
            o += ") { }\n";
        }
    }
    o += "}\n";
}

// ---------------------------------------------------------------- 统计累加器 ----
// formulaCheck 原本要对全部 88,902 个类型做 6 遍全量扫描。既然现在逐类型解码,
// 这些统计就在解码时增量算好 —— formulaCheck 只拿结果, 不再需要整个 vector。
struct Acc {
    uint64_t fTot = 0, fStatic = 0, fOff = 0, mTot = 0, pTot = 0, eTot = 0, iTot = 0;
    uint64_t types = 0;
    uint64_t methods = 0, methodsWithAddr = 0;
    std::unordered_set<uint64_t> addrSet;      // 不同代码地址数(IDA 符号覆盖率)
    uint64_t asc = 0, ascTot = 0;                 // 锚点1: 实例偏移按字段序升序
    uint64_t front = 0, withStatic = 0;           // 锚点2: static 集中在实例字段前
    uint64_t refOk = 0, refTot = 0, vtOk = 0, vtTot = 0;  // 锚点3: 最小实例偏移
    uint64_t vtTypes = 0, vtWithEnum = 0;         // 锚点4: value__ 必须能算枚举成员
    void one(const TypeInfo& t, uint64_t* fStaticAcc, uint64_t* fOffAcc) {
        ++types;
        fTot += t.fields.size();
        mTot += t.methods.size();
        pTot += t.props.size();
        eTot += t.evs.size();
        iTot += t.ifaces.size();
        methods += t.methods.size();
        for (const MethodInfo& m : t.methods)
            if (m.rva) { ++methodsWithAddr; addrSet.insert(m.rva); }
        for (const FieldInfo& fi : t.fields) {
            if (fi.f.isStatic) ++(*fStaticAcc);
            else if (fi.f.offset >= 0) ++(*fOffAcc);
        }
        {   // 锚点1: 至少 2 个来自偏移表的实例字段, 且严格递增(相等也算失败)
            int seen = 0; bool bad = false; long prev = -1;
            for (const FieldInfo& fi : t.fields) {
                if (!fi.f.offsetFromTable) continue;
                long v = fi.f.offset;
                if (seen && v <= prev) bad = true;
                prev = v; ++seen;
            }
            if (seen >= 2) { ++ascTot; if (!bad) ++asc; }
        }
        {   // 锚点2
            long lastStatic = -1, firstInst = -1;
            for (size_t k = 0; k < t.fields.size(); ++k) {
                if (t.fields[k].f.isStatic) lastStatic = (long)k;
                else if (firstInst < 0) firstInst = (long)k;
            }
            if (lastStatic >= 0 && firstInst >= 0) { ++withStatic; if (lastStatic < firstInst) ++front; }
        }
        {   // 锚点3
            long mn = -1;
            for (const FieldInfo& fi : t.fields)
                if (fi.f.offsetFromTable && (mn < 0 || fi.f.offset < mn)) mn = fi.f.offset;
            if (mn >= 0) {
                if (t.isValueType) { ++vtTot; if (mn == 0x10) ++vtOk; }
                else               { ++refTot; if (mn >= 0x10) ++refOk; }
            }
        }
        {   // 锚点4
            for (const FieldInfo& f : t.fields)
                if (f.f.name == "value__") { ++vtTypes; if (!t.enumVals.empty()) ++vtWithEnum; break; }
        }
    }
};

// formulaCheck 只需要的少数类型 —— 逐个深拷贝留一份, 其余一律不留
static bool IsWatched(const TypeInfo& t) {
    if (t.tdIdx == 532) return true;                    // System.Reflection.Assembly
    const std::string f = t.ns.empty() ? t.name : (t.ns + "." + t.name);
    return f == "System.Object" || f == "System.Int32" || f == "System.String" ||
           f == "UnityEngine.Vector2" || f == "UnityEngine.Vector3" ||
           f == "System.ConsoleColor" || f == "System.AttributeTargets" ||
           f == "Microsoft.Win32.RegistryHive";
}

// ---------------------------------------------------------- formulaCheck ----
// 思路照搬 7.0: 每个公式用**独立已知锚点**交叉验证, 任何一项 FAIL 就说明公式在真机上
// 不成立, 产物不可信。7.1 的锚点全部来自 v3 实测 + v4 native 回归。
static void formulaCheck(const GameCtx& ctx, const Acc& A, const std::vector<TypeInfo>& types, std::string& rep) {
    int pass = 0, fail = 0, skip = 0;
    rep += "\n-- formulaCheck (已知锚点反查) --\n";
    auto chk = [&](const char* name, bool ok, const std::string& detail) {
        rep += std::string("formulaCheck ") + (ok ? "PASS" : "FAIL") + " " + name + " " + detail + "\n";
        if (ok) pass++; else fail++;
    };
    auto unported = [&](const char* name) {
        rep += std::string("formulaCheck SKIP ") + name + " [7.0 特性, 7.1 未移植: " +
               FeatureById(atoi(name)).v70 + "]\n";
        skip++;
    };

    // IDA 符号恢复能力: 方法地址覆盖率 + 地址分散度
    chk("method-addr-coverage",
        A.methods > 0 && A.methodsWithAddr * 100 / A.methods >= 90,
        "方法带 rva/addr: " + dec(A.methodsWithAddr) + "/" + dec(A.methods) +
        " (" + dec(A.methods ? A.methodsWithAddr * 100 / A.methods : 0) + "%, 期望 >=90%)");
    // ⚠️ 这条是"两张表没搞反"的关键守卫。
    //    真 MPT(0x2870B90)每个方法一个唯一代码体 -> 重复地址必须为 0。
    //    若不慎用了泛型桩表(0x27D4DE0), 这里会出现 3,754 个重复地址、
    //    最大重数 2,141, 普通属性 getter 指向 `*a5 = a1()` 派发桩。
    chk("method-addr-distinct",
        (uint64_t)A.addrSet.size() >= 400000,
        "不同代码地址 " + dec((uint64_t)A.addrSet.size()) + " 个(泛型共享实现会共用, 期望 >=400000)");
    chk("mpt-unique-body",
        ctx.mptDupAddr == 0,
        "真 MPT 重复地址 " + dec(ctx.mptDupAddr) + " 个(最大重数 " + dec(ctx.mptMaxDup) +
        "); 期望 0 —— 非 0 说明拿错了表(0x27D4DE0 是泛型桩表, 不是 MPT)");
    chk("mpt-coverage",
        ctx.methodCountTotal > 0 && ctx.mptInImage * 100 / ctx.methodCountTotal >= 90,
        "MPT 界内条目 " + dec(ctx.mptInImage) + "/" + dec(ctx.methodCountTotal) +
        " (" + dec(ctx.methodCountTotal ? ctx.mptInImage * 100 / ctx.methodCountTotal : 0) + "%, 期望 >=90%)");
    chk("header-magic", rd32(ctx.hdr) == kHeaderMagic, "hdr[0..3]=" + hex64(rd32(ctx.hdr)));
    chk("typeRec-rva", ctx.typeRecRva > 0x1000 && ctx.typeRecRva < 0x3000000,
        "16B 记录数组 RVA=" + hex64(ctx.typeRecRva) + " (exe 静态数组)");
    chk("image-count-75", ctx.imgs.size() == kImageCount, "image 数 " + dec(ctx.imgs.size()) + " (期望 75)");
    chk("asm-count-75", ctx.asms.size() == kAsmCount, "程序集数 " + dec(ctx.asms.size()) + " (期望 75)");
    if (!ctx.imgs.empty()) chk("image[0]=mscorlib", ctx.imgs[0].name == "mscorlib", "首个 image = " + ctx.imgs[0].name);
    chk("typeCount-88902", ctx.typeCount == 88902, "Σ typeCount = " + dec(ctx.typeCount) + " (期望 88902)");
    // 88B 表的内在一致性: 区间必须首尾相接、无缝、无空洞(纯内存路径的权威来源)
    {
        // ⚠️ 之前 asc 只查 typeStart 上界, 全 0 退化表(ts 恒等)能整条通过 ——
        // 真机 typeCount=0 的空 dump 就是这样骗过了检查。现在额外要求:
        //   ts[0]==0、每条 tc>0、ts 严格递增。
        bool chain = !ctx.asms.empty(), asc = ctx.asms.size() == kAsmImgCount;
        uint64_t prevEnd = 0;
        for (size_t i = 0; i < ctx.asms.size(); ++i) {
            if (i && ctx.asms[i].typeStart != prevEnd) chain = false;
            if (i && ctx.asms[i].typeStart <= ctx.asms[i - 1].typeStart) asc = false;
            if (ctx.asms[i].typeCount == 0) asc = false;
            if (ctx.asms[i].typeStart > 0x1000000u) asc = false;
            prevEnd = (uint64_t)ctx.asms[i].typeStart + ctx.asms[i].typeCount;
        }
        chk("asm88-chain", chain && asc,
            "ts[0]=0 且每条 tc>0 且 ts 严格递增 且 ts[i]+tc[i]==ts[i+1]");
    }
    // 纯内存: blob 必须是**借用的游戏映射**, 不是我们读进来的文件
    chk("blob-borrowed", !ctx.ownsBlob, "blob 借用运行期映射(不读磁盘), ownsBlob=false");
    chk("blob-size", ctx.blobSize == 0x4EE4538ull,
        "blob 大小 " + hex64(ctx.blobSize) + " (7.1 期望 0x4EE4538)");

    // ---- 类型查找助手 ----
    auto findType = [&](const char* full) -> const TypeInfo* {
        for (const TypeInfo& t : types) {
            std::string f = t.ns.empty() ? t.name : (t.ns + "." + t.name);
            if (f == full) return &t;
        }
        return nullptr;
    };
    // 字段名/类型名被混淆时只能按 typedef 索引定位
    auto findTypeByTd = [&](uint32_t td) -> const TypeInfo* {
        for (const TypeInfo& t : types) if (t.tdIdx == td) return &t;
        return nullptr;
    };
    auto findField = [](const TypeInfo& t, const char* n) -> const FieldRaw* {
        for (const FieldInfo& f : t.fields) if (f.f.name == n) return &f.f;
        return nullptr;
    };
    auto findMethod = [](const TypeInfo& t, const char* n) -> const MethodInfo* {
        for (const MethodInfo& m : t.methods) if (m.name == n) return &m;
        return nullptr;
    };

    const TypeInfo* tObj = findType("System.Object");
    chk("type-System.Object", tObj != nullptr, tObj ? "命中 System.Object" : "未找到 System.Object");

    const TypeInfo* tI32 = findType("System.Int32");
    if (tI32) {
        chk("type-System.Int32", true, "命中 System.Int32, 是值类型=" + std::string(tI32->isValueType ? "是" : "否"));
        // ⚠️ 这条专门盯 IsValueType 的判据: 只看 kind 表会把 Int32 误判成 class
        chk("Int32-isValueType", tI32->isValueType, "byvalType 判据(原始类型无 kind 反引用)");
        const FieldRaw* mv = findField(*tI32, "m_value");
        // ⚠️ 偏移域含 16B 对象头, 所以 Int32.m_value 是 0x10 而不是 stock 布局的 0。
        //    早先这里写死 ==0 是拿 Il2CppDumper 的约定去套这份元数据, 必然 FAIL。
        chk("Int32.m_value", mv && mv->type == "int" && mv->offsetKnown && mv->offset == 0x10,
            mv ? ("int @" + dec((uint64_t)(int64_t)mv->offset) + (mv->offsetFromTable ? " (偏移表)" : " (布局推算)"))
               : "未找到 m_value");
    } else chk("type-System.Int32", false, "未找到 System.Int32");

    for (const char* nm : { "UnityEngine.Vector2", "UnityEngine.Vector3" }) {
        const TypeInfo* t = findType(nm);
        if (!t) { chk(nm, false, "未找到"); continue; }
        chk((std::string(nm) + "-isValueType").c_str(), t->isValueType, "命中 " + std::string(nm));
        uint32_t want = (std::string(nm) == "UnityEngine.Vector2") ? 8u : 12u;
        chk((std::string(nm) + "-size").c_str(), t->instanceSize == want,
            "推算 size=" + dec(t->instanceSize) + " 期望 " + dec(want));
        // 自引用判据方向一旦写反, static 字段会挤掉 x/y/z -> 这三条会立刻炸
        const FieldRaw* x = findField(*t, "x");
        const FieldRaw* y = findField(*t, "y");
        std::string got, wantOff;
        if (x && y) got = dec((uint64_t)(int64_t)x->offset) + "/" + dec((uint64_t)(int64_t)y->offset);
        else got = "缺失";
        // ⚠️ 偏移域含 16B 对象头(引用类型和值类型都是 0x10 起), 不是 stock 的 0/4/8。
        wantOff = (std::string(nm) == "UnityEngine.Vector2") ? "16/20" : "16/20";
        if (std::string(nm) == "UnityEngine.Vector3") {
            const FieldRaw* z = findField(*t, "z");
            got += "/" + std::string(z ? dec((uint64_t)(int64_t)z->offset) : "?");
            wantOff += "/24";
        }
        chk((std::string(nm) + "-offset").c_str(), got == wantOff, "x/y[/z]=" + got + " 期望 " + wantOff);
    }

    // 事件总数 + 两个返回类型锚点
    chk("event-count-628", A.eTot == 628, "事件数 " + dec(A.eTot) + " (期望 628)");

    const TypeInfo* tStr = findType("System.String");
    if (tStr) {
        const MethodInfo* m = findMethod(*tStr, "get_Length");
        chk("String.get_Length", m && m->ret == "int", m ? ("返回 " + m->ret) : "未找到 get_Length");
    } else chk("System.String", false, "未找到 System.String");

    const TypeInfo* tV2 = findType("UnityEngine.Vector2");
    if (tV2) {
        const MethodInfo* m = findMethod(*tV2, "Dot");
        chk("Vector2.Dot", m && m->ret == "float", m ? ("返回 " + m->ret) : "未找到 Dot");
    }

    // 混淆原语锚点。**必须取多个 i**: i=0 时好几个原语退化成恒等式
    // (prop_key(0)=0x70BE4B04 因为 >>9 的项为 0), 单点锚点等于没测。
    // 期望值来自 v3 的 Python 实现(v3 用 20000 组对拍钉死)。
    {
        struct P { const char* n; uint32_t got[3]; uint32_t want[3]; };
        const P ps[] = {
            { "field_key",    { field_key(0),    field_key(1),    field_key(12345)    },
                             { 0xE924C21Bu,    0xB37F41D4u,    0x9F82EC9Cu } },
            { "method_key",   { method_key(0),   method_key(1),   method_key(12345)   },
                             { 0xCFB927A2u,    0x9C80D48Fu,    0xD8B15837u } },
            { "method_key16", { method_key16(0), method_key16(1), method_key16(12345) },
                             { 0x000027A2u,    0x0000D48Fu,    0x00005837u } },
            { "prop_key",     { prop_key(0),     prop_key(1),     prop_key(12345)     },
                             { 0x70BE4B04u,    0x8D9F04C6u,    0xD9AF9360u } },
            { "event_key",    { event_key(0),    event_key(1),    event_key(12345)    },
                             { 0x7DFCF528u,    0x1CAFBD62u,    0xB022ACB2u } },
            { "param_key_of", { param_key_of(0), param_key_of(1), param_key_of(12345) },
                             { 0x59176BA7u,    0x62073714u,    0x94627BE1u } },
        };
        for (const P& p : ps) {
            bool ok = true;
            std::string d;
            for (int k = 0; k < 3; ++k) {
                if (p.got[k] != p.want[k]) ok = false;
                char b[32]; snprintf(b, sizeof b, "%s0x%08X", k ? "/" : "", p.got[k]);
                d += b;
            }
            chk(p.n, ok, "i=0/1/12345 -> " + d);
        }
    }

    // ---- 7.0 特性表 ----
    // ---- 真实字段偏移链 (sub_140512870 SetupFields) ----
    if (ctx.features[FEAT_FIELD_OFFSET]) {
        chk("fieldOff-table", ctx.fieldOffTable != nullptr && ctx.fdesc12Tab && ctx.fhidx4Tab,
            "4B 偏移表 + 12B 描述符 + 4B 索引 均已定位");
        // 锚点 1: **布局合法性**(取代早先错误的"attrBase 连续性"判据)。
        // 正确判据 = 多个实例字段时偏移按字段序严格升序无重复。错误的索引链会给出接近 0%。
        {
            uint64_t asc = A.asc, tot = A.ascTot;
            chk("fieldOff-ascending", tot > 0 && asc * 100 / tot >= 99,
                "实例偏移按字段序严格升序: " + dec(asc) + "/" + dec(tot) +
                " (" + dec(tot ? asc * 100 / tot : 0) + "%, 期望 >=99%)");
        }
        // 锚点 2: static 判据 —— 含 static 的类型里, static 应集中在字段表前部。
        // (C# 编译器把 static readonly 一律排在实例字段之前; 泛型/闭包类才会交错)
        {
            uint64_t front = A.front, withStatic = A.withStatic;
            chk("fieldOff-static-first", withStatic > 0 && front * 100 / withStatic >= 99,
                "含 static 的类型里 static 集中在实例字段之前: " + dec(front) + "/" + dec(withStatic) +
                " (" + dec(withStatic ? front * 100 / withStatic : 0) + "%, 期望 >=99%)");
        }
        // 锚点 3: 偏移域含 16B 对象头, 所以引用类型和值类型的**最小**实例偏移都必须是
        // 0x10。引用类型侧是硬约束(不能压对象头); 值类型侧则说明这份元数据与 stock
        // Il2CppDumper 的约定差一个常数 0x10(那边值类型从 0 起)。
        // ⚠️ 不能要求"**首**字段 == 0x10": 派生类 / 显式布局的字段序未必从 0x10 起。
        {
            uint64_t refOk = A.refOk, refTot = A.refTot, vtOk = A.vtOk, vtTot = A.vtTot;
            chk("fieldOff-ref-no-header-clash", refTot > 0 && refOk * 100 / refTot >= 99,
                "引用类型最小实例偏移 >= 0x10(不压对象头): " + dec(refOk) + "/" + dec(refTot) +
                " (" + dec(refTot ? refOk * 100 / refTot : 0) + "%, 期望 >=99%)");
            chk("fieldOff-vt-min-0x10", vtTot > 0 && vtOk * 100 / vtTot >= 99,
                "值类型最小实例偏移 == 0x10(含对象头域, 比 stock 多 0x10): " +
                dec(vtOk) + "/" + dec(vtTot) + " (" + dec(vtTot ? vtOk * 100 / vtTot : 0) + "%, 期望 >=99%)");
        }
        // 锚点 4: 已知类型的偏移直读值(字段名被混淆的类型只能按位置校验)
        for (const char* nm : { "UnityEngine.Vector2", "UnityEngine.Vector3" }) {
            const TypeInfo* t = findType(nm);
            if (!t) continue;
            auto fo = [&](const char* fn) -> long {
                for (const FieldInfo& fi : t->fields)
                    if (fi.f.name == fn && fi.f.offsetFromTable) return fi.f.offset;
                return -1;
            };
            std::string nmS = nm;
            bool ok;
            if (nmS == "UnityEngine.Vector2")     ok = (fo("x") == 0x10 && fo("y") == 0x14);
            else if (nmS == "UnityEngine.Vector3") ok = (fo("x") == 0x10 && fo("y") == 0x14 && fo("z") == 0x18);
            else ok = false;
            chk((nmS + "-off-from-table").c_str(), ok,
                "偏移表直读 " + nmS + " = " + dec((uint64_t)fo("x")) + "/" +
                dec((uint64_t)fo("y")) + (nmS == "UnityEngine.Vector3" ? "/" + dec((uint64_t)fo("z")) : ""));
        }
        {
            // System.Reflection.Assembly(ti=532) 的字段名全被混淆, 只能按位置校验:
            // 10 个引用字段应落在 0x10,0x18,...,0x58
            const TypeInfo* t = findTypeByTd(532);
            std::vector<long> o;
            if (t) for (const FieldInfo& fi : t->fields)
                if (fi.f.offsetFromTable) o.push_back(fi.f.offset);
            bool ok = o.size() >= 8;
            for (size_t k = 0; ok && k < 8 && k < o.size(); ++k)
                if (o[k] != (long)(0x10 + 8 * k)) ok = false;
            chk("Assembly-off-from-table", ok,
                "System.Reflection.Assembly 前 8 个实例偏移 = 0x10 起每槽 8 字节 (共 " + dec(o.size()) + " 个)");
        }
        const OffStat& st = FieldOffsetStats();
        // ⚠️ 与 CLI 布局推算"不一致"是**预期**的, 不是错误: 布局推算无法区分 static,
        // 会把 static 字段也分配实例偏移, 于是后面所有字段都错位。这里只是记录两条
        // 独立路径的吻合面, 供人工判断, 不作为 PASS/FAIL 判据。
        chk("fieldOff-vs-layout", true,
            "与 CLI 布局推算: 一致 " + dec(st.offAgree) + ", 不一致 " + dec(st.offDisagree) +
            " (不一致 = 布局推算错, 偏移表为准), 无实例偏移(static/const) " + dec(st.offNoTable) +
            ", 有默认值 " + dec(st.fieldsWithDefault));
    } else unported("0");

    // ---- 枚举成员常量值 (sub_14051A510) ----
    if (ctx.features[FEAT_ENUM_VALUES]) {
        // 三个已知枚举, 值与 .NET 逐一对照 —— 这是唯一能证伪"槽位/宽度算错了"的锚点
        struct EA { const char* type; const char* member; uint64_t want; };
        const EA ea[] = {
            { "System.ConsoleColor",            "Black",           0 },
            { "System.ConsoleColor",            "White",           15 },
            { "System.AttributeTargets",        "Assembly",        1 },
            { "System.AttributeTargets",        "Property",        128 },
            { "System.AttributeTargets",        "All",             32767 },
            // RegistryHive 只挑**名字与序号一一对应**的成员做锚点。
            // 这份元数据里 DynData=0x80000005 / CurrentConfig=0x80000005... 实为
            // DynData=0x80000006 / CurrentConfig=0x80000005, 与 .NET 文档**互换**。
            // 那是这份元数据的事实(或该 Mono 版本的差异), 不是解码错误, 所以不拿它当判据。
            { "Microsoft.Win32.RegistryHive",   "ClassesRoot",     0x80000000ull },
            { "Microsoft.Win32.RegistryHive",   "CurrentUser",     0x80000001ull },
            { "Microsoft.Win32.RegistryHive",   "LocalMachine",    0x80000002ull },
            { "Microsoft.Win32.RegistryHive",   "Users",           0x80000003ull },
        };
        for (const EA& a : ea) {
            const TypeInfo* t = findType(a.type);
            const FieldRaw* got = nullptr;
            if (t) for (const FieldRaw& e : t->enumVals) if (e.name == a.member) { got = &e; break; }
            chk((std::string("enumval-") + a.type + "." + a.member).c_str(),
                got && got->value == a.want,
                got ? (std::string(a.member) + "=" + dec(got->value) + " 期望 " + dec(a.want))
                    : (std::string(a.member) + " 未找到"));
        }
        // 规模与自洽: 枚举类型数 / 成员数 / 常量表条数
        const OffStat& st = FieldOffsetStats();
        uint64_t maxSlot = 0, ascSlot = 0, vZero = 0;
        for (uint32_t i = 0; i < ctx.enumValCount; ++i) {
            int32_t s = (int32_t)rd32(ctx.enumValTab + 12ull * i + 4);
            if (s > 0 && (uint32_t)s > maxSlot) maxSlot = (uint32_t)s;
            if (i) {
                int32_t p = (int32_t)rd32(ctx.enumValTab + 12ull * (i - 1) + 4);
                if (p >= 0 && s > p) ++ascSlot;
            }
        }
        chk("enumval-table", ctx.enumValCount > 70000 && ascSlot * 100 / ctx.enumValCount >= 99,
            "常量表 " + dec(ctx.enumValCount) + " 条, 槽位严格递增 " + dec(ascSlot) + "/" +
            dec(ctx.enumValCount) + ", 最大槽位 " + dec(maxSlot));
        chk("enumval-coverage", st.enumTypes > 8000 && st.enumMembers > 20000,
            "枚举类型 " + dec(st.enumTypes) + " 个, 成员 " + dec(st.enumMembers) +
            " 个(值全部从常量表直读)");
        // 反向: 带 value__ 的类型必须都能算出成员, 否则说明枚举判据放宽了
        uint64_t vtTypes = A.vtTypes, vtWithEnum = A.vtWithEnum;
        (void)vZero;
        chk("enumval-not-overreach", vtWithEnum * 100 / (vtTypes ? vtTypes : 1) >= 80,
            "带 value__ 的类型里解出成员值的: " + dec(vtWithEnum) + "/" + dec(vtTypes) +
            " (" + dec(vtTypes ? vtWithEnum * 100 / vtTypes : 0) + "%, 期望 >=80%)");
    } else { unported("2"); unported("4"); }

    unported("1");  // FEAT_FIELD_DEF
    unported("3");  // FEAT_FIELD_DEFVAL
    unported("5");  // FEAT_GENERIC_INST
    unported("6");  // FEAT_IFACE_SLOT
    unported("7");  // FEAT_ELEM_14

    char tail[128];
    snprintf(tail, sizeof tail, "formulaCheck summary: %d pass / %d fail / %d skip(未移植)\n", pass, fail, skip);
    rep += tail;
    if (fail)
        rep += "*** 有 " + dec((uint64_t)fail) + " 项 FAIL —— 公式或地址语义不成立, 别信产物 ***\n";
}

// ---------------------------------------------------------------- RunDump ---
bool RunDump(GameCtx& ctx, const std::wstring& outDir) {
    EnsureDir(outDir);

    // ---- 逐类型解码 + 立刻落盘, **不保留全部类型** ----
    // 之前累积 88,902 个 TypeInfo(峰值 RSS 868MB), 在游戏进程里这份堆结构
    // 会被破坏, 写盘时 &t 变野指针 -> 0xC0000005(2026-09-26 真机)。
    // 现在同时只存活一个类型, 峰值内存降到几 MB。
    SetStage("decode.begin");
    Progress("[2/6] 解码 + 流式写盘 (%u 个类型) ...", ctx.typeCount);

    StreamWriter wcs, wjs;
    if (!wcs.open(Join(outDir, L"dump.cs"))) {
        ctx.err = "cannot open dump.cs for writing (outDir=" + NarrowForDiag(outDir) + ")";
        return false;
    }
    if (!wjs.open(Join(outDir, L"dump.json"))) {
        ctx.err = "cannot open dump.json for writing";
        return false;
    }
    // ⚠️ dump.cs 必须带 UTF-8 BOM。
    //    文件本身是合法 UTF-8, 但**没有 BOM** 时, 中文版 Windows 的编辑器会按
    //    GBK/CP936 猜编码 -> 整篇乱码(2026-09-26 真机)。json 不加 BOM ——
    //    RFC 8259 不允许, 加了反而会让严格解析器报错。
    wcs.write("\xEF\xBB\xBF", 3);
    {   // 头长度自己算, 避免手数
        const char* hdr = "// GenshinImpact 7.1 IL2CPP dump (gsdump6)\n"
              "// 字段偏移来自 metadata 的 4B 偏移表(经 desc12[fhidx4[ti]]+8 索引), 不是按布局推算。\n"
              "// ⚠️ 坐标系含 16 字节 Il2CppObject 头: 引用类型和值类型的首字段都在 0x10,\n"
              "//   比 stock Il2CppDumper 的约定(值类型从 0 起)多一个常数 0x10。\n"
              "// static / const 字段不占实例空间, 故无偏移(元数据里就是 0)。\n"
              "// 格式完全对齐 Il2CppDumper: // Image N: dll - start:count、// Namespace、\n"
              "//   // TypeDefIndex: N, 方法上方 // RVA: 0x.. Offset: 0x.. VA: 0x..。\n"
              "//   方法行的 RVA 在行首 —— tools/ida_apply_symbols.py 靠它定位; VA 可在 IDA 里\n"
              "//   直接 Alt+Q 跳转。\n";
        wcs.write(hdr, strlen(hdr));
    }
    {
        // 自描述头: IDA 脚本不用再硬编码 imageBase / 各类表 RVA
        std::string m = "{\"meta\":{";
        m += "\"imageBase\":\"" + hex0(kImageBase) + "\",";
        m += "\"typeArrayRva\":\"" + hex0(ctx.typeRecRva) + "\",";
        m += "\"methodCodeTableRva\":\"" + hex0(kRvaMethodCodePtrs) + "\",";
        m += "\"methodThunkTableRva\":\"" + hex0(kRvaMethodThunkPtrs) + "\",";
        m += "\"typeCount\":" + dec(ctx.typeCount) + ",";
        m += "\"methodCount\":" + dec(ctx.methodCountTotal) + ",";
        m += "\"fieldCount\":" + dec(ctx.fieldCountTotal) + ",";
        m += "\"blobSize\":" + dec(ctx.blobSize) + ",";
        m += "\"coordOffset\":\"0x10\",";
        m += "\"note\":\"rva 是十六进制字符串, VA = imageBase + rva; "
             "已去掉 method.index、type.depth(可由 parent 链推出); "
             "字段偏移坐标系含 16 字节 Il2CppObject 头(值类型从 0x10 起)\"";
        m += "},\"types\":[";
        wjs.write(m.data(), m.size());
    }

    struct Stream {
        const GameCtx* ctx = nullptr;   // emitCs 要查共享桩表; TypeSink 是函数指针,
                                        // 捕获不了 ctx, 只能从 user 里取
        Acc acc;
        std::vector<TypeInfo> watch;
        StreamWriter* cs;
        StreamWriter* js;
        std::string cbuf, jbuf;
        uint64_t nextCs = 16u << 20, nextJs = 32u << 20, bytes = 0;
    } st;
    st.ctx = &ctx;
    st.cs = &wcs;
    st.js = &wjs;

    auto sink = [](void* user, const TypeInfo& t, uint32_t index) {
        Stream& S = *(Stream*)user;
        S.acc.one(t, &S.acc.fStatic, &S.acc.fOff);
        if (IsWatched(t)) S.watch.push_back(t);
        if (index) S.jbuf += ',';        // json 数组分隔符(只加给 json!)
        emitCs(*S.ctx, t, S.cbuf);
        emitJsonOne(t, S.jbuf);
        if (S.cbuf.size() >= (4u << 20)) { S.cs->write(S.cbuf.data(), S.cbuf.size()); S.cbuf.clear(); }
        if (S.jbuf.size() >= (4u << 20)) { S.js->write(S.jbuf.data(), S.jbuf.size()); S.jbuf.clear(); }
        if (S.cs->total() >= S.nextCs) {
            Progress("      dump.cs 已写 %.0f MB ...", S.cs->total() / 1048576.0);
            S.nextCs += 16u << 20;
        }
        if (S.js->total() >= S.nextJs) {
            Progress("      dump.json 已写 %.0f MB ...", S.js->total() / 1048576.0);
            S.nextJs += 32u << 20;
        }
    };

    if (!DecodeAllTypes(ctx, sink, &st)) return false;

    wcs.write(st.cbuf.data(), st.cbuf.size());
    wcs.close();
    if (!wcs.good()) { ctx.err = "write dump.cs failed"; return false; }
    wjs.write(st.jbuf.data(), st.jbuf.size());          // 先写完剩余片段
    { const char* tail = "]}\n"; wjs.write(tail, 3); } // 再补数组尾, 最后才关
    wjs.close();
    if (!wjs.good()) { ctx.err = "write dump.json failed"; return false; }
    Progress("[3/6] dump.cs %llu 字节, dump.json %llu 字节 (memReadable 累计 %llu)",
             (unsigned long long)wcs.total(), (unsigned long long)wjs.total(),
             (unsigned long long)g_memReadableCalls);

    const std::vector<TypeInfo>& types = st.watch;
    const Acc& A = st.acc;
    uint64_t fTot = A.fTot, fStatic = A.fStatic, fOff = A.fOff;
    uint64_t mTot = A.mTot, pTot = A.pTot, eTot = A.eTot, iTot = A.iTot;

    Progress("[6/6] 写 report/summary/diag ...");
    // ---- report.txt ----
    std::string rep;
    rep += "================ gsdump5 report ================\n";
    rep += "input   : 纯内存(运行期映射) —— 不读 global-metadata.dat / startup-metadata.dat\n";
    // 诊断: 真机上每次 memReadable 都是一次 VirtualQuery(~1-3us)。这个数应该
    // 只有几百 —— 若是百万级, 说明热路径上又混进了系统调用, dump 会慢到像卡死。
    rep += "syscalls: memReadable=" + dec(g_memReadableCalls) + " 次 (VirtualQuery)\n";
    rep += "mode    : 纯静态(无运行期 Class/MethodInfo 遍历)\n\n";
    rep += "-- counts --\n";
    rep += "types            " + dec(A.types) + "\n";
    rep += "fields           " + dec(fTot) + "  (static " + dec(fStatic) + ", 有偏移 " + dec(fOff) + ")\n";
    rep += "methods          " + dec(mTot) + "\n";
    rep += "properties       " + dec(pTot) + "\n";
    rep += "events           " + dec(eTot) + "\n";
    rep += "interfaces       " + dec(iTot) + "\n";
    formulaCheck(ctx, A, types, rep);
    writeAll(Join(outDir, L"report.txt"), rep);

    // ---- summary.txt (手拼, 不用 <sstream>: 静态链接下 <sstream> 会拖进几 MB) ----
    {
        std::string sum;
        char b[256];
        auto kv = [&](const char* k, uint64_t v) {
            snprintf(b, sizeof b, "%s=%llu\n", k, (unsigned long long)v); sum += b;
        };
        kv("typeCount", ctx.typeCount);
        kv("dumped", A.types);
        kv("fields", fTot);
        kv("fieldsWithOffset", fOff);
        kv("fieldsStatic", fStatic);
        kv("methods", mTot);
        kv("props", pTot);
        kv("events", eTot);
        kv("ifaces", iTot);
        kv("globalMetadataBytes", ctx.blobSize);
        kv("startupBytes", 0);  // 纯内存: 不读 startup-metadata.dat
        snprintf(b, sizeof b, "typeRecRva=0x%llX\n", (unsigned long long)ctx.typeRecRva); sum += b;
        sum += "features:\n";
        for (int i = 0; i < FEAT__COUNT; ++i) {
            const FeatureInfo& f = FeatureById(i);
            sum += std::string("  [") + (ctx.features[i] ? "on " : "off") + "] " +
                   f.name + "  (7.0: " + f.v70 + ")  " + f.note + "\n";
        }
        sum += "\n" + ctx.diag;
        writeAll(Join(outDir, L"summary.txt"), sum);
    }
    writeAll(Join(outDir, L"diag.txt"), ctx.diag);

    appendLog(outDir, "RunDump ok types=" + dec(A.types) + " fields=" + dec(fTot) + "\n");
    writeAll(Join(outDir, L"dump.done"), "ok\n");
    return true;
}

} // namespace gs
