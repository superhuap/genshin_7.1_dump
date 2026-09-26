// dllmain.cpp —— 注入入口(照搬 7.0 的流程: 轮询等就绪 -> dump -> 失败写 dump.fail)
//
// 与 7.0 完全一致的一点: **注入后轮询 InitCtx, 直到成功为止**。
// 7.0 每 250ms 试一次, 上限 10 分钟。这里同样处理, 因为 g_52B8/g_52C0 只在
// metadata init 完成后才非零 —— 注入太早会拿到 0。
//
// 与旧 v5 的差别: **不再读任何磁盘文件**, 也不再等"metadata 落盘"。
// 唯一等的是运行期全局就绪, 这比等文件落盘更快也更可靠。
#include "dumper.h"
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include "seh.h"
#endif

namespace gs {
static std::wstring g_dir;

// 输出目录: 与 7.0 完全一致 —— %TEMP%\genshin_dump (取不到 TEMP 就退到 .\genshin_dump)
static std::wstring DefaultOutDir() {
    wchar_t tmp[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"TEMP", tmp, MAX_PATH);
    return (n && n < MAX_PATH) ? std::wstring(tmp) + L"\\genshin_dump"
                               : std::wstring(L".\\genshin_dump");
}
static std::wstring DirOfExe() {
    wchar_t w[MAX_PATH];
    if (!GetModuleFileNameW(NULL, w, MAX_PATH)) return L".";
    std::wstring s(w);
    size_t k = s.find_last_of(L"\\");
    return (k == std::wstring::npos) ? L"." : s.substr(0, k);
}
static std::wstring ConfigPath() { return g_dir + L"\\config.txt"; }

// 配置极简: 7.0 也没有配置文件, 全靠默认。这里只保留 console/hold/timeout。
static void WriteDefaultConfig() {
    FILE* f = nullptr;
    _wfopen_s(&f, ConfigPath().c_str(), L"wb");
    if (!f) return;
    fputs("# gsdump6 配置 (纯内存模式, 不读任何 .dat)\r\n"
          "# 输出目录固定为 %TEMP%\\genshin_dump (与 7.0 一致), 不可配置\r\n"
          "# console=1        弹控制台看实时日志(默认 1)\r\n"
          "# hold=1           结束后等按键再关窗口(默认 0)\r\n"
          "# timeout=<秒>     等 metadata 全局就绪的上限(默认 600)\r\n",
          f);
    fputs("console=1\r\nhold=0\r\ntimeout=600\r\n", f);
    fclose(f);
}
static void LoadConfig(int& timeoutSec, int& wantConsole, int& holdConsole) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, ConfigPath().c_str(), L"rb") != 0 || !f) {
        WriteDefaultConfig();
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char* k = line;
        while (*k == ' ' || *k == '\t') ++k;
        char* v = eq + 1;
        if (!strcmp(k, "timeout")) timeoutSec = atoi(v);
        else if (!strcmp(k, "console")) wantConsole = atoi(v);
        else if (!strcmp(k, "hold")) holdConsole = atoi(v);
    }
    fclose(f);
}

// ---------------------------------------------------------------------------
// 控制台
//
// 为什么默认(不给代码)就是**看不到窗口**: GenshinImpact.exe 是 GUI 子系统的进程,
// 本身没有控制台。DLL 被注进它以后, CRT 在进程初始化时就把 stdout/stderr 绑到了
// 一个**无效句柄**上。所以:
//   1) 不主动 AllocConsole -> 根本没有控制台
//   2) 只 AllocConsole 而不 freopen("CONOUT$") -> CRT 的 stdout 仍指向那个无效句柄,
//      printf 照样全部丢失(这一步是最容易漏的)
// 两条都做了才会在屏幕上真的看到字。
//
// 另外 Log() 的内容同时镜像到 progress.log —— 在 Session 0 / 无控制台的远程会话 /
// console=0 的情况下这是唯一的持久记录。
static bool g_haveConsole = false;
static void OpenConsole() {
    // 先尝试挂到父进程的控制台(从 cmd/PowerShell 启动游戏时有效), 否则自己开一个
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
    // ★ 代码页必须设成 UTF-8: 源码里是 UTF-8 中文, 控制台默认 CP936/CP437,
    //   不设就会看到"鍚姩"这种把 UTF-8 当 GBK 解的乱码。
    //   ⚠️ 这里**只改代码页**, 不动控制台的大小和字体 —— 沿用用户/游戏自己的设置。
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    FILE* f = nullptr;
    // ★ 关键: 把 CRT 的 stdout/stderr 重新绑到 CONOUT$/CONIN$, 否则 printf 写不出字
    if (freopen_s(&f, "CONOUT$", "w", stdout) != 0 || !f) { g_haveConsole = false; return; }
    setvbuf(stdout, nullptr, _IONBF, 0);
    FILE* e = nullptr;
    freopen_s(&e, "CONOUT$", "w", stderr);
    g_haveConsole = true;
}

static std::wstring g_logPath;          // progress.log 的完整路径
static void Log(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[strcspn(buf, "\r\n")] = 0;      // Log 行自带换行
    if (g_haveConsole) { printf("%s\n", buf); fflush(stdout); }
    if (!g_logPath.empty()) {            // 镜像, 保证没控制台时也有记录
        FILE* f = nullptr;
        if (_wfopen_s(&f, g_logPath.c_str(), L"ab") == 0 && f) {
            fprintf(f, "[%5lu] %s\r\n", (unsigned long)GetTickCount(), buf);
            fclose(f);
        }
    }
}

// 自报身份: 编译时间 + 自身 SizeOfImage。
// 起因: 2026-09-26 用户注入的是一份旧 DLL, 日志格式对不上, 白排查了好几轮。
// 现在第一行日志就能证明"跑的是不是这份产物"。
static std::string SelfTag() {
    char b[160];
    uint32_t soi = 0;
#ifdef _WIN32
    HMODULE h = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)(const void*)&SelfTag, &h) && h) {
        uint8_t* p = (uint8_t*)h;
        uint32_t lf = rd32(p + 0x3C);
        if (lf && lf < 0x1000) soi = rd32(p + lf + 0x50);
    }
#endif
    snprintf(b, sizeof(b), "built=%s %s  SizeOfImage=%u", __DATE__, __TIME__, soi);
    return std::string(b);
}

// 7.0 的 __try/__except 包裹: dump 期间任何 AV 都不应该把游戏带崩。
// 纯内存模式读的都是游戏自己的结构, 理论上都合法, 但仍要兜底。
// Progress() 的转发: 统一走 Log, 这样控制台和 progress.log 都有
static void ProgressToLog(const char* line) { Log("[.] %s", line); }

static int DumpBody() {
    int timeoutSec = 600, wantConsole = 1, holdConsole = 0;
    LoadConfig(timeoutSec, wantConsole, holdConsole);
    // 输出目录与 7.0 一致: %TEMP%\genshin_dump
    const std::wstring outDir = DefaultOutDir();
    CreateDirectoryW(outDir.c_str(), nullptr);   // 幂等
    gs_outDir = outDir;                          // 崩溃时把现场写到这里
    g_logPath = outDir + L"\\progress.log";

    if (wantConsole) OpenConsole();
    // 把解码/写盘阶段的进度接到 Log 上(否则无法区分"慢"和"卡死")
    SetProgress(&ProgressToLog);

    Log("[+] gsdump6 启动 (pid=%lu) —— 纯内存模式, 不读任何 .dat",
        (unsigned long)GetCurrentProcessId());
    Log("[*] 本 DLL: %s   <- 若这行与你的构建不符, 说明注入的是旧文件", SelfTag().c_str());
    if (wantConsole && !g_haveConsole)
        Log("[!] 申请控制台失败(可能在 Session 0), 日志只写 progress.log");
    Log("[*] 输出目录 : %ls", outDir.c_str());

    // ---- 轮询等待 metadata 全局就绪(照搬 7.0: 每 250ms 试一次) ----
    // g_52B8/g_52C0 在 metadata init 结束前是 0; 注入太早会拿到 0, 所以必须等。
    GameCtx ctx;
    DWORD waited = 0;
    const DWORD kStep = 250, kLimit = (DWORD)timeoutSec * 1000u;
    Log("[*] 等待运行期 metadata 全局就绪 (g_52B8/g_52C0) ...");
    for (;;) {
        if (InitCtx(ctx)) break;
        if (waited % 5000 == 0)
            Log("[*] 等待中... %lus  last=%s", (unsigned long)(waited / 1000), ctx.err.c_str());
        if (waited >= kLimit) {
            Log("[-] metadata 在 %d 秒内没就绪: %s", timeoutSec, ctx.err.c_str());
            FILE* f = nullptr;
            _wfopen_s(&f, (outDir + L"\\dump.fail").c_str(), L"wb");
            if (f) {
                fprintf(f, "init-timeout\nerr  = %s\n\n---- diag ----\n%s\n",
                        ctx.err.c_str(), ctx.diag.c_str());
                fclose(f);
            }
            return 1;
        }
        Sleep(kStep);
        waited += kStep;
    }

    Log("[+] metadata 就绪: asms=%llu imgs=%llu typeCount=%llu methods=%llu fields=%llu",
        (unsigned long long)ctx.asms.size(), (unsigned long long)ctx.imgs.size(),
        (unsigned long long)ctx.typeCount, (unsigned long long)ctx.methodCountTotal,
        (unsigned long long)ctx.fieldCountTotal);
    Log("[*] 特性: ");
    for (int i = 0; i < FEAT__COUNT; ++i)
        if (ctx.features[i]) Log("    [on ] %s", FeatureById(i).name);
    for (int i = 0; i < FEAT__COUNT; ++i)
        if (!ctx.features[i]) Log("    [off] %s", FeatureById(i).name);

    Log("[*] 解算全部类型(约 10~30 秒) ...");
    if (!RunDump(ctx, outDir)) {
        Log("[-] RunDump failed: %s", ctx.err.c_str());
        FILE* f = nullptr;
        _wfopen_s(&f, (outDir + L"\\dump.fail").c_str(), L"wb");
        if (f) {
            fprintf(f, "RunDump failed\nerr  = %s\n\n---- diag ----\n%s\n",
                    ctx.err.c_str(), ctx.diag.c_str());
            fclose(f);
        }
        FreeCtx(ctx);
        return 1;
    }
    Log("[+] 完成 -> dump.cs / dump.json / report.txt / summary.txt");
    Log("[+] 先看 report.txt 的 formulaCheck 段");
    FreeCtx(ctx);
    if (g_haveConsole && holdConsole) {
        Log("[ hold] 按任意键关闭 ...");
        (void)getchar();
    }
    return 0;
}

static int g_rc = 1;
static void Worker() {
    // MinGW 不支持 __try, 用 seh.h 的 VEH 等价实现(MSVC 走原生 __try)。
    // 保护范围 = DumpBody 及其全部下游(解码/输出), 任何 AV 都不让游戏崩。
    // rc 必须 volatile: 它要活过 setjmp/longjmp, 否则寄存器里的值可能已失效。
    volatile int rc = 0;
    GS_GUARD_BEGIN(&DumpBody, (uint8_t*)((uint8_t*)&DumpBody + 0x20000)) {
        rc = DumpBody();
    } GS_GUARD_END(rc = 1);
    if (rc) Log("[x] dump 中断, 详见 dump.fail / progress.log\n");
    g_rc = rc;
}

} // namespace gs


BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        // 绝不在 DllMain 里读文件/开线程做重活 —— 加载器锁下做 I/O 会死锁
        HANDLE t = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            (void)p;
            gs::g_dir = gs::DirOfExe();
            gs::Worker();
            FreeLibraryAndExitThread((HMODULE)GetModuleHandleW(L"gsdump6.dll"), 0);
            return 0;
        }, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
