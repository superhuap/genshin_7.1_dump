// seh.h —— 跨编译器的"调用一段可能崩的代码"保护
//
// MSVC / clang-cl : 直接用 __try/__except。
// GCC / mingw-w64 / clang : 用 VEH + setjmp/longjmp 等价实现。
//
// 用途: 腿二"强制物化"要调用引擎内部函数 sub_14051CD50, 目标类型一旦触发
// 访问违例必须吞掉, 否则整个游戏崩。dumper 其余部分不需要这层保护。
#pragma once
#include <windows.h>
#include <setjmp.h>
#include <cstdio>
#include <cstring>
#include <string>

#if defined(_MSC_VER)

#define GS_GUARD_BEGIN(lo, hi)                       \
    const uintptr_t gs_lo_ = (uintptr_t)(lo);         \
    const uintptr_t gs_hi_ = (uintptr_t)(hi);         \
    __try {

#define GS_GUARD_END(on_error)                        \
    } __except (EXCEPTION_EXECUTE_HANDLER) { on_error; }

#else

namespace gs {
inline thread_local jmp_buf  gs_jb;
inline thread_local int       gs_hit = 0;
inline thread_local bool      gs_active = false;
inline thread_local DWORD     gs_tid = 0;
inline std::wstring          gs_outDir;   // 崩溃标记写到哪

// 捕获异常时先落一份证据: 光靠控制台/日志不够 —— 进程一旦死掉, 现场就没了。
// ⚠️ 必须把故障地址换算成"模块 + 偏移": 有 ASLR, 裸地址跨机器无法比对。
inline void GsWriteCrashMark(ULONG code, EXCEPTION_POINTERS* ep) {
    if (gs_outDir.empty()) return;
    void* addr = ep->ExceptionRecord->ExceptionAddress;
    void* fault = (ep->ExceptionRecord->NumberParameters >= 2)
                    ? (void*)(uintptr_t)ep->ExceptionRecord->ExceptionInformation[1] : nullptr;
    int acc = (ep->ExceptionRecord->NumberParameters >= 1)
                ? (int)ep->ExceptionRecord->ExceptionInformation[0] : -1;

    // 自身模块基址(用本函数地址反查, 不依赖任何硬编码)
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(const void*)&GsWriteCrashMark, &self);
    uint8_t* game = (uint8_t*)GetModuleHandleW(L"GenshinImpact.exe");

    wchar_t p[MAX_PATH];
    int n = _snwprintf(p, MAX_PATH, L"%s\\crash.txt", gs_outDir.c_str());
    if (n <= 0) return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, p, L"wb") != 0 || !f) return;

    fprintf(f, "exception_code = 0x%08lX  %s\n", (unsigned long)code,
            code == 0xC0000005UL ? "(ACCESS_VIOLATION)" :
            code == 0xC0000374UL ? "(HEAP_CORRUPTION)" :
            code == 0xE06D7363UL ? "(C++ EH)" : "");
    fprintf(f, "access         = %s\n",
            acc == 0 ? "READ" : acc == 1 ? "WRITE" : acc == 8 ? "EXECUTE" : "unknown");
    fprintf(f, "fault_addr     = %p\n", addr);
    fprintf(f, "fault_data     = %p  (被读/写的那个地址)\n", fault);
    fprintf(f, "tid            = %lu\n", (unsigned long)GetCurrentThreadId());
    fprintf(f, "\n-- module relative (关键: 有 ASLR, 裸地址没法跨机器比对) --\n");
    if (self) {
        uintptr_t a = (uintptr_t)addr, b = (uintptr_t)self;
        fprintf(f, "self_dll_base  = %p\n", (void*)self);
        fprintf(f, "addr_in_self   = %s", (a >= b && a - b < 0x2000000u) ? "YES  " : "no   ");
        if (a >= b && a - b < 0x2000000u) fprintf(f, "  self+0x%llX",
                                                  (unsigned long long)(a - b));
        fprintf(f, "\n");
    }
    if (game) {
        uintptr_t a = (uintptr_t)addr, b = (uintptr_t)game;
        fprintf(f, "game_base      = %p\n", (void*)game);
        fprintf(f, "addr_in_game   = %s", (a >= b && a - b < 0x40000000u) ? "YES  " : "no   ");
        if (a >= b && a - b < 0x40000000u) fprintf(f, "  game+0x%llX (RVA)",
                                                   (unsigned long long)(a - b));
        fprintf(f, "\n");
    }
    if (fault && self) {
        uintptr_t a = (uintptr_t)fault, b = (uintptr_t)self;
        fprintf(f, "data_in_self   = %s", (a >= b && a - b < 0x2000000u) ? "YES  " : "no   ");
        if (a >= b && a - b < 0x2000000u) fprintf(f, "  self+0x%llX",
                                                  (unsigned long long)(a - b));
        fprintf(f, "\n");
    }
    fprintf(f, "\n-- 当时在干什么 --\n");
    fprintf(f, "stage          = %s\n", g_stage);
    fprintf(f, "stage_idx      = %u\n", g_stageIdx);
    fprintf(f, "stage_val      = 0x%llX\n", (unsigned long long)g_stageVal);
    fclose(f);
}

// 只捕获**我们自己的线程**上的异常。
// 之前用 [lo,hi) 地址区间判定, 但 DecodeAllTypes/TypeNameOfRecord 在 meta.cpp,
// 与 dllmain.cpp 里的 &DumpBody 相距甚远, 根本不在那个区间 —— 异常会
// CONTINUE_SEARCH 直接打死游戏进程(2026-09-26 真机: 连 dump.cs 都没创建)。
// dump 跑在专用线程上, 所以"线程 ID 匹配"才是正确的判据:
// 既能兜住跨编译单元的 AV, 又完全不会碰游戏自己的线程。
inline LONG CALLBACK GsVeh(PEXCEPTION_POINTERS ep) {
    if (!gs_active) return EXCEPTION_CONTINUE_SEARCH;
    if (GetCurrentThreadId() != gs_tid) return EXCEPTION_CONTINUE_SEARCH;
    GsWriteCrashMark(ep->ExceptionRecord->ExceptionCode, ep);
    gs_hit = 1;
    longjmp(gs_jb, 1);
}
inline bool& GsVehOn() { static bool v = false; return v; }
inline void GsVehInstall() {
    if (!GsVehOn()) { AddVectoredExceptionHandler(1, GsVeh); GsVehOn() = true; }
}
} // namespace gs

#define GS_GUARD_BEGIN(lo, hi)                                     \
    (void)(lo); (void)(hi);                                        \
    gs::GsVehInstall();                                            \
    gs::gs_tid = GetCurrentThreadId();                             \
    gs::gs_hit = 0; gs::gs_active = true;                           \
    if (setjmp(gs::gs_jb) == 0) {

#define GS_GUARD_END(on_error)                                     \
    } else { gs::gs_hit = 0; }                                     \
    gs::gs_active = false;                                         \
    if (gs::gs_hit) { on_error; }

#endif
