// gi_dump.c - GenshinImpact 7.1 metadata dump DLL
//
// Trigger : qword at RVA 0x5AD52C8 (startup-metadata buffer ptr) transitions
//           non-NULL -> NULL. That NULL happens at 0x14053A829 right after all
//           metadata tables are built (startup buffer released). Everything
//           metadata-related is clean/decoded in memory at that point.
// Manual  : create file "trigger.txt" inside the dump dir to force a dump.
// Output  : <game dir>\gi_dump\  (module.bin, pool_*.bin, raw_global.bin,
//           il2cpp_section.bin, globals.bin, *.map, info.json, gi_dump.log)
//
// Build (mingw-w64):
//   x86_64-w64-mingw32-gcc -O2 -shared -o gi_dump.dll gi_dump.c -static -lkernel32 -luser32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------- config ---

#define IMAGE_BASE_EXPECTED 0x140000000ULL
#define HEADER_SIZE_528     528
#define RAW_META_SIZE       0x4EE4538ULL   /* global-metadata.dat size (82,724,152) */
#define DUMP_DIRNAME        "gi_dump"
#define MANUAL_TRIGGER      "trigger.txt"
#define POLL_MS             5
#define LATE_ATTACH_GRACE   3000           /* ms to wait if we attached after init */
#define AUTO_TIMEOUT_MS     600000         /* give up auto trigger after 10 min */

// --- RVAs (VA - 0x140000000) from IDA analysis of GenshinImpact.exe 7.1 ---

#define RVA_POOL_METADATA   0x5AD4E90ULL   /* MemoryPool "Metadata"   (48B struct) */
#define RVA_POOL_GENCLASS   0x5AD4E98ULL   /* MemoryPool "GenericClass"            */
#define RVA_POOL_GENMETHOD  0x5AD4EA0ULL   /* MemoryPool "GenericMethod"           */

#define RVA_G_GLOBALS_LO    0x5AD4E80ULL   /* globals blob start (covers pools too) */
#define RVA_G_GLOBALS_HI    0x5AD5330ULL   /* globals blob end                      */

#define RVA_STARTUP_PTR     0x5AD52C8ULL   /* -> NULL when init finished            */
#define RVA_GLOBAL_BUF_528  0x5AD52C0ULL   /* -> raw global-metadata buffer + 528   */
#define RVA_IL2CPP_SEC_LO   0x5AD3900ULL   /* -> il2cpp section VA                  */
#define RVA_IL2CPP_SEC_HI   0x5AD3908ULL   /* -> il2cpp section end VA              */
#define RVA_IMAGE_SIZE      0x5AD3978ULL   /* -> SizeOfImage (set during init)      */

// globals recorded into info.json (name, rva)
static const struct { const char* name; uint64_t rva; } kGlobals[] = {
    {"il2cpp_sec_lo",     0x5AD3900ULL},
    {"il2cpp_sec_hi",     0x5AD3908ULL},
    {"image_size",        0x5AD3978ULL},
    {"methodptr_base",    0x5AD4D28ULL},
    {"pool_metadata",     0x5AD4E90ULL},
    {"pool_genericclass", 0x5AD4E98ULL},
    {"pool_genericmethod",0x5AD4EA0ULL},
    {"g_50F0",            0x5AD50F0ULL},
    {"g_5298",            0x5AD5298ULL},
    {"g_52A0",            0x5AD52A0ULL},
    {"g_52A8",            0x5AD52A8ULL},
    {"g_52B0",            0x5AD52B0ULL},
    {"g_52B8",            0x5AD52B8ULL},
    {"g_52C0",            0x5AD52C0ULL},
    {"startup_ptr",       0x5AD52C8ULL},
    {"g_52D0",            0x5AD52D0ULL},
    {"g_52D8",            0x5AD52D8ULL},
    {"g_52E0",            0x5AD52E0ULL},
    {"g_52E8",            0x5AD52E8ULL},
    {"g_52F0",            0x5AD52F0ULL},
    {"g_52F8",            0x5AD52F8ULL},
    {"g_5300",            0x5AD5300ULL},
    {"g_5308",            0x5AD5308ULL},
    {"g_5310",            0x5AD5310ULL},
    {"critsec",           0x5AD5458ULL},
};
#define NGLOBALS (sizeof(kGlobals)/sizeof(kGlobals[0]))

// ---------------------------------------------------------------- state ----

static uint64_t g_base   = 0;          /* actual image base                    */
static char     g_dir[MAX_PATH];       /* dump output dir                      */
static char     g_exedir[MAX_PATH];    /* game exe directory                   */
static char     g_log[MAX_PATH];
static HANDLE   g_logf   = NULL;
static volatile LONG g_done = 0;

#define RVA(rva)  (g_base + (rva))
#define RD64(rva) (*(volatile uint64_t*)RVA(rva))
#define RD32(rva) (*(volatile uint32_t*)RVA(rva))

// ---------------------------------------------------------------- helpers --

static void logf_(const char* fmt, ...)
{
    if (!g_logf) return;
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf(buf, sizeof(buf)-2, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    buf[n] = '\n';
    DWORD wr;
    WriteFile(g_logf, buf, (DWORD)n+1, &wr, NULL);
    FlushFileBuffers(g_logf);
}

static int readable(uint64_t addr, uint64_t size)
{
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t p = addr, end = addr + size;
    while (p < end) {
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) return 0;
        uint64_t region_end = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
        if (!(mbi.State & MEM_COMMIT)) return 0;
        DWORD prot = mbi.Protect & 0xFF;
        if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return 0;
        if (prot != PAGE_READONLY  && prot != PAGE_READWRITE &&
            prot != PAGE_WRITECOPY && prot != PAGE_EXECUTE_READ &&
            prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
            return 0;
        p = region_end;
    }
    return 1;
}

/* mingw has no __try/__except; guard with VirtualQuery before touching memory.
   TOCTOU window is negligible here (post-init state is stable). */
static int read_mem(uint64_t addr, void* out, size_t len)
{
    if (!readable(addr, (uint64_t)len)) return 0;
    memcpy(out, (const void*)addr, len);
    return 1;
}

/* dump [start,end) walking committed regions; sparse parts stored as zero gaps
   in the linear file, mapping written to <path>.map */
static int dump_range(const char* name, uint64_t start, uint64_t end)
{
    char path[MAX_PATH], mappath[MAX_PATH];
    _snprintf(path,    sizeof(path), "%s\\%s",     g_dir, name);
    _snprintf(mappath, sizeof(mappath), "%s\\%s.map", g_dir, name);

    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE mf = CreateFileA(mappath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { logf_("open failed: %s", path); return 0; }

    uint64_t written = 0;
    uint64_t p = start;
    logf_("dump %s: [0x%llX, 0x%llX)", name, start, end);

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) break;
        uint64_t rbase = (uint64_t)mbi.BaseAddress;
        uint64_t rend  = rbase + mbi.RegionSize;
        if (rend > end) rend = end;
        if (rend <= p) break;

        DWORD prot = mbi.Protect & 0xFF;
        int ok = (mbi.State & MEM_COMMIT) &&
                 prot != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD) &&
                 (prot==PAGE_READONLY || prot==PAGE_READWRITE || prot==PAGE_WRITECOPY ||
                  prot==PAGE_EXECUTE_READ || prot==PAGE_EXECUTE_READWRITE ||
                  prot==PAGE_EXECUTE_WRITECOPY);

        static char zero[1 << 20];
        static char buf [1 << 20];

        uint64_t q = p;
        while (q < rend) {
            uint64_t chunk = rend - q;
            if (chunk > sizeof(buf)) chunk = sizeof(buf);
            if (ok && readable(q, chunk) && read_mem(q, buf, (size_t)chunk)) {
                DWORD wr; WriteFile(f, buf, (DWORD)chunk, &wr, NULL);
                if (mf != INVALID_HANDLE_VALUE) {
                    char line[128];
                    int n = _snprintf(line, sizeof(line), "%llX %llX %llX\n",
                                      (unsigned long long)(q - start),
                                      (unsigned long long)q,
                                      (unsigned long long)chunk);
                    DWORD mw; WriteFile(mf, line, (DWORD)n, &mw, NULL);
                }
            } else {
                DWORD wr; WriteFile(f, zero, 1, &wr, NULL);
                /* single zero byte for uncommitted byte, then bulk-zero below */
                if (chunk > 1) {
                    uint64_t big = chunk - 1; DWORD wr;
                    if (big > sizeof(zero)) {
                        while (big > sizeof(zero)) {
                            WriteFile(f, zero, sizeof(zero), &wr, NULL);
                            big -= sizeof(zero);
                        }
                    }
                    WriteFile(f, zero, (DWORD)big, &wr, NULL);
                }
            }
            q += chunk;
            written += chunk;
        }
        p = rend;
    }
    if (mf != INVALID_HANDLE_VALUE) CloseHandle(mf);
    CloseHandle(f);
    logf_("dump %s done: %llu bytes", name, (unsigned long long)written);
    return 1;
}

static void add_json_qword(char* json, size_t cap, int* first,
                           const char* name, uint64_t v)
{
    char item[128];
    _snprintf(item, sizeof(item), "%s\"%s\": %llu",
              *first ? "" : ",\n  ", name, (unsigned long long)v);
    size_t len = strlen(json);
    if (len + strlen(item) + 8 < cap) { strcat(json, item); *first = 0; }
}

// ------------------------------------------------------------------ dump ---

static int dump_everything(void)
{
    char path[MAX_PATH];

    /* --- module image --- */
    uint64_t image_size = 0;
    {
        uint64_t v = RD64(RVA_IMAGE_SIZE);
        if (v > 0x1000 && v < 0x100000000ULL) image_size = v;
        else {
            IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS64 nt;
            if (read_mem(g_base, &dos, sizeof(dos)) && dos.e_magic == 0x5A4D &&
                read_mem(g_base + dos.e_lfanew, &nt, sizeof(nt)) &&
                nt.Signature == 0x4550)
                image_size = nt.OptionalHeader.SizeOfImage;
        }
    }
    logf_("image base 0x%llX size 0x%llX", g_base, image_size);
    if (g_base != IMAGE_BASE_EXPECTED)
        logf_("WARNING: base != expected 0x%llX (internal exe pointers assume it!)",
              IMAGE_BASE_EXPECTED);

    /* --- globals blob + json --- */
    uint64_t glo_size = RVA_G_GLOBALS_HI - RVA_G_GLOBALS_LO;
    static unsigned char glo[0x1000];
    int have_glo = read_mem(RVA(RVA_G_GLOBALS_LO), glo, (size_t)glo_size);

    _snprintf(path, sizeof(path), "%s\\globals.bin", g_dir);
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr; WriteFile(f, glo, (DWORD)glo_size, &wr, NULL); CloseHandle(f);
    }

    char json[8192]; json[0] = 0;
    strcat(json, "{\n  ");
    int first = 1;
    add_json_qword(json, sizeof(json), &first, "image_base", g_base);
    add_json_qword(json, sizeof(json), &first, "image_size", image_size);
    add_json_qword(json, sizeof(json), &first, "globals_blob_rva", RVA_G_GLOBALS_LO);
    for (unsigned i = 0; i < NGLOBALS; i++) {
        uint64_t v = have_glo
            ? *(uint64_t*)(glo + (kGlobals[i].rva - RVA_G_GLOBALS_LO))
            : RD64(kGlobals[i].rva);
        add_json_qword(json, sizeof(json), &first, kGlobals[i].name, v);
    }
    /* pool extents */
    {
        uint64_t pm = RD64(RVA_POOL_METADATA);
        uint64_t pc = RD64(RVA_POOL_GENCLASS);
        uint64_t pg = RD64(RVA_POOL_GENMETHOD);
        if (pm) { add_json_qword(json, sizeof(json), &first, "pool_meta_base",   *(uint64_t*)pm); add_json_qword(json, sizeof(json), &first, "pool_meta_end",   *(uint64_t*)(pm+16)); }
        if (pc) { add_json_qword(json, sizeof(json), &first, "pool_gclass_base", *(uint64_t*)pc); add_json_qword(json, sizeof(json), &first, "pool_gclass_end", *(uint64_t*)(pc+16)); }
        if (pg) { add_json_qword(json, sizeof(json), &first, "pool_gmethod_base",*(uint64_t*)pg); add_json_qword(json, sizeof(json), &first, "pool_gmethod_end",*(uint64_t*)(pg+16)); }
    }
    strcat(json, "\n}\n");
    _snprintf(path, sizeof(path), "%s\\info.json", g_dir);
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) { DWORD wr; WriteFile(f, json, (DWORD)strlen(json), &wr, NULL); CloseHandle(f); }

    /* --- dumps --- */
    if (image_size)
        dump_range("module.bin", g_base, g_base + image_size);

    uint64_t pm = RD64(RVA_POOL_METADATA);
    uint64_t pc = RD64(RVA_POOL_GENCLASS);
    uint64_t pg = RD64(RVA_POOL_GENMETHOD);
    if (pm && *(uint64_t*)pm && *(uint64_t*)(pm+16) > *(uint64_t*)pm)
        dump_range("pool_metadata.bin",   *(uint64_t*)pm, *(uint64_t*)(pm+16));
    if (pc && *(uint64_t*)pc && *(uint64_t*)(pc+16) > *(uint64_t*)pc)
        dump_range("pool_genericclass.bin",*(uint64_t*)pc, *(uint64_t*)(pc+16));
    if (pg && *(uint64_t*)pg && *(uint64_t*)(pg+16) > *(uint64_t*)pg)
        dump_range("pool_genericmethod.bin",*(uint64_t*)pg,*(uint64_t*)(pg+16));

    /* --- raw global-metadata buffer --- */
    uint64_t c0 = RD64(RVA_GLOBAL_BUF_528);
    if (c0 > HEADER_SIZE_528 && c0 < 0x7FFFFFFFFFFFULL) {
        uint64_t raw = c0 - HEADER_SIZE_528;
        uint64_t fsize = RAW_META_SIZE;
        /* prefer the on-disk file size (hotupdates may change it) */
        {
            char mpath[MAX_PATH];
            _snprintf(mpath, sizeof(mpath), "%s\\Data\\Metadata\\global-metadata.dat", g_exedir);
            HANDLE hf = CreateFileA(mpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li;
                if (GetFileSizeEx(hf, &li) && li.QuadPart > 0x100000)
                    fsize = (uint64_t)li.QuadPart;
                CloseHandle(hf);
                logf_("on-disk global-metadata.dat size = %llu", (unsigned long long)fsize);
            } else {
                logf_("global-metadata.dat not found next to exe, using built-in size");
            }
        }
        if (readable(raw, 4096))
            dump_range("raw_global.bin", raw, raw + fsize);
        else
            logf_("raw global buffer at 0x%llX not readable, skipped", raw);
    } else {
        logf_("g_52C0 invalid (0x%llX), raw buffer skipped", c0);
    }

    /* --- il2cpp section (also inside module.bin, kept separate for clarity) --- */
    uint64_t slo = RD64(RVA_IL2CPP_SEC_LO), shi = RD64(RVA_IL2CPP_SEC_HI);
    if (slo && shi && shi > slo && shi - slo < 0x40000000ULL)
        dump_range("il2cpp_section.bin", slo, shi);

    /* done marker */
    _snprintf(path, sizeof(path), "%s\\DONE.txt", g_dir);
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    return 1;
}

// ---------------------------------------------------------------- thread ---

static DWORD WINAPI dump_thread(LPVOID arg)
{
    (void)arg;
    UNREFERENCED_PARAMETER(arg);

    /* resolve base + prepare output dir next to the game exe */
    g_base = (uint64_t)GetModuleHandleA(NULL);
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char* slash = strrchr(exe, '\\');
    if (slash) *slash = 0;
    lstrcpyA(g_exedir, exe);
    _snprintf(g_dir, sizeof(g_dir), "%s\\%s", exe, DUMP_DIRNAME);
    CreateDirectoryA(g_dir, NULL);
    _snprintf(g_log, sizeof(g_log), "%s\\gi_dump.log", g_dir);
    g_logf = CreateFileA(g_log, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    logf_("gi_dump attached, base=0x%llX, pid=%lu",
          g_base, (unsigned long)GetCurrentProcessId());

    /* game exes of this build hardcode 0x140000000 internally; if rebased the
       game itself would malfunction, so this must match */
    if (g_base != IMAGE_BASE_EXPECTED)
        logf_("WARNING: image base mismatch, RVAs still applied to actual base");

    int seen_loaded = 0;
    uint64_t t0 = GetTickCount64();
    for (;;) {
        uint64_t startup = RD64(RVA_STARTUP_PTR);
        uint64_t c0      = RD64(RVA_GLOBAL_BUF_528);

        /* manual trigger */
        char tpath[MAX_PATH];
        _snprintf(tpath, sizeof(tpath), "%s\\%s", g_dir, MANUAL_TRIGGER);
        if (GetFileAttributesA(tpath) != INVALID_FILE_ATTRIBUTES) {
            logf_("manual trigger detected");
            DeleteFileA(tpath);
            dump_everything();
            break;
        }

        /* normal path: observe startup ptr get loaded, then released */
        if (startup != 0 && startup != 0xFFFFFFFFFFFFFFFFULL) {
            if (!seen_loaded) { seen_loaded = 1; logf_("startup metadata loaded (0x%llX)", startup); }
        } else if (seen_loaded) {
            logf_("startup metadata released -> init complete, dumping");
            Sleep(200);                      /* let final writes settle */
            dump_everything();
            break;
        }

        /* late attach fallback: everything already done before we arrived */
        if (!seen_loaded && c0 != 0 && c0 != 0xFFFFFFFFFFFFFFFFULL &&
            startup == 0 && g_done == 0 &&
            GetTickCount64() - t0 > 30000) {
            uint64_t a0 = RD64(0x5AD52A0ULL);
            if (a0 != 0 && a0 != 0xFFFFFFFFFFFFFFFFULL) {
                logf_("late attach: init appears finished, dumping in %d ms",
                      LATE_ATTACH_GRACE);
                Sleep(LATE_ATTACH_GRACE);
                dump_everything();
                break;
            }
        }

        if (GetTickCount64() - t0 > AUTO_TIMEOUT_MS) {
            logf_("auto timeout, standing by for manual trigger file only");
            /* keep waiting for manual trigger forever */
            for (;;) {
                _snprintf(tpath, sizeof(tpath), "%s\\%s", g_dir, MANUAL_TRIGGER);
                if (GetFileAttributesA(tpath) != INVALID_FILE_ATTRIBUTES) {
                    DeleteFileA(tpath);
                    dump_everything();
                    goto out;
                }
                Sleep(250);
            }
        }
        Sleep(POLL_MS);
    }
out:
    InterlockedExchange(&g_done, 1);
    logf_("dump thread exiting");
    CloseHandle(g_logf);
    g_logf = NULL;
    return 0;
}

// --------------------------------------------------------------- dllmain ---

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        HANDLE t = CreateThread(NULL, 0, dump_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
