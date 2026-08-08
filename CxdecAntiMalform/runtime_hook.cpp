#include "runtime_hook.h"
#include "tjs_patcher.h"
#include "kmp_search.h"
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <shlwapi.h>
#include <detours.h>
#//pragma comment(lib, "detours.lib")

namespace {

static void AmLog(const wchar_t* fmt, ...) {
    wchar_t buf[512];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, args);
    va_end(args);
    OutputDebugStringW(buf);
    FILE* f = nullptr;
    {
    static wchar_t _logPath[MAX_PATH] = {0};
    if (!_logPath[0]) {
        HMODULE _hMod = NULL;
        GetModuleHandleExW(6, (LPCWSTR)&AmLog, &_hMod); // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|UNCHANGED_REFCOUNT
        GetModuleFileNameW(_hMod, _logPath, MAX_PATH);
        wchar_t* _bs = wcsrchr(_logPath, L'\\');
        if (_bs) *(_bs+1) = 0;
        wcscat_s(_logPath, L"CxdecAntiMalform.log");
    }
    _wfopen_s(&f, _logPath, L"a");
}
    if (f) { fwprintf(f, L"%s\n", buf); fflush(f); fclose(f); }
}

const uint8_t kHookPattern[] = { 0x55, 0x8B, 0xEC, 0xF6, 0x45, 0x2A, 0x2A, 0x74 };
const uint8_t kHookMask[]    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF };
const size_t  kHookPatternLen = 8;

typedef void* (__cdecl *HookTargetFn)(int, int, int);

struct TjsStreamVtbl {
    int64_t  (__cdecl *Seek)(void* stream, int64_t offset, int whence);
    uint32_t (__cdecl *Read)(void* stream, void* buf, uint32_t size);
    uint32_t (__cdecl *Write)(void* stream, const void* buf, uint32_t size, int reserved);
    void     (__cdecl *SetEndOfStorage)(void* stream);
    uint64_t (__cdecl *GetSize)(void* stream);
};

struct TjsStream {
    TjsStreamVtbl* vtable;
    uint8_t _pad[0x0C];
    TjsStream* writeTarget;
};

static void* FindHookTarget() {
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (!hMod) return nullptr;
    auto* base = reinterpret_cast<const uint8_t*>(hMod);
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    const uint8_t* end = base + imageSize - kHookPatternLen;
    for (const uint8_t* p = base; p <= end; ++p) {
        bool match = true;
        for (size_t i = 0; i < kHookPatternLen; ++i) {
            if (kHookMask[i] == 0) continue;
            if (p[i] != kHookPattern[i]) { match = false; break; }
        }
        if (match) return const_cast<uint8_t*>(p);
    }
    return nullptr;
}

static HookTargetFn g_originalFn = nullptr;
static bool         g_hookInstalled = false;

// --------------- Helpers --------------------------------------------------

static uint8_t* ReadFileToBuf(const wchar_t* path, size_t* outSize) {
    *outSize = 0;
    FILE* f = nullptr;
    _wfopen_s(&f, path, L"rb");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return nullptr; }
    auto* buf = static_cast<uint8_t*>(malloc(sz));
    if (!buf) { fclose(f); return nullptr; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return nullptr; }
    fclose(f);
    *outSize = sz;
    return buf;
}

static ptrdiff_t KmpFindPos(const uint8_t* haystack, size_t haySize,
                              const uint8_t* needle, size_t needleSize) {
    const uint8_t* found = Kmp::Search(haystack, haySize, needle, needleSize);
    if (!found) return -1;
    return found - haystack;
}

// Differential XOR patch: EXE[pos+i] ^= needle[i] ^ replacement[i]
// Bytes where needle==replacement are unchanged (XOR 0).
// Bytes where they differ get the XOR delta applied.
static bool KmpDiffPatch(uint8_t* haystack, size_t haySize,
                         const uint8_t* needle, size_t needleSize,
                         const uint8_t* replacement, size_t replSize) {
    ptrdiff_t pos = KmpFindPos(haystack, haySize, needle, needleSize);
    if (pos < 0) return false;
    if (pos + (ptrdiff_t)replSize > (ptrdiff_t)haySize) return false;
    for (size_t i = 0; i < replSize; i++) {
        haystack[pos + i] ^= needle[i] ^ replacement[i];
    }
    return true;
}

// Simple memcpy KMP replace (for 1-byte steam patch)
static bool KmpMemcpyPatch(uint8_t* haystack, size_t haySize,
                           const uint8_t* needle, size_t needleSize,
                           const uint8_t* replacement, size_t replSize) {
    ptrdiff_t pos = KmpFindPos(haystack, haySize, needle, needleSize);
    if (pos < 0) return false;
    if (pos + (ptrdiff_t)replSize > (ptrdiff_t)haySize) return false;
    std::memcpy(haystack + pos, replacement, replSize);
    return true;
}

// --------------- PatchAndWrite ----------------------------------------------
// origTjs (v5)    = encrypted original TJS -> KMP needle
// patchedTjs       = encrypted patched TJS   -> KMP replacement
static bool PatchAndWrite(const wchar_t* origPath, const wchar_t* crackPath,
                          const uint8_t* origTjs, size_t origTjsSize,
                          const uint8_t* patchedTjs, size_t patchedTjsSize) {
    size_t exeSize = 0;
    uint8_t* exeData = ReadFileToBuf(origPath, &exeSize);
    if (!exeData) {
        MessageBoxW(nullptr,
            L"ERROR: Failed to read original executable file.",
            L"AntiMalform", MB_ICONERROR);
        return false;
    }

    if (!KmpDiffPatch(exeData, exeSize, origTjs, origTjsSize, patchedTjs, patchedTjsSize)) {
        MessageBoxW(nullptr,
            L"WARNING: Startup TJS patch not applied.",
            L"AntiMalform", MB_ICONWARNING);
    }

    {
        const char steamStr[] = "steam=\"yes\"";
        const char steamRepl  = 'r';
        if (!KmpMemcpyPatch(exeData, exeSize,
                            reinterpret_cast<const uint8_t*>(steamStr), sizeof(steamStr) - 1,
                            reinterpret_cast<const uint8_t*>(&steamRepl), 1)) {
            MessageBoxW(nullptr,
                L"WARNING: Steam patch not applied.",
                L"AntiMalform", MB_ICONWARNING);
        }
    }

    FILE* f = nullptr;
    _wfopen_s(&f, crackPath, L"wb");
    if (!f || fwrite(exeData, 1, exeSize, f) != exeSize) {
        if (f) fclose(f);
        MessageBoxW(nullptr,
            L"ERROR: Failed to write patched executable file.",
            L"AntiMalform", MB_ICONERROR);
        free(exeData);
        return false;
    }
    fclose(f);
    free(exeData);
    return true;
}

// PatchAndDump - decrypt, patch bytecode, write back, generate _crack.exe.
static void __cdecl PatchAndDump(TjsStream* stream) {
    AmLog(L"[AntiMalform] PatchAndDump: stream=0x%p", stream);

    // All heap allocations are declared up-front so the cleanup label can
    // free them unconditionally (free(nullptr) is always safe).
    uint8_t* blockDec     = nullptr;
    uint8_t* blockDecOrig = nullptr;
    uint8_t* v5enc        = nullptr;
    uint8_t* v5encPatched = nullptr;
    TjsStream* savedWt    = nullptr;
    bool ok               = false;

    AmLog(L"[AntiMalform] A: calling GetSize...");
    uint64_t rawSize = stream->vtable->GetSize(stream);
    AmLog(L"[AntiMalform] B: GetSize=%llu", rawSize);
    if (rawSize == 0 || rawSize > 10 * 1024 * 1024) {
        AmLog(L"[AntiMalform] Invalid size %llu", rawSize);
        return;
    }
    int dataSize = (int)rawSize;
    AmLog(L"[AntiMalform] C: dataSize=%d", dataSize);

    // Step 2: First Read -> Block (decrypted, for analysis)
    blockDec = (uint8_t*)malloc(dataSize);
    if (!blockDec) { AmLog(L"D: alloc fail"); return; }
    stream->vtable->Read(stream, blockDec, (uint32_t)dataSize);
    AmLog(L"[AntiMalform] E: Read1 OK, size=%d", dataSize);
    stream->vtable->Seek(stream, 0, 0);
    AmLog(L"[AntiMalform] F: Seek1 OK");

    // Save decrypted original before patching (needed for Delta computation)
    blockDecOrig = (uint8_t*)malloc(dataSize);
    if (!blockDecOrig) { AmLog(L"G: orig alloc fail"); goto cleanup; }
    std::memcpy(blockDecOrig, blockDec, dataSize);
    AmLog(L"[AntiMalform] G: orig saved");

    // Step 3-5: Second Read -> v5 (encrypted, writeTarget=0)
    savedWt = *(TjsStream**)((uint8_t*)stream + 0x10);
    *(TjsStream**)((uint8_t*)stream + 0x10) = nullptr;
    AmLog(L"[AntiMalform] H: writeTarget=0, alloc v5enc...");

    v5enc = (uint8_t*)malloc(dataSize);
    if (!v5enc) {
        AmLog(L"I: v5enc alloc fail");
        *(TjsStream**)((uint8_t*)stream + 0x10) = savedWt;
        goto cleanup;
    }
    stream->vtable->Read(stream, v5enc, (uint32_t)dataSize);
    AmLog(L"[AntiMalform] J: Read2 OK");
    stream->vtable->Seek(stream, 0, 0);
    AmLog(L"[AntiMalform] K: Seek2 OK");
    *(TjsStream**)((uint8_t*)stream + 0x10) = savedWt;
    AmLog(L"[AntiMalform] L: writeTarget restored");

    // Step 6: Parse & patch decrypted Block
    {
        auto patchResult = TjsPatcher::PatchBytecode(blockDec, dataSize);
        AmLog(L"[AntiMalform] M: patch done, mod=%d pat=%d", patchResult.modified, patchResult.patchesApplied);

        if (patchResult.modified) {
            // Sanity: patched buffer must be the same size as input.
            if (patchResult.bytes.size() != (size_t)dataSize) {
                AmLog(L"[AntiMalform] ERROR: PatchBytecode returned wrong size %zu (expected %d)",
                        patchResult.bytes.size(), dataSize);
                goto write_runtime;
            }
            std::memcpy(blockDec, patchResult.bytes.data(), dataSize);
            AmLog(L"[AntiMalform] TJS patched: %d patches", patchResult.patchesApplied);
        }
    }

    // Step 7: Build encrypted patched version
    //   For each byte where decrypted changed: apply Delta to encrypted
    //   Delta = blockDecOrig[i] ^ blockDec[i]  (= 3 for VM_TF<->VM_TT)
    v5encPatched = (uint8_t*)malloc(dataSize);
    if (!v5encPatched) {
        AmLog(L"[AntiMalform] ERROR: v5encPatched alloc fail — crack.exe will NOT be generated");
        // Still write the decrypted patch to the runtime stream (Step 8).
        goto write_runtime;
    }
    std::memcpy(v5encPatched, v5enc, dataSize);
    for (int i = 0; i < dataSize; i++) {
        uint8_t delta = blockDecOrig[i] ^ blockDec[i];
        if (delta)
            v5encPatched[i] ^= delta;
    }

write_runtime:
    // Step 8: Write patched decrypted to writeTarget (for engine runtime)
    if (savedWt) {
        savedWt->vtable->Write(savedWt, blockDec, (uint32_t)dataSize, 0);
    }

    // Step 9: Generate _crack.exe (only if encrypted patched buffer exists)
    if (v5encPatched) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t crackPath[MAX_PATH];
        wcscpy_s(crackPath, exePath);
        PathRemoveExtensionW(crackPath);
        size_t _len = wcslen(crackPath);
        if (_len > 4 && _wcsicmp(crackPath + _len - 4, L"_unp") == 0)
            crackPath[_len - 4] = L'\0';
        wcscat_s(crackPath, L"_crack");
        wcscat_s(crackPath, L".exe");

        // KMP needle      = v5enc (encrypted original, matches EXE's .rsrc data)
        // KMP replacement = v5encPatched (encrypted with Delta applied)
        ok = PatchAndWrite(exePath, crackPath, v5enc, dataSize, v5encPatched, dataSize);
    }

cleanup:
    free(blockDec);
    free(blockDecOrig);
    free(v5enc);
    free(v5encPatched);

    if (ok) {
        OutputDebugStringW(L"[AntiMalform] _crack.exe created");
        ExitProcess(0);
    }
}

// Hook callback
static void* __cdecl HookCallback(int a1, int a2, int a3) {
    void* result = g_originalFn(a1, a2, a3);

    const wchar_t* scriptPath = *(const wchar_t**)(*(DWORD*)a2 + 4);
    if (!scriptPath)
        scriptPath = (const wchar_t*)(*(DWORD*)a2 + 8);

    if (wcsstr(scriptPath, L"startup.tjs")) {
        PatchAndDump((TjsStream*)result);
    }
    return result;
}

// =====================================================================
// Public API
// =====================================================================
} // namespace

bool InstallRuntimeHook() {
    void* target = FindHookTarget();
    if (!target) {
        OutputDebugStringW(L"[AntiMalform] Hook target not found");
        return false;
    }
    g_originalFn = (HookTargetFn)target;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)g_originalFn, HookCallback);
    LONG err = DetourTransactionCommit();
    if (err == NO_ERROR) { g_hookInstalled = true; return true; }
    return false;
}

void RemoveRuntimeHook() {
    if (!g_hookInstalled) return;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)g_originalFn, HookCallback);
    DetourTransactionCommit();
    g_hookInstalled = false;
}
