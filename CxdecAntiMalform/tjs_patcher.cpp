#include "tjs_patcher.h"
#include "tjs2_parser.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
static void TjsLog(const wchar_t* fmt, ...) {
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
        GetModuleHandleExW(6, (LPCWSTR)&TjsLog, &_hMod);
        GetModuleFileNameW(_hMod, _logPath, MAX_PATH);
        wchar_t* _bs = wcsrchr(_logPath, L'\\');
        if (_bs) *(_bs+1) = 0;
        wcscat_s(_logPath, L"CxdecAntiMalform.log");
    }
    _wfopen_s(&f, _logPath, L"a");
}
    if (f) { fwprintf(f, L"%s\n", buf); fflush(f); fclose(f); }
}


namespace TjsPatcher {

bool IsTjs2Bytecode(const uint8_t* data, size_t size) {
    return Tjs2Parser::IsTjs2(data, size);
}

// TJS2 VM opcodes
constexpr int32_t VM_TF    = 6;
constexpr int32_t VM_TT    = 5;
constexpr int32_t VM_CALL  = 99;
constexpr int32_t VM_CALLD = 100;
constexpr int32_t VM_DOT   = 103;

// The actual method name whose post-call branch we flip.
// "checkSignature" is a red herring — it does not appear in the _bootStrap context.
// The real target is "archiveUniqueKey": the engine calls it to verify the
// archive's embedded signature key, then branches on the result with VM_TF/VM_TT.
static const char* kPatchTarget = "archiveUniqueKey";

PatchedData PatchBytecode(const uint8_t* data, size_t size) {
    PatchedData result;
    result.bytes.assign(data, data + size);
    result.modified = false;
    result.patchesApplied = 0;

    Tjs2Parser::ByteCode bc = Tjs2Parser::Parse(data, size);
    TjsLog(L"[TJS] Parse: valid=%d ctx=%zu", (int)bc.valid, bc.contexts.size());
    if (!bc.valid) {
        TjsLog(L"[TJS] parse FAILED");
        return result;
    }

    for (const auto& ctx : bc.contexts) {
        TjsLog(L"[TJS] ctx='%hs' code=%zu rawOff=0x%zX", ctx.name.c_str(), ctx.code.size(), ctx.rawCodeOffset);
        const auto& code    = ctx.code;
        const auto& strings = bc.strings; // global string pool

        if (code.size() < 5) continue;

        // Search for VM_DOT referencing "archiveUniqueKey".
        // This is the method the engine calls to verify archive signature.
        // The VM_TF/VM_TT branch immediately after VM_CALL/VM_CALLD is
        // the conditional we need to flip (TF->TT) to bypass the check.
        // A context may contain multiple such calls; patch ALL of them.
        for (size_t i = 0; i + 4 < code.size(); ++i) {
            if (code[i] != VM_DOT) continue;
            // VM_DOT layout: opcode(i), dst(i+1), obj(i+2), name_idx(i+3)
            int32_t idx1 = code[i + 3];  // name_idx -> global string pool
            if (idx1 < 0 || idx1 >= (int32_t)strings.size()) continue;
            const std::string& name1 = strings[idx1];

            if (_stricmp(name1.c_str(), kPatchTarget) != 0) continue;

            TjsLog(L"[TJS] Found %hs at code[%zu] strIdx=%d ctx=%hs",
                kPatchTarget, i, idx1, ctx.name.c_str());

            // Scan forward for VM_CALL / VM_CALLD within a small window.
            for (size_t j = i + 4; j + 2 < code.size() && j < i + 30; ++j) {
                if (code[j] != VM_CALL && code[j] != VM_CALLD) continue;
                TjsLog(L"[TJS] VM_CALL at code[%zu] ctx=%hs", j, ctx.name.c_str());

                // Scan forward for the conditional branch to flip.
                for (size_t k = j + 2; k < code.size() && k < j + 18; ++k) {
                    if (code[k] == VM_TF || code[k] == VM_TT) {
                        size_t byteOff = ctx.rawCodeOffset + (k * 2);
                        int32_t newOp = (code[k] == VM_TF) ? VM_TT : VM_TF;
                        result.bytes[byteOff]     = (uint8_t)(newOp & 0xFF);
                        result.bytes[byteOff + 1] = (uint8_t)((newOp >> 8) & 0xFF);
                        result.modified = true;
                        result.patchesApplied++;
                        result.patchOffsets.push_back(byteOff);
                        wchar_t _dbg2[256];
                        swprintf_s(_dbg2, L"[TJS] PATCH ctx=%hs rawOff=0x%zX code[%zu] op %d->%d",
                            ctx.name.c_str(), byteOff, k, (int)code[k], (int)newOp);
                        TjsLog(_dbg2);
                        // Do NOT break/goto — keep scanning for more occurrences
                        // in this context (e.g. _bootStrap has two checkSignature calls).
                        break; // only one branch per VM_CALL, then keep outer i-loop going
                    }
                }
                break; // only one VM_CALL per VM_DOT
            }
        }
    }

    TjsLog(L"[TJS] PatchBytecode done: modified=%d patches=%d",
        result.modified, result.patchesApplied);
    return result;
}

} // namespace TjsPatcher
