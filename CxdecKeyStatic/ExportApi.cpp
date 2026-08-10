#include "ExportApi.h"
#include <cstring>

BOOL __stdcall ExtractKey(const wchar_t* exePath, const wchar_t* outputDir,
                           char* errorOut, int errorOutSize) {
    if (!exePath || !outputDir) {
        if (errorOut && errorOutSize > 0)
            errorOut[0] = 0;
        return FALSE;
    }
    Engine::GameParams params;
    std::string error;
    bool ok = Engine::recover_drip_program(exePath, outputDir, params, &error);
    if (!ok && errorOut && errorOutSize > 0) {
        strncpy_s(errorOut, errorOutSize, error.c_str(), errorOutSize - 1);
    }
    return ok ? TRUE : FALSE;
}
