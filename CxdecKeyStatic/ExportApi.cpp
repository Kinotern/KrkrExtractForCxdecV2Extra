#include "ExportApi.h"
#include "TryExport.h"

#include <cstring>

BOOL __stdcall ExtractKey(const wchar_t* exePath, const wchar_t* outputDir,
                           char* errorOut, int errorOutSize) {
    if (!exePath || !outputDir) {
        if (errorOut && errorOutSize > 0)
            errorOut[0] = 0;
        return FALSE;
    }
    const bool ok = ExportGuard::Run(
        [&](const std::string& m) { ExportGuard::WriteAnsi(m, errorOut, errorOutSize); },
        [&]() -> bool {
            Engine::GameParams params;
            std::string error;
            const bool recovered = Engine::recover_drip_program(exePath, outputDir, params, &error);
            if (!recovered && errorOut && errorOutSize > 0) {
                strncpy_s(errorOut, errorOutSize, error.c_str(), errorOutSize - 1);
            }
            return recovered;
        });
    return ok ? TRUE : FALSE;
}
