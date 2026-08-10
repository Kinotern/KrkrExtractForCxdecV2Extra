#pragma once
#include <windows.h>
#include "CxdecRecover.h"

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) BOOL __stdcall ExtractKey(
    const wchar_t* exePath,
    const wchar_t* outputDir,
    char* errorOut,
    int errorOutSize);

#ifdef __cplusplus
}
#endif
