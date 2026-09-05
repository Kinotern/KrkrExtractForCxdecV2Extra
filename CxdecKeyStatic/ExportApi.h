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

// 让导出表同时包含无装饰名 "ExtractKey"，便于 GetProcAddress 直接按名字查找。
#pragma comment(linker, "/EXPORT:ExtractKey=_ExtractKey@16")

#ifdef __cplusplus
}
#endif
