#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include "../CxdecExtractor/ExtractApi.h"

namespace UI
{
    struct CoreApi
    {
        HMODULE Module;
        tExtractPackageExProc ExtractPackageEx;
        tSetExtractProgressCallbackProc SetExtractProgressCallback;
    };

    struct StartupContext
    {
        HINSTANCE ModuleInstance;
        CoreApi Api;
    };

    DWORD WINAPI RunBatchExtractorUi(LPVOID parameter);
}
