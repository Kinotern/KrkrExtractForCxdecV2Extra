#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

namespace Engine
{
    enum ExtractTaskState : unsigned int
    {
        ExtractTaskQueued = 0,
        ExtractTaskPreparing = 1,
        ExtractTaskIndexLoaded = 2,
        ExtractTaskExtracting = 3,
        ExtractTaskCompleted = 4,
        ExtractTaskFailed = 5
    };

    using tExtractProgressCallback = void (WINAPI*)(
        unsigned int taskId,
        const wchar_t* packagePath,
        unsigned int state,
        unsigned int current,
        unsigned int total,
        const wchar_t* detail,
        void* context);
}

using tExtractPackageProc = void (WINAPI*)(const wchar_t* packageName);
using tExtractPackageExProc = BOOL (WINAPI*)(const wchar_t* packagePath, const wchar_t* outputDirectory, unsigned int taskId);
using tSetExtractProgressCallbackProc = void (WINAPI*)(Engine::tExtractProgressCallback callback, void* context);
