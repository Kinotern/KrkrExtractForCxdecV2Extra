#include <Windows.h>
#include <Shlwapi.h>

#include "BatchExtractorUI.h"

#pragma comment(lib, "shlwapi.lib")

namespace
{
    constexpr size_t MaxPath = 1024u;
    UI::StartupContext g_Startup{};
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            constexpr const wchar_t CoreDllNameW[] = L"CxdecExtractor.dll";

            wchar_t moduleFullPath[MaxPath]{};
            ::GetModuleFileNameW(hModule, moduleFullPath, MaxPath);
            wchar_t* dllName = ::PathFindFileNameW(moduleFullPath);
            memcpy(dllName, CoreDllNameW, sizeof(CoreDllNameW));

            HMODULE coreBase = ::LoadLibraryW(moduleFullPath);
            if (!coreBase)
            {
                ::MessageBoxW(nullptr, L"CxdecExtractor.dll 加载失败", L"错误", MB_OK);
                break;
            }

            g_Startup.ModuleInstance = hModule;
            g_Startup.Api.Module = coreBase;
            g_Startup.Api.ExtractPackageEx = (tExtractPackageExProc)::GetProcAddress(coreBase, "ExtractPackageEx");
            g_Startup.Api.SetExtractProgressCallback = (tSetExtractProgressCallbackProc)::GetProcAddress(coreBase, "SetExtractProgressCallback");

            if (!g_Startup.Api.ExtractPackageEx || !g_Startup.Api.SetExtractProgressCallback)
            {
                ::MessageBoxW(nullptr, L"CxdecExtractor.dll 缺少批量解包接口", L"错误", MB_OK);
                break;
            }

            HANDLE thread = ::CreateThread(nullptr, 0u, UI::RunBatchExtractorUi, &g_Startup, 0u, nullptr);
            if (thread)
            {
                ::CloseHandle(thread);
            }
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void Dummy()
{
}

