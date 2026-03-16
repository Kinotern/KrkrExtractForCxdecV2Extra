#include "Application.h"
#include "ExtractApi.h"

#pragma comment(linker, "/MERGE:\".detourd=.data\"")
#pragma comment(linker, "/MERGE:\".detourc=.rdata\"")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            Engine::Application::Initialize(hModule);
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
        {
            Engine::Application::Release();
            break;
        }
    }
    return TRUE;
}

/// <summary>
/// 兼容旧界面的单包解包接口
/// </summary>
extern "C" __declspec(dllexport) void WINAPI ExtractPackage(const wchar_t* packageName)
{
    if (!packageName)
    {
        ::MessageBoxW(nullptr, L"封包路径为空", L"错误", MB_OK);
        return;
    }

    bool success = Engine::Application::GetInstance()->GetExtractor()->ExtractPackage(packageName);
    if (success)
    {
        ::MessageBoxW(nullptr, (std::wstring(packageName) + L" 提取成功").c_str(), L"信息", MB_OK);
    }
    else
    {
        ::MessageBoxW(nullptr, L"提取失败，请查看 Extractor.log", L"错误", MB_OK);
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI ExtractPackageEx(const wchar_t* packagePath, const wchar_t* outputDirectory, unsigned int taskId)
{
    if (!packagePath)
    {
        return FALSE;
    }

    return Engine::Application::GetInstance()->GetExtractor()->ExtractPackageTo(packagePath,
                                                                                 outputDirectory ? outputDirectory : L"",
                                                                                 taskId)
               ? TRUE
               : FALSE;
}

extern "C" __declspec(dllexport) void WINAPI SetExtractProgressCallback(Engine::tExtractProgressCallback callback, void* context)
{
    Engine::Application::GetInstance()->GetExtractor()->SetProgressCallback(callback, context);
}

