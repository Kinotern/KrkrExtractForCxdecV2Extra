#include "Application.h"
#include "ExtractApi.h"

#include "TryExport.h"

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

// 这个 DLL 是注入到游戏里的，异常穿出去会把游戏一起带走，所以导出体一律套兜底。
// 失败提示沿用本模块原有的 MessageBoxW。
namespace
{
    void ReportExportFailure(const std::string& message)
    {
        const std::wstring wide = ExportGuard::WideFromUtf8(message);
        ::MessageBoxW(nullptr, wide.c_str(), L"错误", MB_OK);
    }
}

// 兼容旧界面的单包解包接口
extern "C" __declspec(dllexport) void WINAPI ExtractPackage(const wchar_t* packageName)
{
    ExportGuard::Run(
        [](const std::string& m) { ReportExportFailure(m); },
        [&]() -> bool
        {
            if (!packageName)
            {
                ::MessageBoxW(nullptr, L"封包路径为空", L"错误", MB_OK);
                return false;
            }

            const bool success =
                Engine::Application::GetInstance()->GetExtractor()->ExtractPackage(packageName);
            if (success)
            {
                ::MessageBoxW(nullptr, (std::wstring(packageName) + L" 提取成功").c_str(), L"信息",
                              MB_OK);
            }
            else
            {
                ::MessageBoxW(nullptr, L"提取失败，请查看工具目录 Log 目录下的 Extractor.log", L"错误", MB_OK);
            }
            return success;
        });
}

extern "C" __declspec(dllexport) BOOL WINAPI ExtractPackageEx(const wchar_t* packagePath, const wchar_t* outputDirectory, unsigned int taskId)
{
    const bool ok = ExportGuard::Run(
        [](const std::string& m) { ReportExportFailure(m); },
        [&]() -> bool
        {
            if (!packagePath)
            {
                return false;
            }

            return Engine::Application::GetInstance()->GetExtractor()->ExtractPackageTo(
                packagePath, outputDirectory ? outputDirectory : L"", taskId);
        });
    return ok ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) void WINAPI SetExtractProgressCallback(Engine::tExtractProgressCallback callback, void* context)
{
    ExportGuard::Run(
        [](const std::string& m) { ReportExportFailure(m); },
        [&]() -> bool
        {
            Engine::Application::GetInstance()->GetExtractor()->SetProgressCallback(callback,
                                                                                    context);
            return true;
        });
}

