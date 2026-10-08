#include "RuntimeHashUI.h"
#include "HashRestoreUI.h"
#include "logdir.h"
#include "utf8text.h"

#include <string>

namespace
{
    constexpr wchar_t RuntimeWindowClassName[] = L"CxdecRuntimeHashWindow";

    struct RuntimeUiContext
    {
        std::wstring GameDirectory;
        std::wstring TargetDirectory;
        std::wstring OutputDirectory;
        std::wstring LogDirectory;
    };

    std::wstring CombinePath(const std::wstring& directory, const std::wstring& fileName)
    {
        if (directory.empty())
        {
            return fileName;
        }
        if (directory.back() == L'\\' || directory.back() == L'/')
        {
            return directory + fileName;
        }
        return directory + L'\\' + fileName;
    }

    void WriteRuntimeLog(RuntimeUiContext* context, const std::wstring& message)
    {
        if (!context)
        {
            return;
        }
        ::CreateDirectoryW(context->LogDirectory.c_str(), nullptr);
        AppendUtf8Line(CombinePath(context->LogDirectory, L"RuntimeHashRestore.log"), message + L"\r\n");
    }

    std::wstring GetEnvironmentString(const wchar_t* name)
    {
        DWORD length = ::GetEnvironmentVariableW(name, nullptr, 0u);
        if (length == 0u)
        {
            return std::wstring();
        }

        std::wstring value(length, L'\0');
        DWORD copied = ::GetEnvironmentVariableW(name, value.data(), length);
        if (copied == 0u)
        {
            return std::wstring();
        }
        value.resize(copied);
        return value;
    }

    LRESULT CALLBACK RuntimeWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        RuntimeUiContext* context = (RuntimeUiContext*)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        switch (message)
        {
            case WM_CREATE:
            {
                CREATESTRUCTW* create = (CREATESTRUCTW*)lParam;
                context = (RuntimeUiContext*)create->lpCreateParams;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);
                WriteRuntimeLog(context, L"运行时恢复Hash映射模块窗口已创建");

                ::CreateWindowW(L"STATIC", L"运行时恢复Hash映射模块已加载", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                20, 18, 700, 22, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"STATIC", L"纯Hash目录", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                20, 52, 700, 18, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"EDIT", context->TargetDirectory.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY | WS_BORDER,
                                20, 72, 700, 24, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"STATIC", L"Hash映射输出", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                20, 108, 700, 18, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"EDIT", context->OutputDirectory.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY | WS_BORDER,
                                20, 128, 700, 24, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"STATIC", L"DirectoryHash.log / FileNameHash.log 会持续追加并自动去重。", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                20, 166, 700, 22, hwnd, nullptr, nullptr, nullptr);
                ::CreateWindowW(L"STATIC", L"运行日志：<工具目录>\\Log\\RuntimeHashRestore.log", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                20, 194, 700, 22, hwnd, nullptr, nullptr, nullptr);
                return 0;
            }
            case WM_CLOSE:
                WriteRuntimeLog(context, L"运行时恢复Hash映射模块窗口关闭");
                ::DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                delete context;
                ::PostQuitMessage(0);
                return 0;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    }

    DWORD WINAPI RuntimeUiThreadProc(LPVOID parameter)
    {
        RuntimeUiContext* context = (RuntimeUiContext*)parameter;

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = RuntimeWindowProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        windowClass.lpszClassName = RuntimeWindowClassName;
        ::RegisterClassExW(&windowClass);

        HWND hwnd = ::CreateWindowExW(0,
                                      RuntimeWindowClassName,
                                      L"Cxdec 运行时Hash映射恢复",
                                      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                      CW_USEDEFAULT,
                                      CW_USEDEFAULT,
                                      760,
                                      270,
                                      nullptr,
                                      nullptr,
                                      windowClass.hInstance,
                                      context);
        if (!hwnd)
        {
            WriteRuntimeLog(context, L"运行时恢复Hash映射模块窗口创建失败");
            delete context;
            return 0;
        }

        ::ShowWindow(hwnd, SW_SHOW);
        ::UpdateWindow(hwnd);

        MSG msg{};
        while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        return 0;
    }
}

namespace Engine
{
    void RuntimeHashUI::Start(HMODULE moduleHandle, const std::wstring& gameDirectory)
    {
        UNREFERENCED_PARAMETER(moduleHandle);

        RuntimeUiContext* context = new RuntimeUiContext{};
        context->GameDirectory = gameDirectory;
        context->TargetDirectory = GetEnvironmentString(L"CXDEC_RUNTIME_HASH_TARGET_DIR");
        if (context->TargetDirectory.empty())
        {
            context->TargetDirectory = gameDirectory;
        }
        context->OutputDirectory = CombinePath(gameDirectory, L"StringHashDumper_Output");
        // 会话日志统一到 <工具根>\Log\，跟解包器、Loader 那些写同一处；
        // 纯Hash目录下不再留 Extractor_Log（那边只剩 HashRestore 的报表产物）。
        context->LogDirectory = Log::ResolveLogDirectoryFromCallerModule(
                                   reinterpret_cast<const void*>(&RuntimeHashUI::Start))
                                   .path;

        ::CreateDirectoryW(context->LogDirectory.c_str(), nullptr);
        WriteRuntimeLog(context, L"运行时恢复Hash映射模块已加载");
        WriteRuntimeLog(context, L"纯Hash目录: " + context->TargetDirectory);
        WriteRuntimeLog(context, L"Hash映射输出目录: " + context->OutputDirectory);
        WriteRuntimeLog(context, L"运行日志目录: " + context->LogDirectory);

        HashRestoreUI::Start(moduleHandle, gameDirectory, context->TargetDirectory, false);
        delete context;
    }
}
