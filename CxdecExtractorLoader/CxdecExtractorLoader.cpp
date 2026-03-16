#include <windows.h>
#include <commctrl.h>
#include <detours.h>
#include <string>

#include "loaderipc.h"
#include "path.h"
#include "util.h"
#include "directory.h"
#include "encoding.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "/MERGE:\".detourd=.data\"")
#pragma comment(linker, "/MERGE:\".detourc=.rdata\"")

#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

static std::wstring g_LoaderFullPath;
static std::wstring g_LoaderCurrentDirectory;
static std::wstring g_KrkrExeFullPath;
static std::wstring g_KrkrExeDirectory;

namespace
{
    void SetLoaderWindowHandleEnv(HWND hwnd)
    {
        std::wstring value = std::to_wstring((unsigned long long)(ULONG_PTR)hwnd);
        ::SetEnvironmentVariableW(LoaderIpc::LoaderWindowHandleEnvName, value.c_str());
    }

    void ClearLoaderWindowHandleEnv()
    {
        ::SetEnvironmentVariableW(LoaderIpc::LoaderWindowHandleEnvName, nullptr);
    }

    void SetProgressPercentText(HWND hwnd, unsigned int percent)
    {
        wchar_t text[16]{};
        wsprintfW(text, L"%u%%", percent);
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_KeyProgressText), text);
    }

    void ShowKeyProgressControls(HWND hwnd, bool visible)
    {
        int showMode = visible ? SW_SHOW : SW_HIDE;
        ::ShowWindow(::GetDlgItem(hwnd, IDC_KeyProgress), showMode);
        ::ShowWindow(::GetDlgItem(hwnd, IDC_KeyProgressText), showMode);
        ::ShowWindow(::GetDlgItem(hwnd, IDC_KeyProgressLabel), showMode);
    }

    void InitializeKeyProgressControls(HWND hwnd)
    {
        HWND progressBar = ::GetDlgItem(hwnd, IDC_KeyProgress);
        if (progressBar)
        {
            ::SendMessageW(progressBar, PBM_SETRANGE, 0u, MAKELPARAM(0, 100));
            ::SendMessageW(progressBar, PBM_SETPOS, 0u, 0u);
        }

        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_KeyProgressLabel), L"\x63D0\x53D6\x8FDB\x5EA6");
        SetProgressPercentText(hwnd, 0u);
    }

    void UpdateKeyProgressUi(HWND hwnd, unsigned int percent, const wchar_t* labelText)
    {
        if (percent > 100u)
        {
            percent = 100u;
        }

        HWND progressBar = ::GetDlgItem(hwnd, IDC_KeyProgress);
        if (progressBar)
        {
            ::SendMessageW(progressBar, PBM_SETPOS, (WPARAM)percent, 0u);
        }

        if (labelText)
        {
            ::SetWindowTextW(::GetDlgItem(hwnd, IDC_KeyProgressLabel), labelText);
        }

        SetProgressPercentText(hwnd, percent);
    }
}

INT_PTR CALLBACK LoaderDialogWindProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == LoaderIpc::ProgressMessage())
    {
        ShowKeyProgressControls(hwnd, true);
        UpdateKeyProgressUi(hwnd, (unsigned int)wParam, L"\x63D0\x53D6\x8FDB\x5EA6");
        return TRUE;
    }

    if (msg == LoaderIpc::CompletedMessage())
    {
        ShowKeyProgressControls(hwnd, true);
        UpdateKeyProgressUi(hwnd, 100u, L"\x63D0\x53D6\x5B8C\x6210");
        ::MessageBoxW(hwnd,
                      L"\x63D0\x53D6\x5B8C\x6210\xFF0C\x8BF7\x67E5\x770B\x76EE\x5F55\x3002",
                      L"CxdecExtractorLoader",
                      MB_OK | MB_ICONINFORMATION);
        ::PostMessageW(hwnd, WM_CLOSE, 0u, 0u);
        return TRUE;
    }

    switch (msg)
    {
        case WM_INITDIALOG:
        {
            InitializeKeyProgressControls(hwnd);
            ShowKeyProgressControls(hwnd, false);
            return TRUE;
        }
        case WM_COMMAND:
        {
            std::wstring injectDllFileName;
            bool shouldCloseLoaderAfterLaunch = true;

            switch (LOWORD(wParam))
            {
                case IDC_Extractor:
                    injectDllFileName = L"CxdecExtractorUI.dll";
                    break;
                case IDC_StringDumper:
                    injectDllFileName = L"CxdecStringDumper.dll";
                    break;
                case IDC_KeyDumper:
                    injectDllFileName = L"CxdecKeyDumper.dll";
                    shouldCloseLoaderAfterLaunch = false;
                    break;
            }

            if (!injectDllFileName.empty())
            {
                std::wstring injectDllFullPath = Path::Combine(g_LoaderCurrentDirectory, injectDllFileName);
                std::string injectDllFullPathA = Encoding::UnicodeToAnsi(injectDllFullPath, Encoding::CodePage::ACP);

                STARTUPINFOW si{};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};

                if (!shouldCloseLoaderAfterLaunch)
                {
                    SetLoaderWindowHandleEnv(hwnd);
                }

                if (DetourCreateProcessWithDllW(g_KrkrExeFullPath.c_str(),
                                                NULL,
                                                NULL,
                                                NULL,
                                                FALSE,
                                                0u,
                                                NULL,
                                                g_KrkrExeDirectory.c_str(),
                                                &si,
                                                &pi,
                                                injectDllFullPathA.c_str(),
                                                NULL))
                {
                    ::CloseHandle(pi.hThread);
                    ::CloseHandle(pi.hProcess);

                    if (shouldCloseLoaderAfterLaunch)
                    {
                        ::PostMessageW(hwnd, WM_CLOSE, 0u, 0u);
                    }
                    else
                    {
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_Extractor), FALSE);
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_StringDumper), FALSE);
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_KeyDumper), FALSE);
                        ShowKeyProgressControls(hwnd, true);
                        UpdateKeyProgressUi(hwnd, 0u, L"\x7B49\x5F85\x63D0\x53D6\x5F00\x59CB");
                        ::SetWindowTextW(hwnd, L"CxdecExtractorLoader - \x7B49\x5F85Key\x63D0\x53D6\x5B8C\x6210");
                    }
                }
                else
                {
                    if (!shouldCloseLoaderAfterLaunch)
                    {
                        ClearLoaderWindowHandleEnv();
                    }
                    ::MessageBoxW(hwnd,
                                  L"\x521B\x5EFA\x8FDB\x7A0B\x9519\x8BEF",
                                  L"\x9519\x8BEF",
                                  MB_OK | MB_ICONERROR);
                }
            }
            return TRUE;
        }
        case WM_CLOSE:
        {
            ::DestroyWindow(hwnd);
            return TRUE;
        }
        case WM_DESTROY:
        {
            ClearLoaderWindowHandleEnv();
            ::PostQuitMessage(0);
            return TRUE;
        }
    }

    return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nShowCmd);

    INITCOMMONCONTROLSEX commonControls{ sizeof(commonControls), ICC_PROGRESS_CLASS };
    ::InitCommonControlsEx(&commonControls);

    std::wstring loaderFullPath = Util::GetAppPathW();
    std::wstring loaderCurrentDirectory = Path::GetDirectoryName(loaderFullPath);
    std::wstring krkrExeFullPath;
    std::wstring krkrExeDirectory;

    {
        int argc = 0;
        LPWSTR* argv = ::CommandLineToArgvW(lpCmdLine, &argc);
        if (argc)
        {
            krkrExeFullPath = std::wstring(argv[0]);
            krkrExeDirectory = Path::GetDirectoryName(krkrExeFullPath);
        }
        ::LocalFree(argv);
    }

    g_LoaderFullPath = loaderFullPath;
    g_LoaderCurrentDirectory = loaderCurrentDirectory;
    g_KrkrExeFullPath = krkrExeFullPath;
    g_KrkrExeDirectory = krkrExeDirectory;

    if (!krkrExeFullPath.empty() && krkrExeFullPath != loaderFullPath)
    {
        HWND hwnd = ::CreateDialogParamW((HINSTANCE)hInstance, MAKEINTRESOURCEW(IDD_MainForm), NULL, LoaderDialogWindProc, 0u);
        ::ShowWindow(hwnd, SW_NORMAL);

        MSG msg{};
        while (BOOL ret = ::GetMessageW(&msg, NULL, 0u, 0u))
        {
            if (ret == -1)
            {
                return -1;
            }

            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }
    else
    {
        ::MessageBoxW(nullptr,
                      L"\x8BF7\x62D6\x62FD\x6E38\x620F\x4E3B\x7A0B\x5E8F\x5230\x542F\x52A8\x5668",
                      L"\x9519\x8BEF",
                      MB_OK | MB_ICONERROR);
    }

    return 0;
}
