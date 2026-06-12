#include <windows.h>
#include <commctrl.h>
#include <detours.h>
#include <ShObjIdl.h>
#include <ShlObj.h>
#include <algorithm>
#include <cstdarg>
#include <cwctype>
#include <string>
#include <unordered_set>
#include <vector>

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
    constexpr wchar_t RuntimeHashTargetDirectoryEnvName[] = L"CXDEC_RUNTIME_HASH_TARGET_DIR";
    constexpr wchar_t HashCrackOutputDirectoryEnvName[] = L"CXDEC_HASH_CRACK_OUTPUT_DIR";
    constexpr wchar_t HashCrackDirsFileEnvName[] = L"CXDEC_HASH_CRACK_DIRS_FILE";
    constexpr wchar_t HashCrackFilesFileEnvName[] = L"CXDEC_HASH_CRACK_FILES_FILE";
    constexpr wchar_t HashCrackPureHashDirectoryEnvName[] = L"CXDEC_HASH_CRACK_PURE_HASH_DIR";
    constexpr wchar_t HashCrackSupplementalMapEnvName[] = L"CXDEC_HASH_CRACK_SUPPLEMENTAL_MAP";
    constexpr wchar_t HashCrackSuppressRestoreUiEnvName[] = L"CXDEC_HASH_CRACK_SUPPRESS_RESTORE_UI";
    constexpr wchar_t HookHashDialogClassName[] = L"CxdecHookHashRestorePrepareWindow";
    constexpr int IDC_HOOK_PURE_EDIT = 3101;
    constexpr int IDC_HOOK_PURE_BROWSE = 3102;
    constexpr int IDC_HOOK_OUTPUT_EDIT = 3103;
    constexpr int IDC_HOOK_OUTPUT_BROWSE = 3104;
    constexpr int IDC_HOOK_SUPPLEMENT_EDIT = 3105;
    constexpr int IDC_HOOK_SUPPLEMENT_BROWSE = 3106;
    constexpr int IDC_HOOK_DIRS_EDIT = 3107;
    constexpr int IDC_HOOK_DIRS_BROWSE = 3108;
    constexpr int IDC_HOOK_FILES_EDIT = 3109;
    constexpr int IDC_HOOK_FILES_BROWSE = 3110;
    constexpr int IDC_HOOK_MAKE_CANDIDATE = 3111;
    constexpr int IDC_HOOK_RESCAN = 3112;
    constexpr int IDC_HOOK_SUMMARY = 3113;
    constexpr int IDC_HOOK_START = 3114;

    struct HookHashRestoreLaunchOptions
    {
        std::wstring PureHashDirectory;
        std::wstring OutputDirectory;
        std::wstring SupplementalMapPath;
        std::wstring DirsPath;
        std::wstring FilesPath;
    };

    std::wstring BrowseFolder(HWND owner, const wchar_t* title);

    std::wstring CombinePathLocal(const std::wstring& directory, const std::wstring& fileName)
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

    std::wstring GetFileNameLocal(const std::wstring& path)
    {
        size_t slash = path.find_last_of(L"\\/");
        return slash == std::wstring::npos ? path : path.substr(slash + 1u);
    }

    std::wstring GetParentDirectoryLocal(const std::wstring& path)
    {
        size_t slash = path.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
    }

    bool SamePathText(const std::wstring& left, const std::wstring& right)
    {
        return !left.empty() && !right.empty() && _wcsicmp(left.c_str(), right.c_str()) == 0;
    }

    bool FileExistsLocal(const std::wstring& path)
    {
        DWORD attributes = ::GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    std::wstring GetModuleDllPath(const std::wstring& dllFileName)
    {
        std::wstring modulePath = Path::Combine(Path::Combine(g_LoaderCurrentDirectory, L"CxdecExtractordll"), dllFileName);
        if (FileExistsLocal(modulePath))
        {
            return modulePath;
        }

        std::wstring fallbackPath = Path::Combine(g_LoaderCurrentDirectory, dllFileName);
        if (FileExistsLocal(fallbackPath))
        {
            return fallbackPath;
        }

        return modulePath;
    }

    std::wstring FormatString(const wchar_t* format, ...)
    {
        wchar_t buffer[2048]{};
        va_list ap;
        va_start(ap, format);
        int count = _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, ap);
        va_end(ap);
        if (count <= 0)
        {
            return std::wstring();
        }
        return std::wstring(buffer, count);
    }

    bool FindLatestFile(const std::wstring& directory, const std::wstring& pattern, std::wstring& latestPath, FILETIME& latestTime)
    {
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(CombinePathLocal(directory, pattern).c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        bool found = false;
        do
        {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                continue;
            }
            std::wstring name = data.cFileName;
            std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
            if (name.find(L"_match") != std::wstring::npos || name.find(L"_tmp") != std::wstring::npos)
            {
                continue;
            }

            if (!found || ::CompareFileTime(&data.ftLastWriteTime, &latestTime) > 0)
            {
                found = true;
                latestTime = data.ftLastWriteTime;
                latestPath = CombinePathLocal(directory, data.cFileName);
            }
        } while (::FindNextFileW(find, &data));

        ::FindClose(find);
        return found;
    }

    unsigned int CountTextLines(const std::wstring& path)
    {
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return 0u;
        }

        LARGE_INTEGER size{};
        if (!::GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 64ll * 1024ll * 1024ll)
        {
            ::CloseHandle(file);
            return 0u;
        }

        std::string bytes((size_t)size.QuadPart, '\0');
        DWORD read = 0u;
        BOOL ok = ::ReadFile(file, bytes.data(), (DWORD)bytes.size(), &read, nullptr);
        ::CloseHandle(file);
        if (!ok || read != bytes.size())
        {
            return 0u;
        }

        unsigned int lines = 0u;
        for (char ch : bytes)
        {
            if (ch == '\n')
            {
                ++lines;
            }
        }
        if (!bytes.empty() && bytes.back() != '\n')
        {
            ++lines;
        }
        return lines;
    }

    std::wstring MakeRelativePathLocal(const std::wstring& root, const std::wstring& path)
    {
        if (path.length() <= root.length())
        {
            return std::wstring();
        }

        size_t start = root.length();
        if (path[start] == L'\\' || path[start] == L'/')
        {
            ++start;
        }
        return path.substr(start);
    }

    void CollectCandidateNames(const std::wstring& root,
                               const std::wstring& directory,
                               std::unordered_set<std::wstring>& directoryNames,
                               std::unordered_set<std::wstring>& fileNames)
    {
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(CombinePathLocal(directory, L"*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return;
        }

        do
        {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            {
                continue;
            }
            if (_wcsicmp(data.cFileName, L"ExtractLog") == 0 || _wcsicmp(data.cFileName, L"Extractor_Log") == 0)
            {
                continue;
            }

            std::wstring fullPath = CombinePathLocal(directory, data.cFileName);
            std::wstring relative = MakeRelativePathLocal(root, fullPath);
            std::replace(relative.begin(), relative.end(), L'\\', L'/');
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (!relative.empty())
                {
                    directoryNames.insert(relative);
                }
                CollectCandidateNames(root, fullPath, directoryNames, fileNames);
            }
            else if (!relative.empty())
            {
                fileNames.insert(relative);
                size_t slash = relative.find_last_of(L'/');
                fileNames.insert(slash == std::wstring::npos ? relative : relative.substr(slash + 1u));
            }
        } while (::FindNextFileW(find, &data));

        ::FindClose(find);
    }

    std::vector<std::wstring> SortedCandidateLines(const std::unordered_set<std::wstring>& values)
    {
        std::vector<std::wstring> lines(values.begin(), values.end());
        std::sort(lines.begin(), lines.end(), [](const std::wstring& left, const std::wstring& right)
        {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        });
        return lines;
    }

    bool WriteUtf16LinesLocal(const std::wstring& path, const std::vector<std::wstring>& lines)
    {
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        WORD bom = 0xFEFF;
        DWORD written = 0u;
        ::WriteFile(file, &bom, sizeof(bom), &written, nullptr);
        for (const std::wstring& line : lines)
        {
            ::WriteFile(file, line.c_str(), (DWORD)(line.length() * sizeof(wchar_t)), &written, nullptr);
            ::WriteFile(file, L"\r\n", 4u, &written, nullptr);
        }
        ::CloseHandle(file);
        return true;
    }

    std::wstring GetTimestampStringLocal()
    {
        SYSTEMTIME time{};
        ::GetLocalTime(&time);
        return FormatString(L"%04u_%02u_%02u_%02u_%02u_%02u", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    }

    bool MakeCandidateLists(HWND owner, HookHashRestoreLaunchOptions& options)
    {
        std::wstring sourceDirectory = BrowseFolder(owner, L"选择用于制作候选lst的明文资源目录");
        if (sourceDirectory.empty())
        {
            return false;
        }
        if (options.OutputDirectory.empty())
        {
            options.OutputDirectory = CombinePathLocal(g_KrkrExeDirectory, L"StringHashDumper_Output");
        }
        ::SHCreateDirectoryExW(owner, options.OutputDirectory.c_str(), nullptr);

        std::unordered_set<std::wstring> directoryNames;
        std::unordered_set<std::wstring> fileNames;
        directoryNames.insert(L"/");
        CollectCandidateNames(sourceDirectory, sourceDirectory, directoryNames, fileNames);

        std::wstring stamp = GetTimestampStringLocal();
        options.DirsPath = CombinePathLocal(options.OutputDirectory, L"dirs_" + stamp + L".txt");
        options.FilesPath = CombinePathLocal(options.OutputDirectory, L"files_" + stamp + L".txt");
        return WriteUtf16LinesLocal(options.DirsPath, SortedCandidateLines(directoryNames))
            && WriteUtf16LinesLocal(options.FilesPath, SortedCandidateLines(fileNames));
    }

    void ScanLatestHookCandidates(HookHashRestoreLaunchOptions& options)
    {
        if (options.OutputDirectory.empty())
        {
            options.OutputDirectory = CombinePathLocal(g_KrkrExeDirectory, L"StringHashDumper_Output");
        }

        FILETIME latestDirsTime{};
        FILETIME latestFilesTime{};
        FindLatestFile(options.OutputDirectory, L"dirs_*.txt", options.DirsPath, latestDirsTime);
        FindLatestFile(options.OutputDirectory, L"files_*.txt", options.FilesPath, latestFilesTime);
    }

    void NormalizeHookDirectories(HookHashRestoreLaunchOptions& options)
    {
        if (options.OutputDirectory.empty())
        {
            options.OutputDirectory = CombinePathLocal(g_KrkrExeDirectory, L"StringHashDumper_Output");
        }

        bool pureLooksLikeHashOutput = _wcsicmp(GetFileNameLocal(options.PureHashDirectory).c_str(), L"StringHashDumper_Output") == 0;
        if (options.PureHashDirectory.empty() || SamePathText(options.PureHashDirectory, options.OutputDirectory) || pureLooksLikeHashOutput)
        {
            std::wstring parent = GetParentDirectoryLocal(options.OutputDirectory);
            options.PureHashDirectory = CombinePathLocal(parent.empty() ? g_KrkrExeDirectory : parent, L"Extractor_Output");
        }
    }

    std::wstring BrowseFolder(HWND owner, const wchar_t* title)
    {
        std::wstring result;
        HRESULT coInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        IFileDialog* dialog = nullptr;
        HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
        if (SUCCEEDED(hr) && dialog)
        {
            DWORD options = 0u;
            if (SUCCEEDED(dialog->GetOptions(&options)))
            {
                dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
            }
            dialog->SetTitle(title);

            if (SUCCEEDED(dialog->Show(owner)))
            {
                IShellItem* item = nullptr;
                if (SUCCEEDED(dialog->GetResult(&item)) && item)
                {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path)
                    {
                        result = path;
                        ::CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            dialog->Release();
        }

        if (SUCCEEDED(coInit))
        {
            ::CoUninitialize();
        }
        return result;
    }

    std::wstring BrowseTextFile(HWND owner, const wchar_t* title)
    {
        std::wstring result;
        HRESULT coInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        IFileDialog* dialog = nullptr;
        HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
        if (SUCCEEDED(hr) && dialog)
        {
            DWORD options = 0u;
            if (SUCCEEDED(dialog->GetOptions(&options)))
            {
                dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST);
            }
            dialog->SetTitle(title);
            COMDLG_FILTERSPEC filters[] =
            {
                { L"候选文本", L"*.txt" },
                { L"所有文件", L"*.*" }
            };
            dialog->SetFileTypes(_countof(filters), filters);

            if (SUCCEEDED(dialog->Show(owner)))
            {
                IShellItem* item = nullptr;
                if (SUCCEEDED(dialog->GetResult(&item)) && item)
                {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path)
                    {
                        result = path;
                        ::CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            dialog->Release();
        }

        if (SUCCEEDED(coInit))
        {
            ::CoUninitialize();
        }
        return result;
    }

    std::wstring GetWindowTextString(HWND hwnd)
    {
        int length = ::GetWindowTextLengthW(hwnd);
        if (length <= 0)
        {
            return std::wstring();
        }

        std::wstring text((size_t)length + 1u, L'\0');
        int copied = ::GetWindowTextW(hwnd, text.data(), length + 1);
        if (copied <= 0)
        {
            return std::wstring();
        }
        text.resize((size_t)copied);
        return text;
    }

    HFONT CreateLoaderUiFont(HWND hwnd)
    {
        HDC dc = ::GetDC(hwnd);
        int dpiY = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
        if (dc)
        {
            ::ReleaseDC(hwnd, dc);
        }
        return ::CreateFontW(-::MulDiv(9, dpiY, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    }

    BOOL CALLBACK ApplyLoaderFontToChild(HWND child, LPARAM font)
    {
        ::SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
        return TRUE;
    }

    std::wstring BuildHookSummary(const HookHashRestoreLaunchOptions& options)
    {
        return FormatString(L"纯Hash目录：%s\r\n"
                            L"补充lst映射：%s\r\n"
                            L"游戏主程序：%s\r\n"
                            L"游戏目录：%s\r\n"
                            L"Hash输出目录：%s\r\n"
                            L"候选目录表：%s%s\r\n"
                            L"候选文件表：%s%s\r\n"
                            L"阶段：准备就绪。点击“开始撞库”后才启动游戏并注入 CxdecHashRestore.dll。",
                            options.PureHashDirectory.empty() ? L"未选择" : options.PureHashDirectory.c_str(),
                            options.SupplementalMapPath.empty() ? L"未选择（可选）" : options.SupplementalMapPath.c_str(),
                            g_KrkrExeFullPath.c_str(),
                            g_KrkrExeDirectory.c_str(),
                            options.OutputDirectory.empty() ? L"未选择" : options.OutputDirectory.c_str(),
                            options.DirsPath.empty() ? L"未选择" : options.DirsPath.c_str(),
                            options.DirsPath.empty() ? L"" : FormatString(L"（%u 行）", CountTextLines(options.DirsPath)).c_str(),
                            options.FilesPath.empty() ? L"未选择" : options.FilesPath.c_str(),
                            options.FilesPath.empty() ? L"" : FormatString(L"（%u 行）", CountTextLines(options.FilesPath)).c_str());
    }

    struct HookDialogContext
    {
        HookHashRestoreLaunchOptions Options;
        bool Accepted;
        HFONT Font;
    };

    void RefreshHookDialog(HWND hwnd, HookDialogContext* context)
    {
        if (!context)
        {
            return;
        }
        NormalizeHookDirectories(context->Options);
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_PURE_EDIT), context->Options.PureHashDirectory.c_str());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_OUTPUT_EDIT), context->Options.OutputDirectory.c_str());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_SUPPLEMENT_EDIT), context->Options.SupplementalMapPath.c_str());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_DIRS_EDIT), context->Options.DirsPath.c_str());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_FILES_EDIT), context->Options.FilesPath.c_str());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_SUMMARY), BuildHookSummary(context->Options).c_str());
    }

    LRESULT CALLBACK HookHashDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        HookDialogContext* context = (HookDialogContext*)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        switch (message)
        {
            case WM_CREATE:
            {
                CREATESTRUCTW* create = (CREATESTRUCTW*)lParam;
                context = (HookDialogContext*)create->lpCreateParams;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);
                context->Font = CreateLoaderUiFont(hwnd);

                CreateWindowW(L"STATIC", L"纯Hash目录：", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 18, 95, 18, hwnd, nullptr, nullptr, nullptr);
                CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 15, 610, 23, hwnd, (HMENU)IDC_HOOK_PURE_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 740, 14, 70, 25, hwnd, (HMENU)IDC_HOOK_PURE_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"Hash输出目录：", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 52, 95, 18, hwnd, nullptr, nullptr, nullptr);
                CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 49, 610, 23, hwnd, (HMENU)IDC_HOOK_OUTPUT_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 740, 48, 70, 25, hwnd, (HMENU)IDC_HOOK_OUTPUT_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"补充lst映射：", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 86, 95, 18, hwnd, nullptr, nullptr, nullptr);
                CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 83, 610, 23, hwnd, (HMENU)IDC_HOOK_SUPPLEMENT_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 740, 82, 70, 25, hwnd, (HMENU)IDC_HOOK_SUPPLEMENT_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"候选目录表：", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 120, 95, 18, hwnd, nullptr, nullptr, nullptr);
                CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 117, 610, 23, hwnd, (HMENU)IDC_HOOK_DIRS_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 740, 116, 70, 25, hwnd, (HMENU)IDC_HOOK_DIRS_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"候选文件表：", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 154, 95, 18, hwnd, nullptr, nullptr, nullptr);
                CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 151, 610, 23, hwnd, (HMENU)IDC_HOOK_FILES_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 740, 150, 70, 25, hwnd, (HMENU)IDC_HOOK_FILES_BROWSE, nullptr, nullptr);

                CreateWindowW(L"BUTTON", L"制作候选lst", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 18, 190, 115, 28, hwnd, (HMENU)IDC_HOOK_MAKE_CANDIDATE, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"重新扫描最新候选", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 143, 190, 145, 28, hwnd, (HMENU)IDC_HOOK_RESCAN, nullptr, nullptr);
                CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 18, 230, 790, 135, hwnd, (HMENU)IDC_HOOK_SUMMARY, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"开始撞库", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 610, 382, 95, 30, hwnd, (HMENU)IDC_HOOK_START, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 715, 382, 90, 30, hwnd, (HMENU)IDCANCEL, nullptr, nullptr);

                ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)context->Font, TRUE);
                ::EnumChildWindows(hwnd, ApplyLoaderFontToChild, (LPARAM)context->Font);
                RefreshHookDialog(hwnd, context);
                return 0;
            }
            case WM_COMMAND:
                if (!context)
                {
                    break;
                }
                if (LOWORD(wParam) == IDC_HOOK_PURE_BROWSE)
                {
                    std::wstring folder = BrowseFolder(hwnd, L"选择需要恢复的纯Hash目录");
                    if (!folder.empty())
                    {
                        if (SamePathText(folder, GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_OUTPUT_EDIT))))
                        {
                            ::MessageBoxW(hwnd, L"纯Hash目录不能和 Hash 输出目录相同。纯Hash目录应选择 Extractor_Output。", L"Cxdec Hook撞库恢复Hash映射", MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        context->Options.PureHashDirectory = folder;
                        RefreshHookDialog(hwnd, context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_OUTPUT_BROWSE)
                {
                    std::wstring folder = BrowseFolder(hwnd, L"选择 Hash 输出目录");
                    if (!folder.empty())
                    {
                        context->Options.OutputDirectory = folder;
                        context->Options.DirsPath.clear();
                        context->Options.FilesPath.clear();
                        ScanLatestHookCandidates(context->Options);
                        RefreshHookDialog(hwnd, context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_SUPPLEMENT_BROWSE)
                {
                    std::wstring file = BrowseTextFile(hwnd, L"选择补充lst映射");
                    if (!file.empty())
                    {
                        context->Options.SupplementalMapPath = file;
                        RefreshHookDialog(hwnd, context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_DIRS_BROWSE)
                {
                    std::wstring file = BrowseTextFile(hwnd, L"选择候选目录表");
                    if (!file.empty())
                    {
                        context->Options.DirsPath = file;
                        RefreshHookDialog(hwnd, context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_FILES_BROWSE)
                {
                    std::wstring file = BrowseTextFile(hwnd, L"选择候选文件表");
                    if (!file.empty())
                    {
                        context->Options.FilesPath = file;
                        RefreshHookDialog(hwnd, context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_MAKE_CANDIDATE)
                {
                    context->Options.PureHashDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_PURE_EDIT));
                    context->Options.OutputDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_OUTPUT_EDIT));
                    context->Options.SupplementalMapPath = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_SUPPLEMENT_EDIT));
                    bool ok = MakeCandidateLists(hwnd, context->Options);
                    RefreshHookDialog(hwnd, context);
                    ::MessageBoxW(hwnd,
                                  ok ? L"候选lst制作完成。" : L"候选lst制作失败或已取消。",
                                  L"Cxdec Hook撞库恢复Hash映射",
                                  ok ? MB_OK | MB_ICONINFORMATION : MB_OK | MB_ICONWARNING);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_RESCAN)
                {
                    context->Options.PureHashDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_PURE_EDIT));
                    context->Options.OutputDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_OUTPUT_EDIT));
                    context->Options.SupplementalMapPath = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_SUPPLEMENT_EDIT));
                    context->Options.DirsPath.clear();
                    context->Options.FilesPath.clear();
                    ScanLatestHookCandidates(context->Options);
                    RefreshHookDialog(hwnd, context);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_HOOK_START)
                {
                    context->Options.PureHashDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_PURE_EDIT));
                    context->Options.OutputDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_OUTPUT_EDIT));
                    context->Options.SupplementalMapPath = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_SUPPLEMENT_EDIT));
                    context->Options.DirsPath = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_DIRS_EDIT));
                    context->Options.FilesPath = GetWindowTextString(::GetDlgItem(hwnd, IDC_HOOK_FILES_EDIT));
                    NormalizeHookDirectories(context->Options);
                    if (SamePathText(context->Options.PureHashDirectory, context->Options.OutputDirectory))
                    {
                        ::MessageBoxW(hwnd, L"纯Hash目录不能和 Hash 输出目录相同。纯Hash目录应选择 Extractor_Output。", L"Cxdec Hook撞库恢复Hash映射", MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    if (context->Options.DirsPath.empty() && context->Options.FilesPath.empty())
                    {
                        int choice = ::MessageBoxW(hwnd,
                                                   L"还没有候选表。\r\n\r\n可以点击“制作候选lst”从明文资源目录生成，也可以点击“重新扫描最新候选”，或者手动浏览选择 dirs/files txt。\r\n\r\n现在要制作候选lst吗？",
                                                   L"Cxdec Hook撞库恢复Hash映射",
                                                   MB_YESNO | MB_ICONQUESTION);
                        if (choice == IDYES)
                        {
                            bool ok = MakeCandidateLists(hwnd, context->Options);
                            RefreshHookDialog(hwnd, context);
                            if (!ok)
                            {
                                return 0;
                            }
                        }
                        else
                        {
                            return 0;
                        }
                    }
                    context->Accepted = true;
                    ::DestroyWindow(hwnd);
                    return 0;
                }
                if (LOWORD(wParam) == IDCANCEL)
                {
                    ::DestroyWindow(hwnd);
                    return 0;
                }
                break;
            case WM_CLOSE:
                ::DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (context && context->Font)
                {
                    ::DeleteObject(context->Font);
                    context->Font = nullptr;
                }
                return 0;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    }

    bool ShowHookHashRestoreLaunchDialog(HWND owner, HookHashRestoreLaunchOptions& options)
    {
        options.PureHashDirectory = CombinePathLocal(g_KrkrExeDirectory, L"Extractor_Output");
        options.OutputDirectory = CombinePathLocal(g_KrkrExeDirectory, L"StringHashDumper_Output");
        NormalizeHookDirectories(options);
        ScanLatestHookCandidates(options);

        HookDialogContext context{};
        context.Options = options;

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = HookHashDialogProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        windowClass.lpszClassName = HookHashDialogClassName;
        ::RegisterClassExW(&windowClass);

        HWND hwnd = ::CreateWindowExW(WS_EX_DLGMODALFRAME,
                                      HookHashDialogClassName,
                                      L"Cxdec Hook撞库恢复Hash映射",
                                      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                      CW_USEDEFAULT,
                                      CW_USEDEFAULT,
                                      840,
                                      465,
                                      owner,
                                      nullptr,
                                      windowClass.hInstance,
                                      &context);
        if (!hwnd)
        {
            return false;
        }

        ::EnableWindow(owner, FALSE);
        ::ShowWindow(hwnd, SW_SHOW);
        ::UpdateWindow(hwnd);

        MSG msg{};
        while (::IsWindow(hwnd) && ::GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        ::EnableWindow(owner, TRUE);
        ::SetForegroundWindow(owner);

        options = context.Options;
        return context.Accepted;
    }

    void SetLoaderWindowHandleEnv(HWND hwnd)
    {
        // KeyDumper 运行在目标进程里，不能直接持有 loader HWND。
        // 这里通过环境变量传句柄，方便跨进程回发进度消息。
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

        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_KeyProgressLabel), L"提取进度");
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
        // 目标进程用 RegisterWindowMessage 回传百分比，loader 只负责显示。
        ShowKeyProgressControls(hwnd, true);
        UpdateKeyProgressUi(hwnd, (unsigned int)wParam, lParam == 1 ? L"撞库进度" : L"提取进度");
        return TRUE;
    }

    if (msg == LoaderIpc::CompletedMessage())
    {
        ShowKeyProgressControls(hwnd, true);
        UpdateKeyProgressUi(hwnd, 100u, lParam == 1 ? L"撞库完成" : L"提取完成");
        ::MessageBoxW(hwnd,
                      lParam == 1 ? L"撞库完成，恢复映射表已写入 Hash 输出目录。" : L"提取完成，请查看目录。",
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
            std::wstring runtimeHashTargetDirectory;
            HookHashRestoreLaunchOptions hookHashOptions;
            bool hasHookHashOptions = false;
            bool shouldCloseLoaderAfterLaunch = true;

            switch (LOWORD(wParam))
            {
                case IDC_Extractor:
                    injectDllFileName = L"CxdecExtractorUI.dll";
                    break;
                case IDC_StringDumper:
                    runtimeHashTargetDirectory = BrowseFolder(hwnd, L"选择需要恢复的纯Hash目录");
                    if (runtimeHashTargetDirectory.empty())
                    {
                        return TRUE;
                    }
                    ::SetEnvironmentVariableW(RuntimeHashTargetDirectoryEnvName, runtimeHashTargetDirectory.c_str());
                    injectDllFileName = L"CxdecStringDumper.dll";
                    break;
                case IDC_KeyDumper:
                    injectDllFileName = L"CxdecKeyDumper.dll";
                    // Key 提取是异步分阶段完成的，loader 需要继续存活来展示进度。
                    shouldCloseLoaderAfterLaunch = false;
                    break;
                case IDC_HashRestore:
                    if (!ShowHookHashRestoreLaunchDialog(hwnd, hookHashOptions))
                    {
                        return TRUE;
                    }
                    hasHookHashOptions = true;
                    injectDllFileName = L"CxdecHashRestore.dll";
                    shouldCloseLoaderAfterLaunch = false;
                    break;
            }

            if (!injectDllFileName.empty())
            {
                std::wstring injectDllFullPath = GetModuleDllPath(injectDllFileName);
                if (!FileExistsLocal(injectDllFullPath))
                {
                    ::MessageBoxW(hwnd,
                                  FormatString(L"找不到模块 DLL：\r\n%s\r\n\r\n请确认发布结构为：\r\nCxdecExtractorLoader.exe\r\nCxdecExtractordll\\%s",
                                               injectDllFullPath.c_str(),
                                               injectDllFileName.c_str()).c_str(),
                                  L"CxdecExtractorLoader",
                                  MB_OK | MB_ICONERROR);
                    return TRUE;
                }
                std::string injectDllFullPathA = Encoding::UnicodeToAnsi(injectDllFullPath, Encoding::CodePage::ACP);

                STARTUPINFOW si{};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};

                if (!shouldCloseLoaderAfterLaunch)
                {
                    SetLoaderWindowHandleEnv(hwnd);
                }
                if (hasHookHashOptions)
                {
                    ::SetEnvironmentVariableW(HashCrackOutputDirectoryEnvName, hookHashOptions.OutputDirectory.c_str());
                    ::SetEnvironmentVariableW(HashCrackDirsFileEnvName, hookHashOptions.DirsPath.empty() ? nullptr : hookHashOptions.DirsPath.c_str());
                    ::SetEnvironmentVariableW(HashCrackFilesFileEnvName, hookHashOptions.FilesPath.empty() ? nullptr : hookHashOptions.FilesPath.c_str());
                    ::SetEnvironmentVariableW(HashCrackPureHashDirectoryEnvName, hookHashOptions.PureHashDirectory.empty() ? nullptr : hookHashOptions.PureHashDirectory.c_str());
                    ::SetEnvironmentVariableW(HashCrackSupplementalMapEnvName, hookHashOptions.SupplementalMapPath.empty() ? nullptr : hookHashOptions.SupplementalMapPath.c_str());
                    ::SetEnvironmentVariableW(HashCrackSuppressRestoreUiEnvName, L"1");
                }

                // 直接用 Detours 创建并注入，避免额外的远程线程/写内存步骤。
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
                    if (!runtimeHashTargetDirectory.empty())
                    {
                        ::SetEnvironmentVariableW(RuntimeHashTargetDirectoryEnvName, nullptr);
                    }
                    if (hasHookHashOptions)
                    {
                        ::SetEnvironmentVariableW(HashCrackOutputDirectoryEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackDirsFileEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackFilesFileEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackPureHashDirectoryEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackSupplementalMapEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackSuppressRestoreUiEnvName, nullptr);
                    }
                    ::CloseHandle(pi.hThread);
                    ::CloseHandle(pi.hProcess);

                    if (shouldCloseLoaderAfterLaunch)
                    {
                        ::PostMessageW(hwnd, WM_CLOSE, 0u, 0u);
                    }
                    else
                    {
                        // 异步模式下禁止重复点击，避免多个目标进程同时回报到同一个 loader。
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_Extractor), FALSE);
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_StringDumper), FALSE);
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_KeyDumper), FALSE);
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_HashRestore), FALSE);
                        ShowKeyProgressControls(hwnd, true);
                        UpdateKeyProgressUi(hwnd, 0u, hasHookHashOptions ? L"等待撞库开始" : L"等待提取开始");
                        ::SetWindowTextW(hwnd, hasHookHashOptions ? L"CxdecExtractorLoader - 等待Hook撞库完成" : L"CxdecExtractorLoader - 等待Key提取完成");
                    }
                }
                else
                {
                    if (!runtimeHashTargetDirectory.empty())
                    {
                        ::SetEnvironmentVariableW(RuntimeHashTargetDirectoryEnvName, nullptr);
                    }
                    if (hasHookHashOptions)
                    {
                        ::SetEnvironmentVariableW(HashCrackOutputDirectoryEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackDirsFileEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackFilesFileEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackPureHashDirectoryEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackSupplementalMapEnvName, nullptr);
                        ::SetEnvironmentVariableW(HashCrackSuppressRestoreUiEnvName, nullptr);
                    }
                    if (!shouldCloseLoaderAfterLaunch)
                    {
                        ClearLoaderWindowHandleEnv();
                    }
                    ::MessageBoxW(hwnd,
                                  L"创建进程错误",
                                  L"错误",
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
            // loader 通过“把游戏 exe 拖到自身上”启动，因此这里只关心第一个参数。
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

        // 纯对话框程序，自己维护标准消息循环即可。
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
                      L"请拖拽游戏主程序到启动器",
                      L"错误",
                      MB_OK | MB_ICONERROR);
    }

    return 0;
}
