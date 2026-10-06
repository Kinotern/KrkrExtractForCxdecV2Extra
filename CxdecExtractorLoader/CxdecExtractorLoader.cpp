#include <windows.h>
#include <commctrl.h>
#include <detours.h>
#include "detour_section.h"
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
    constexpr int IDC_HOOK_HINT_BASE = 3200;
    constexpr int IDC_HOOK_HINT_COUNT = 8;

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

    bool DirectoryExistsLocal(const std::wstring& path)
    {
        if (path.empty())
        {
            return false;
        }
        DWORD attributes = ::GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
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

    // 统一的文件选择框：save=true 走"另存为"，否则走"打开"。
    // defaultDirectory / defaultName 只决定弹出来时的初始位置，用户可以随便改。
    std::wstring BrowseFileDialog(HWND owner, const wchar_t* title, bool save,
                                  const wchar_t* filterName, const wchar_t* filterSpec,
                                  const wchar_t* defaultDirectory, const wchar_t* defaultName)
    {
        std::wstring result;
        HRESULT coInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        IFileDialog* dialog = nullptr;
        HRESULT hr = ::CoCreateInstance(save ? CLSID_FileSaveDialog : CLSID_FileOpenDialog,
                                        nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
        if (SUCCEEDED(hr) && dialog)
        {
            DWORD options = 0u;
            if (SUCCEEDED(dialog->GetOptions(&options)))
            {
                options |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
                options |= save ? FOS_OVERWRITEPROMPT : FOS_FILEMUSTEXIST;
                dialog->SetOptions(options);
            }
            dialog->SetTitle(title);

            if (filterName != nullptr && filterSpec != nullptr)
            {
                COMDLG_FILTERSPEC filters[] =
                {
                    { filterName, filterSpec },
                    { L"所有文件", L"*.*" }
                };
                dialog->SetFileTypes(_countof(filters), filters);
            }

            if (defaultDirectory != nullptr && defaultDirectory[0] != L'\0')
            {
                IShellItem* folder = nullptr;
                if (SUCCEEDED(::SHCreateItemFromParsingName(defaultDirectory, nullptr, IID_PPV_ARGS(&folder))) && folder)
                {
                    dialog->SetFolder(folder);
                    folder->Release();
                }
            }
            if (defaultName != nullptr && defaultName[0] != L'\0')
            {
                dialog->SetFileName(defaultName);
            }

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
        return BrowseFileDialog(owner, title, false, L"候选文本", L"*.txt", nullptr, nullptr);
    }

    std::wstring BrowseExeFile(HWND owner, const wchar_t* title)
    {
        return BrowseFileDialog(owner, title, false, L"游戏主程序", L"*.exe", nullptr, nullptr);
    }

    // 默认落在 <游戏目录>\patch@r<N>.xp3，用户可以直接改。
    std::wstring BrowseSaveXp3File(HWND owner, const wchar_t* title, const std::wstring& defaultPath)
    {
        const std::wstring defaultDirectory = GetParentDirectoryLocal(defaultPath);
        const std::wstring defaultName = GetFileNameLocal(defaultPath);
        return BrowseFileDialog(owner, title, true, L"XP3 封包", L"*.xp3",
                                defaultDirectory.c_str(), defaultName.c_str());
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

    HFONT CreateLoaderUiFont(HWND hwnd, int pointSize = 9, bool bold = false)
    {
        HDC dc = ::GetDC(hwnd);
        int dpiY = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
        if (dc)
        {
            ::ReleaseDC(hwnd, dc);
        }
        return ::CreateFontW(-::MulDiv(pointSize, dpiY, 72), 0, 0, 0, bold ? FW_SEMIBOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    }

    BOOL CALLBACK ApplyLoaderFontToChild(HWND child, LPARAM font)
    {
        ::SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
        return TRUE;
    }

    std::wstring BuildHookStatus(const HookHashRestoreLaunchOptions& options)
    {
        std::wstring missing;
        auto addMissing = [&missing](const wchar_t* name)
        {
            if (!missing.empty())
            {
                missing += L"、";
            }
            missing += name;
        };

        if (options.PureHashDirectory.empty())
        {
            addMissing(L"纯Hash目录");
        }
        if (options.OutputDirectory.empty())
        {
            addMissing(L"Hash输出目录");
        }
        if (options.DirsPath.empty() && options.FilesPath.empty())
        {
            addMissing(L"候选表");
        }

        std::wstring status;
        if (missing.empty())
        {
            status = L"状态：就绪，可以开始撞库。";
        }
        else
        {
            status = L"状态：还缺 " + missing + L"，补齐后才能开始。";
        }

        status += L"\r\n游戏主程序：";
        status += g_KrkrExeFullPath;

        if (!options.DirsPath.empty() || !options.FilesPath.empty())
        {
            status += L"\r\n候选表：目录 ";
            status += options.DirsPath.empty() ? std::wstring(L"未选择")
                                               : FormatString(L"%u 项", CountTextLines(options.DirsPath));
            status += L"  /  文件 ";
            status += options.FilesPath.empty() ? std::wstring(L"未选择")
                                                : FormatString(L"%u 项", CountTextLines(options.FilesPath));
        }

        if (!options.SupplementalMapPath.empty())
        {
            status += L"\r\n补充映射：";
            status += GetFileNameLocal(options.SupplementalMapPath);
        }

        return status;
    }

    struct HookDialogContext
    {
        HookHashRestoreLaunchOptions Options;
        bool Accepted;
        bool StatusReady;
        HFONT Font;
        HFONT BoldFont;
        HWND StepLabels[4];
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

        context->StatusReady = !context->Options.PureHashDirectory.empty()
                            && !context->Options.OutputDirectory.empty()
                            && (!context->Options.DirsPath.empty() || !context->Options.FilesPath.empty());
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_HOOK_SUMMARY), BuildHookStatus(context->Options).c_str());
        ::InvalidateRect(::GetDlgItem(hwnd, IDC_HOOK_SUMMARY), nullptr, TRUE);
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
                context->Font = CreateLoaderUiFont(hwnd, 9, false);
                context->BoldFont = CreateLoaderUiFont(hwnd, 10, true);
                for (HWND& label : context->StepLabels)
                {
                    label = nullptr;
                }

                const int kEditX = 222;
                const int kEditW = 524;
                const int kBrowseX = 754;
                const int kBrowseW = 94;

                auto MakeStepLabel = [&](int y, const wchar_t* text) -> HWND
                {
                    return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                         16, y, 200, 20, hwnd, nullptr, nullptr, nullptr);
                };
                auto MakeHint = [&](int y, int index, const wchar_t* text)
                {
                    CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  kEditX, y, 630, 17, hwnd, (HMENU)(INT_PTR)(IDC_HOOK_HINT_BASE + index), nullptr, nullptr);
                };
                auto MakeEdit = [&](int x, int y, int width, int id)
                {
                    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    x, y, width, 24, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
                };
                auto MakeBrowse = [&](int y, int id)
                {
                    CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  kBrowseX, y, kBrowseW, 26, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
                };

                // 第 1 步：要恢复的纯 Hash 解包目录
                context->StepLabels[0] = MakeStepLabel(16, L"第 1 步 · 纯Hash目录（必填）");
                MakeEdit(kEditX, 13, kEditW, IDC_HOOK_PURE_EDIT);
                MakeBrowse(12, IDC_HOOK_PURE_BROWSE);
                MakeHint(43, 0, L"要恢复的纯Hash解包目录，通常是游戏目录下的 Extractor_Output");

                // 第 2 步：撞库结果写入位置
                context->StepLabels[1] = MakeStepLabel(76, L"第 2 步 · Hash输出目录（必填）");
                MakeEdit(kEditX, 73, kEditW, IDC_HOOK_OUTPUT_EDIT);
                MakeBrowse(72, IDC_HOOK_OUTPUT_BROWSE);
                MakeHint(103, 1, L"撞库结果 HashRestore_RecoveredNames.lst 的写入目录");

                // 第 3 步：候选表（按钮与候选字段放在一起）
                context->StepLabels[2] = MakeStepLabel(136, L"第 3 步 · 候选表（必填）");
                CreateWindowW(L"STATIC", L"候选目录表", WS_CHILD | WS_VISIBLE | SS_LEFT,
                              36, 168, 100, 20, hwnd, nullptr, nullptr, nullptr);
                MakeEdit(146, 165, 600, IDC_HOOK_DIRS_EDIT);
                MakeBrowse(164, IDC_HOOK_DIRS_BROWSE);
                CreateWindowW(L"STATIC", L"候选文件表", WS_CHILD | WS_VISIBLE | SS_LEFT,
                              36, 200, 100, 20, hwnd, nullptr, nullptr, nullptr);
                MakeEdit(146, 197, 600, IDC_HOOK_FILES_EDIT);
                MakeBrowse(196, IDC_HOOK_FILES_BROWSE);
                CreateWindowW(L"BUTTON", L"从明文资源目录制作候选lst", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              146, 232, 200, 28, hwnd, (HMENU)IDC_HOOK_MAKE_CANDIDATE, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"扫描最新候选", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              356, 232, 140, 28, hwnd, (HMENU)IDC_HOOK_RESCAN, nullptr, nullptr);
                MakeHint(268, 2, L"没有候选表时先用左侧按钮生成；目录表和文件表至少要有一个");

                // 第 4 步：可选补充映射
                context->StepLabels[3] = MakeStepLabel(302, L"第 4 步 · 补充lst映射（可选）");
                MakeEdit(kEditX, 299, kEditW, IDC_HOOK_SUPPLEMENT_EDIT);
                MakeBrowse(298, IDC_HOOK_SUPPLEMENT_BROWSE);
                MakeHint(329, 3, L"已有的映射文件，会合并进最终结果；没有可留空");

                // 底部状态：只显示校验结果与游戏主程序，不重复上面的输入
                CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                              16, 360, 832, 62, hwnd, (HMENU)IDC_HOOK_SUMMARY, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"开始撞库", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                              650, 434, 110, 32, hwnd, (HMENU)IDC_HOOK_START, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              768, 434, 90, 32, hwnd, (HMENU)IDCANCEL, nullptr, nullptr);

                ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)context->Font, TRUE);
                ::EnumChildWindows(hwnd, ApplyLoaderFontToChild, (LPARAM)context->Font);
                for (HWND label : context->StepLabels)
                {
                    if (label)
                    {
                        ::SendMessageW(label, WM_SETFONT, (WPARAM)context->BoldFont, TRUE);
                    }
                }
                RefreshHookDialog(hwnd, context);
                return 0;
            }
            case WM_CTLCOLORSTATIC:
            {
                if (!context)
                {
                    break;
                }
                const int controlId = ::GetDlgCtrlID((HWND)lParam);
                HDC dc = (HDC)wParam;
                ::SetBkMode(dc, TRANSPARENT);
                if (controlId == IDC_HOOK_SUMMARY)
                {
                    ::SetTextColor(dc, context->StatusReady ? RGB(0, 110, 40) : RGB(178, 78, 0));
                    return (LRESULT)::GetSysColorBrush(COLOR_WINDOW);
                }
                if (controlId >= IDC_HOOK_HINT_BASE && controlId < IDC_HOOK_HINT_BASE + IDC_HOOK_HINT_COUNT)
                {
                    ::SetTextColor(dc, RGB(110, 110, 110));
                    return (LRESULT)::GetSysColorBrush(COLOR_WINDOW);
                }
                break;
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
                                                   L"还没有候选表。\r\n\r\n可以点击“从明文资源目录制作候选lst”生成，也可以点击“扫描最新候选”，或者手动浏览选择 dirs/files txt。\r\n\r\n现在要制作候选lst吗？",
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
                if (context)
                {
                    if (context->Font)
                    {
                        ::DeleteObject(context->Font);
                        context->Font = nullptr;
                    }
                    if (context->BoldFont)
                    {
                        ::DeleteObject(context->BoldFont);
                        context->BoldFont = nullptr;
                    }
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
                                      880,
                                      530,
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

    // ---------- 封包（目录 -> XP3）----------

    constexpr wchar_t RepackDialogClassName[] = L"CxdecRepackWindow";
    constexpr int IDC_REPACK_INPUT_EDIT = 3301;
    constexpr int IDC_REPACK_INPUT_BROWSE = 3302;
    constexpr int IDC_REPACK_EXE_EDIT = 3303;
    constexpr int IDC_REPACK_EXE_BROWSE = 3304;
    constexpr int IDC_REPACK_OUTPUT_EDIT = 3305;
    constexpr int IDC_REPACK_OUTPUT_BROWSE = 3306;
    constexpr int IDC_REPACK_KEYS_EDIT = 3307;
    constexpr int IDC_REPACK_KEYS_BROWSE = 3308;
    constexpr int IDC_REPACK_RESCRAMBLE = 3309;
    constexpr int IDC_REPACK_STATUS = 3310;
    constexpr int IDC_REPACK_START = 3311;
    constexpr int IDC_REPACK_HINT_BASE = 3400;
    constexpr int IDC_REPACK_HINT_COUNT = 8;
    constexpr UINT RepackDoneMessage = WM_APP + 1;

    typedef int(__stdcall* RepackSniffFn)(const wchar_t*, int*, char*, int, char*, int);
    typedef int(__stdcall* RepackPackFn)(const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*,
                                         int, int, char*, int, char*, int);
    typedef unsigned int(__stdcall* RepackNextRevisionFn)(const wchar_t*);

    struct RepackerApi
    {
        HMODULE Module;
        RepackSniffFn Sniff;
        RepackPackFn Pack;
        RepackNextRevisionFn NextRevision;
    };

    // 只加载一次，之后复用同一份函数指针。
    // 调用方（界面线程）总是在起后台线程之前先调一次，所以不存在并发初始化。
    const RepackerApi* LoadRepackerApi(std::wstring& errorOut)
    {
        static RepackerApi api{};
        static bool tried = false;
        static std::wstring loadError;

        if (!tried)
        {
            tried = true;

            const std::wstring dllPath = GetModuleDllPath(L"CxdecRepacker.dll");
            api.Module = ::LoadLibraryW(dllPath.c_str());
            if (api.Module == nullptr)
            {
                loadError = FormatString(L"无法加载封包模块：\r\n%s", dllPath.c_str());
            }
            else
            {
                api.Sniff = (RepackSniffFn)::GetProcAddress(api.Module, "SniffInputDir");
                api.Pack = (RepackPackFn)::GetProcAddress(api.Module, "Repack");
                api.NextRevision = (RepackNextRevisionFn)::GetProcAddress(api.Module, "NextPatchRevision");
                if (api.Sniff == nullptr || api.Pack == nullptr)
                {
                    loadError = FormatString(L"封包模块缺少导出接口：\r\n%s", dllPath.c_str());
                }
            }
        }

        if (!loadError.empty())
        {
            errorOut = loadError;
            return nullptr;
        }
        return &api;
    }

    // 导出接口回的是 ANSI
    std::wstring AnsiBufferToString(const char* text)
    {
        if (text == nullptr || text[0] == '\0')
        {
            return std::wstring();
        }
        return Encoding::AnsiToUnicode(std::string(text), Encoding::ACP);
    }

    struct RepackOptions
    {
        std::wstring InputDirectory;
        std::wstring OutputXp3;
        std::wstring ExePath;
        std::wstring KeysRoot;
        bool Rescramble;
    };

    // 输出默认名：<游戏目录>\patch@r<N>.xp3，修订号由封包模块扫已有补丁包得出。
    std::wstring DefaultPatchOutputPath(const std::wstring& exePath)
    {
        const std::wstring gameDirectory = GetParentDirectoryLocal(exePath);
        if (gameDirectory.empty())
        {
            return std::wstring();
        }

        unsigned int revision = 1u;
        std::wstring loadError;
        const RepackerApi* api = LoadRepackerApi(loadError);
        if (api != nullptr && api->NextRevision != nullptr)
        {
            revision = api->NextRevision(gameDirectory.c_str());
            if (revision == 0u)
            {
                revision = 1u;
            }
        }
        return FormatString(L"%s\\patch@r%u.xp3", gameDirectory.c_str(), revision);
    }

    struct RepackDialogContext
    {
        RepackOptions Options;
        bool Ready;
        bool Busy;
        HFONT Font;
        HFONT BoldFont;
        HWND StepLabels[4];
    };

    std::wstring BuildRepackStatus(HWND hwnd, RepackDialogContext* context)
    {
        context->Options.InputDirectory = GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_INPUT_EDIT));
        context->Options.OutputXp3 = GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT));
        context->Options.ExePath = GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_EXE_EDIT));
        context->Options.KeysRoot = GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_KEYS_EDIT));
        context->Options.Rescramble = ::IsDlgButtonChecked(hwnd, IDC_REPACK_RESCRAMBLE) == BST_CHECKED;
        context->Ready = false;

        if (context->Options.InputDirectory.empty())
        {
            return std::wstring(L"状态：先选要封包的目录。");
        }

        std::wstring loadError;
        const RepackerApi* api = LoadRepackerApi(loadError);
        if (api == nullptr)
        {
            return L"状态：" + loadError;
        }

        std::wstring status;
        int mode = -1;
        char detail[1024]{};
        char error[1024]{};
        if (api->Sniff(context->Options.InputDirectory.c_str(), &mode, detail, sizeof(detail), error, sizeof(error)))
        {
            context->Ready = !context->Options.OutputXp3.empty();
            status = L"状态：可以封包。\r\n目录形态：";
            status += AnsiBufferToString(detail);
        }
        else
        {
            status = L"状态：这个目录还封不了 —— ";
            status += AnsiBufferToString(error);
        }

        status += L"\r\n输出：";
        status += context->Options.OutputXp3.empty() ? std::wstring(L"还没填（必填）") : context->Options.OutputXp3;
        status += L"\r\n参数：";
        status += context->Options.ExePath.empty()
                      ? std::wstring(L"未指定游戏主程序，会用内置参数")
                      : GetFileNameLocal(context->Options.ExePath);
        if (!context->Options.KeysRoot.empty())
        {
            status += L"\r\n参数仓库：";
            status += context->Options.KeysRoot;
        }
        return status;
    }

    void RefreshRepackDialog(HWND hwnd, RepackDialogContext* context)
    {
        if (context == nullptr)
        {
            return;
        }
        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_STATUS), BuildRepackStatus(hwnd, context).c_str());
        ::InvalidateRect(::GetDlgItem(hwnd, IDC_REPACK_STATUS), nullptr, TRUE);
    }

    struct RepackJob
    {
        HWND Owner;
        std::wstring InputDirectory;
        std::wstring OutputXp3;
        std::wstring ExePath;
        std::wstring KeysRoot;
        bool Rescramble;
    };

    // 打包可能很久，放后台线程跑；结果通过 RepackDoneMessage 回发，
    // 由窗口负责释放那个 string。
    DWORD WINAPI RepackThreadProc(LPVOID parameter)
    {
        RepackJob* job = (RepackJob*)parameter;

        bool ok = false;
        std::wstring message;

        std::wstring loadError;
        const RepackerApi* api = LoadRepackerApi(loadError);
        if (api == nullptr)
        {
            message = loadError;
        }
        else
        {
            // 先嗅探一遍：形态不对就别白打一遍包
            int mode = -1;
            char detail[1024]{};
            char sniffError[2048]{};
            if (!api->Sniff(job->InputDirectory.c_str(), &mode, detail, sizeof(detail),
                            sniffError, sizeof(sniffError)))
            {
                message = L"封包失败：" + AnsiBufferToString(sniffError);
            }
            else
            {
                char result[4096]{};
                char packError[2048]{};
                const wchar_t* exePath = job->ExePath.empty() ? nullptr : job->ExePath.c_str();
                const wchar_t* keysRoot = job->KeysRoot.empty() ? nullptr : job->KeysRoot.c_str();
                if (api->Pack(job->InputDirectory.c_str(), job->OutputXp3.c_str(), exePath, keysRoot,
                              -1, job->Rescramble ? 1 : 0,
                              result, sizeof(result), packError, sizeof(packError)))
                {
                    ok = true;
                    message = L"封包完成。\r\n\r\n";
                    message += AnsiBufferToString(result);
                    message += L"\r\n\r\n输出：" + job->OutputXp3;
                }
                else
                {
                    message = L"封包失败：" + AnsiBufferToString(packError);
                }
            }
        }

        std::wstring* payload = new std::wstring(message);
        if (::PostMessageW(job->Owner, RepackDoneMessage, ok ? 1u : 0u, (LPARAM)payload) == FALSE)
        {
            delete payload;
        }
        delete job;
        return 0;
    }

    LRESULT CALLBACK RepackDialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        RepackDialogContext* context = (RepackDialogContext*)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);

        if (message == RepackDoneMessage)
        {
            std::wstring* payload = (std::wstring*)lParam;
            if (context != nullptr)
            {
                context->Busy = false;
                ::SetWindowTextW(hwnd, L"Cxdec 封包（目录 → XP3）");
                ::EnableWindow(::GetDlgItem(hwnd, IDC_REPACK_START), TRUE);
            }
            if (payload != nullptr)
            {
                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_STATUS), payload->c_str());
                ::MessageBoxW(hwnd, payload->c_str(), L"Cxdec 封包",
                              wParam == 0u ? (MB_OK | MB_ICONERROR) : (MB_OK | MB_ICONINFORMATION));
                delete payload;
            }
            return 0;
        }

        switch (message)
        {
            case WM_CREATE:
            {
                CREATESTRUCTW* create = (CREATESTRUCTW*)lParam;
                context = (RepackDialogContext*)create->lpCreateParams;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);
                context->Font = CreateLoaderUiFont(hwnd, 9, false);
                context->BoldFont = CreateLoaderUiFont(hwnd, 10, true);
                for (HWND& label : context->StepLabels)
                {
                    label = nullptr;
                }

                const int kEditX = 222;
                const int kEditW = 524;
                const int kBrowseX = 754;
                const int kBrowseW = 94;

                auto MakeStepLabel = [&](int y, const wchar_t* text) -> HWND
                {
                    return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                         16, y, 200, 20, hwnd, nullptr, nullptr, nullptr);
                };
                auto MakeHint = [&](int y, int index, const wchar_t* text)
                {
                    CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  kEditX, y, 630, 17, hwnd, (HMENU)(INT_PTR)(IDC_REPACK_HINT_BASE + index), nullptr, nullptr);
                };
                auto MakeEdit = [&](int x, int y, int width, int id)
                {
                    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                    x, y, width, 24, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
                };
                auto MakeBrowse = [&](int y, int id)
                {
                    CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  kBrowseX, y, kBrowseW, 26, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
                };

                // 第 1 步：要封包的资源目录
                context->StepLabels[0] = MakeStepLabel(16, L"第 1 步 · 要封包的目录（必填）");
                MakeEdit(kEditX, 13, kEditW, IDC_REPACK_INPUT_EDIT);
                MakeBrowse(12, IDC_REPACK_INPUT_BROWSE);
                MakeHint(43, 0, L"解包出来的资源目录；单域 / 多域 / 平铺三种形态会自动判定");

                // 第 2 步：游戏主程序，用来从参数仓库取这套参数
                context->StepLabels[1] = MakeStepLabel(76, L"第 2 步 · 游戏主程序（可选）");
                MakeEdit(kEditX, 73, kEditW, IDC_REPACK_EXE_EDIT);
                MakeBrowse(72, IDC_REPACK_EXE_BROWSE);
                MakeHint(103, 1, L"用来取这套游戏的参数；不填就用内置参数，目标游戏不是它的话结果不会对");

                // 第 3 步：输出 XP3
                context->StepLabels[2] = MakeStepLabel(136, L"第 3 步 · 输出 XP3（必填）");
                MakeEdit(kEditX, 133, kEditW, IDC_REPACK_OUTPUT_EDIT);
                MakeBrowse(132, IDC_REPACK_OUTPUT_BROWSE);
                MakeHint(163, 2, L"默认写到游戏目录下的 patch@rN.xp3，可以直接改");

                // 第 4 步：参数仓库目录，留空走封包模块自己的默认
                context->StepLabels[3] = MakeStepLabel(196, L"第 4 步 · 参数仓库（可选）");
                MakeEdit(kEditX, 193, kEditW, IDC_REPACK_KEYS_EDIT);
                MakeBrowse(192, IDC_REPACK_KEYS_BROWSE);
                MakeHint(223, 3, L"留空表示用封包模块默认的 keys 目录；参数按 EXE 内容摘要存放，可以跨游戏共用");

                CreateWindowW(L"BUTTON", L"把干净文本重新加扰（补丁包通常要勾）", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                              kEditX, 250, kEditW, 22, hwnd, (HMENU)(INT_PTR)IDC_REPACK_RESCRAMBLE, nullptr, nullptr);
                MakeHint(275, 4, L"只对 FF FE 开头的干净文本生效，其它文件原样打进去");

                CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                              16, 302, 832, 96, hwnd, (HMENU)(INT_PTR)IDC_REPACK_STATUS, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"开始封包", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                              650, 406, 110, 32, hwnd, (HMENU)(INT_PTR)IDC_REPACK_START, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"取消", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              768, 406, 90, 32, hwnd, (HMENU)IDCANCEL, nullptr, nullptr);

                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_INPUT_EDIT), context->Options.InputDirectory.c_str());
                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_EXE_EDIT), context->Options.ExePath.c_str());
                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT), context->Options.OutputXp3.c_str());
                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_KEYS_EDIT), context->Options.KeysRoot.c_str());
                ::CheckDlgButton(hwnd, IDC_REPACK_RESCRAMBLE, context->Options.Rescramble ? BST_CHECKED : BST_UNCHECKED);

                ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)context->Font, TRUE);
                ::EnumChildWindows(hwnd, ApplyLoaderFontToChild, (LPARAM)context->Font);
                for (HWND label : context->StepLabels)
                {
                    if (label)
                    {
                        ::SendMessageW(label, WM_SETFONT, (WPARAM)context->BoldFont, TRUE);
                    }
                }
                RefreshRepackDialog(hwnd, context);
                return 0;
            }
            case WM_CTLCOLORSTATIC:
            {
                if (!context)
                {
                    break;
                }
                const int controlId = ::GetDlgCtrlID((HWND)lParam);
                HDC dc = (HDC)wParam;
                ::SetBkMode(dc, TRANSPARENT);
                if (controlId == IDC_REPACK_STATUS)
                {
                    ::SetTextColor(dc, context->Ready ? RGB(0, 110, 40) : RGB(178, 78, 0));
                    return (LRESULT)::GetSysColorBrush(COLOR_WINDOW);
                }
                if (controlId >= IDC_REPACK_HINT_BASE && controlId < IDC_REPACK_HINT_BASE + IDC_REPACK_HINT_COUNT)
                {
                    ::SetTextColor(dc, RGB(110, 110, 110));
                    return (LRESULT)::GetSysColorBrush(COLOR_WINDOW);
                }
                break;
            }
            case WM_COMMAND:
                if (!context)
                {
                    break;
                }
                switch (LOWORD(wParam))
                {
                    case IDC_REPACK_INPUT_BROWSE:
                    {
                        std::wstring folder = BrowseFolder(hwnd, L"选择要封包的资源目录");
                        if (!folder.empty())
                        {
                            ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_INPUT_EDIT), folder.c_str());
                            RefreshRepackDialog(hwnd, context);
                        }
                        return 0;
                    }
                    case IDC_REPACK_EXE_BROWSE:
                    {
                        std::wstring exe = BrowseExeFile(hwnd, L"选择游戏主程序");
                        if (!exe.empty())
                        {
                            ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_EXE_EDIT), exe.c_str());
                            // 输出还是空的就顺手填上 patch@rN.xp3
                            if (GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT)).empty())
                            {
                                const std::wstring defaultOutput = DefaultPatchOutputPath(exe);
                                ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT), defaultOutput.c_str());
                            }
                            RefreshRepackDialog(hwnd, context);
                        }
                        return 0;
                    }
                    case IDC_REPACK_OUTPUT_BROWSE:
                    {
                        const std::wstring current = GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT));
                        const std::wstring fallback = current.empty()
                                                          ? DefaultPatchOutputPath(GetWindowTextString(::GetDlgItem(hwnd, IDC_REPACK_EXE_EDIT)))
                                                          : current;
                        std::wstring target = BrowseSaveXp3File(hwnd, L"选择输出 XP3", fallback);
                        if (target.empty())
                        {
                            return 0;
                        }
                        // 用户只输了名字、没写扩展名时补上
                        if (target.size() < 4u || _wcsicmp(target.c_str() + target.size() - 4u, L".xp3") != 0)
                        {
                            target += L".xp3";
                        }
                        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_OUTPUT_EDIT), target.c_str());
                        RefreshRepackDialog(hwnd, context);
                        return 0;
                    }
                    case IDC_REPACK_KEYS_BROWSE:
                    {
                        std::wstring folder = BrowseFolder(hwnd, L"选择参数仓库目录");
                        if (!folder.empty())
                        {
                            ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_KEYS_EDIT), folder.c_str());
                            RefreshRepackDialog(hwnd, context);
                        }
                        return 0;
                    }
                    case IDC_REPACK_RESCRAMBLE:
                        RefreshRepackDialog(hwnd, context);
                        return 0;
                    case IDC_REPACK_INPUT_EDIT:
                    case IDC_REPACK_EXE_EDIT:
                    case IDC_REPACK_OUTPUT_EDIT:
                    case IDC_REPACK_KEYS_EDIT:
                        // 只认失焦：刷新要扫一遍目录，不能跟着每次按键跑
                        if (HIWORD(wParam) == EN_KILLFOCUS)
                        {
                            RefreshRepackDialog(hwnd, context);
                        }
                        return 0;
                    case IDC_REPACK_START:
                    {
                        if (context->Busy)
                        {
                            return 0;
                        }
                        RefreshRepackDialog(hwnd, context);
                        if (context->Options.InputDirectory.empty())
                        {
                            ::MessageBoxW(hwnd, L"先选要封包的目录。", L"Cxdec 封包", MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        if (context->Options.OutputXp3.empty())
                        {
                            ::MessageBoxW(hwnd, L"先填输出 XP3 的路径。", L"Cxdec 封包", MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        if (!context->Ready)
                        {
                            ::MessageBoxW(hwnd, L"这个目录还判定不出形态，先按上面的提示改一改。", L"Cxdec 封包", MB_OK | MB_ICONWARNING);
                            return 0;
                        }

                        RepackJob* job = new RepackJob{};
                        job->Owner = hwnd;
                        job->InputDirectory = context->Options.InputDirectory;
                        job->OutputXp3 = context->Options.OutputXp3;
                        job->ExePath = context->Options.ExePath;
                        job->KeysRoot = context->Options.KeysRoot;
                        job->Rescramble = context->Options.Rescramble;

                        DWORD threadId = 0u;
                        HANDLE thread = ::CreateThread(nullptr, 0u, RepackThreadProc, job, 0u, &threadId);
                        if (thread == nullptr)
                        {
                            delete job;
                            ::MessageBoxW(hwnd, L"起不了后台线程。", L"Cxdec 封包", MB_OK | MB_ICONERROR);
                            return 0;
                        }
                        ::CloseHandle(thread);

                        context->Busy = true;
                        ::EnableWindow(::GetDlgItem(hwnd, IDC_REPACK_START), FALSE);
                        ::SetWindowTextW(::GetDlgItem(hwnd, IDC_REPACK_STATUS), L"状态：正在封包，请稍候……");
                        ::SetWindowTextW(hwnd, L"Cxdec 封包（目录 → XP3）- 正在封包");
                        return 0;
                    }
                    case IDCANCEL:
                        ::DestroyWindow(hwnd);
                        return 0;
                }
                break;
            case WM_CLOSE:
                if (context != nullptr && context->Busy)
                {
                    ::MessageBoxW(hwnd, L"正在封包，等它写完再关。", L"Cxdec 封包", MB_OK | MB_ICONINFORMATION);
                    return 0;
                }
                ::DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (context)
                {
                    if (context->Font)
                    {
                        ::DeleteObject(context->Font);
                        context->Font = nullptr;
                    }
                    if (context->BoldFont)
                    {
                        ::DeleteObject(context->BoldFont);
                        context->BoldFont = nullptr;
                    }
                }
                return 0;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    }

    void ShowRepackDialog(HWND owner)
    {
        std::wstring loadError;
        if (LoadRepackerApi(loadError) == nullptr)
        {
            ::MessageBoxW(owner, loadError.c_str(), L"Cxdec 封包", MB_OK | MB_ICONERROR);
            return;
        }

        RepackDialogContext context{};
        context.Ready = false;
        context.Busy = false;
        context.Font = nullptr;
        context.BoldFont = nullptr;
        for (HWND& label : context.StepLabels)
        {
            label = nullptr;
        }

        // Loader 启动时就拿到了游戏主程序，直接带上，省得再选一次
        context.Options.ExePath = g_KrkrExeFullPath;
        const std::wstring extractOutput = CombinePathLocal(g_KrkrExeDirectory, L"Extractor_Output");
        if (DirectoryExistsLocal(extractOutput))
        {
            context.Options.InputDirectory = extractOutput;
        }
        context.Options.OutputXp3 = DefaultPatchOutputPath(context.Options.ExePath);
        context.Options.Rescramble = true;

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = RepackDialogProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        windowClass.lpszClassName = RepackDialogClassName;
        ::RegisterClassExW(&windowClass);

        HWND hwnd = ::CreateWindowExW(WS_EX_DLGMODALFRAME,
                                      RepackDialogClassName,
                                      L"Cxdec 封包（目录 → XP3）",
                                      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                                      CW_USEDEFAULT,
                                      CW_USEDEFAULT,
                                      880,
                                      480,
                                      owner,
                                      nullptr,
                                      windowClass.hInstance,
                                      &context);
        if (!hwnd)
        {
            return;
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

    void RunStaticKeyExtraction(HWND hwnd)
    {
        if (g_KrkrExeFullPath.empty())
        {
            ::MessageBoxW(hwnd, L"未指定游戏 EXE，请先把游戏 EXE 拖到 Loader 上。", L"CxdecExtractorLoader", MB_OK | MB_ICONERROR);
            return;
        }

        std::wstring keyStaticDll = GetModuleDllPath(L"CxdecKeyStatic.dll");
        HMODULE hKeyStatic = ::LoadLibraryW(keyStaticDll.c_str());
        if (!hKeyStatic)
        {
            ::MessageBoxW(hwnd, FormatString(L"无法加载静态提取模块：\r\n%s", keyStaticDll.c_str()).c_str(), L"CxdecExtractorLoader", MB_OK | MB_ICONERROR);
            return;
        }

        auto extractKey = (BOOL(__stdcall*)(const wchar_t*, const wchar_t*, char*, int))::GetProcAddress(hKeyStatic, "ExtractKey");
        if (!extractKey)
        {
            ::FreeLibrary(hKeyStatic);
            ::MessageBoxW(hwnd, L"静态提取模块缺少 ExtractKey 导出接口。", L"CxdecExtractorLoader", MB_OK | MB_ICONERROR);
            return;
        }

        std::wstring staticOutput = CombinePathLocal(g_KrkrExeDirectory, L"ExtractKey_Output\\Static");
        char errorBuf[2048]{};
        BOOL ok = extractKey(g_KrkrExeFullPath.c_str(), staticOutput.c_str(), errorBuf, sizeof(errorBuf));
        ::FreeLibrary(hKeyStatic);

        if (ok)
        {
            ::MessageBoxW(hwnd, FormatString(L"静态提取完成。\r\n输出目录：%s", staticOutput.c_str()).c_str(), L"CxdecExtractorLoader", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            ::MessageBoxA(hwnd, errorBuf[0] ? errorBuf : "Unknown error", "CxdecExtractorLoader", MB_OK | MB_ICONERROR);
        }
    }

    // ---------- 目标 EXE 导入 ----------

    void LoaderLog(const wchar_t* text)
    {
        ::OutputDebugStringW(text);
        std::wstring path = Path::GetDirectoryName(g_LoaderFullPath) + L"\\CxdecExtractorLoader.log";
        FILE* f = nullptr;
        _wfopen_s(&f, path.c_str(), L"a");
        if (f)
        {
            fwprintf(f, L"%s\n", text);
            fclose(f);
        }
    }

    // 检测并处理 SteamStub 保护壳。
    // 返回 true 表示本次运行已交给脱壳流程（无论用户确认还是取消），调用方应关闭窗口并退出。
    bool RunSteamStubPrecheck(HWND owner, const std::wstring& exePath)
    {
        if (exePath.empty())
        {
            return false;
        }

        std::wstring loaderDir = Path::GetDirectoryName(g_LoaderFullPath) + L"\\";
        HMODULE hUnp = ::LoadLibraryW((loaderDir + L"CxdecExtractordll\\CxdecPeUnpacker.dll").c_str());
        if (!hUnp)
        {
            LoaderLog(L"[Loader] Cannot load CxdecPeUnpacker.dll");
            return false;
        }

        auto D = (bool(*)(const wchar_t*))::GetProcAddress(hUnp, "CxdecPeUnpacker_Detect");
        auto P = (bool(*)(const wchar_t*, const wchar_t*))::GetProcAddress(hUnp, "CxdecPeUnpacker_Process");

        LoaderLog(L"[Loader] Checking SteamStub...");
        const bool packed = (D && P && D(exePath.c_str()));

        if (!packed)
        {
            // 已经脱过壳（或本来就没壳）的 exe 也要继续走后面的「注入 + 打补丁」：
            // 反篡改校验跟壳没有关系，不补一样会在启动的最后一步撞上。
            LoaderLog(L"[Loader] Not packed - will still inject and patch");
        }
        else
        {
            LoaderLog(L"[Loader] SteamStub detected");
            if (IDYES != ::MessageBoxW(owner,
                                       L"检测到 SteamStub 保护壳，需要脱壳处理。\n\n是 - 脱壳并打补丁\n否 - 退出",
                                       L"检测到保护壳", MB_YESNO | MB_ICONQUESTION))
            {
                LoaderLog(L"[Loader] User cancelled");
                ::FreeLibrary(hUnp);
                return true;
            }
            LoaderLog(L"[Loader] User confirmed");
        }
        std::wstring gameDir = Path::GetDirectoryName(exePath) + L"\\";
        std::wstring stem = exePath;
        size_t dot = stem.rfind(L'.');
        if (dot != std::wstring::npos)
        {
            stem = stem.substr(0, dot);
        }
        std::wstring unpacked = stem + L"_unp.exe";
        std::wstring api = gameDir + L"steam_api.dll";
        std::wstring apiBak = api + L".bak";
        std::wstring crackedApi = loaderDir + L"CxdecExtractordll\\steamapi_cra\\steam_api.dll";

        // 只有「游戏目录本来就有 steam_api.dll」**且**「破解版 dll 存在」时才替换。
        // 缺任一个都什么都不做——不能在非 Steam 游戏的目录里凭空造一个 steam_api.dll。
        const bool haveCracked = (::GetFileAttributesW(crackedApi.c_str()) != INVALID_FILE_ATTRIBUTES);
        const bool haveGameApi = (::GetFileAttributesW(api.c_str()) != INVALID_FILE_ATTRIBUTES);
        if (haveCracked && haveGameApi)
        {
            if (::GetFileAttributesW(apiBak.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                ::MoveFileW(api.c_str(), apiBak.c_str());
                LoaderLog(L"[Loader] Backed up steam_api.dll -> .bak");
            }

            if (!::CopyFileW(crackedApi.c_str(), api.c_str(), FALSE))
            {
                // 拷贝失败且新 dll 没到位时，把备份移回来
                if (::GetFileAttributesW(apiBak.c_str()) != INVALID_FILE_ATTRIBUTES &&
                    ::GetFileAttributesW(api.c_str()) == INVALID_FILE_ATTRIBUTES)
                {
                    ::MoveFileW(apiBak.c_str(), api.c_str());
                }
                LoaderLog(L"[Loader] FAIL: steam_api.dll replace failed");
            }
        }
        else
        {
            LoaderLog(haveGameApi ? L"[Loader] WARNING: cracked steam_api.dll missing, skip swap"
                                  : L"[Loader] no steam_api.dll in game dir, skip swap");
        }

        if (packed)
        {
            LoaderLog(L"[Loader] Unpacking...");
            if (!P(exePath.c_str(), unpacked.c_str()))
            {
                LoaderLog(L"[Loader] FAIL: unpack");
                ::FreeLibrary(hUnp);
                return true;
            }
        }
        else
        {
            // 没壳：复制工作副本走同一条注入流程，原 exe 全程不动
            LoaderLog(L"[Loader] Copying working copy...");
            ::DeleteFileW(unpacked.c_str());
            if (!::CopyFileW(exePath.c_str(), unpacked.c_str(), FALSE))
            {
                LoaderLog(L"[Loader] FAIL: copy working copy");
                ::FreeLibrary(hUnp);
                return false;
            }
        }

        LoaderLog(L"[Loader] Injecting...");
        std::wstring dll = loaderDir + L"CxdecExtractordll\\CxdecAntiMalform.dll";
        std::wstring cmd = L"\"" + unpacked + L"\"";
        std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
        cmdline.push_back(L'\0');

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (::CreateProcessW(unpacked.c_str(), cmdline.data(), nullptr, nullptr, FALSE,
                             CREATE_SUSPENDED, nullptr, gameDir.c_str(), &si, &pi))
        {
            LoaderLog(L"[Loader] Process created suspended");
            uint8_t detourData[0x678] = {};
            *(uint32_t*)detourData = 0x678;
            CreateDetourSection(pi.hProcess, detourData, sizeof(detourData));

            SIZE_T bytes = (dll.length() + 1) * sizeof(wchar_t);
            LPVOID remote = ::VirtualAllocEx(pi.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remote)
            {
                ::WriteProcessMemory(pi.hProcess, remote, dll.c_str(), bytes, nullptr);
                auto* loadLibrary = (LPTHREAD_START_ROUTINE)::GetProcAddress(
                    ::GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
                HANDLE thread = ::CreateRemoteThread(pi.hProcess, nullptr, 0, loadLibrary, remote, 0, nullptr);
                if (thread)
                {
                    ::WaitForSingleObject(thread, INFINITE);
                    ::CloseHandle(thread);
                    LoaderLog(L"[Loader] DLL injected");
                }
                else
                {
                    LoaderLog(L"[Loader] FAIL: CreateRemoteThread");
                }
                ::VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);
            }
            else
            {
                LoaderLog(L"[Loader] FAIL: VirtualAllocEx");
            }

            ::ResumeThread(pi.hThread);
            LoaderLog(L"[Loader] Process resumed");
            ::WaitForSingleObject(pi.hProcess, INFINITE);

            DWORD exitCode = 0;
            ::GetExitCodeProcess(pi.hProcess, &exitCode);
            ::CloseHandle(pi.hProcess);
            ::CloseHandle(pi.hThread);
            ::DeleteFileW(unpacked.c_str());
            LoaderLog(L"[Loader] Cleaned working copy");

            if (exitCode == 2 || exitCode == 3)
            {
                // 2 = 这个 exe 已经不需要处理；3 = 需要补但没补上（警告已经弹过了）。
                // 两种都直接进主界面，不再提示"拖回来"，避免套娃。
                LoaderLog(exitCode == 2
                              ? L"[Loader] Nothing to patch, going to main window"
                              : L"[Loader] Patch could not be applied, going to main window");
                ::FreeLibrary(hUnp);
                return false;
            }

            ::MessageBoxW(owner,
                          FormatString(L"补丁注入完成。\n\n已生成：\n%s_crack.exe\n\n"
                                       L"请把它拖到本程序上继续。", stem.c_str()).c_str(),
                          L"处理完成", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            LoaderLog(L"[Loader] FAIL: CreateProcess");
        }

        ::FreeLibrary(hUnp);
        return true;
    }

    std::wstring BrowseForExe(HWND owner)
    {
        std::wstring result;
        HRESULT coInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        IFileOpenDialog* dialog = nullptr;
        if (SUCCEEDED(::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))) && dialog)
        {
            DWORD options = 0u;
            if (SUCCEEDED(dialog->GetOptions(&options)))
            {
                dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST);
            }
            dialog->SetTitle(L"选择游戏主程序");

            COMDLG_FILTERSPEC filters[] =
            {
                { L"可执行文件", L"*.exe" },
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

    // 子控件默认不接收 WM_DROPFILES，会把拖放挡掉。
    // 让每个子控件也接受拖放并原样转交给对话框，实现"窗口任意位置都能放下"。
    LRESULT CALLBACK ForwardDropToParent(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                         UINT_PTR /*idSubclass*/, DWORD_PTR refData)
    {
        if (msg == WM_DROPFILES)
        {
            ::SendMessageW((HWND)refData, WM_DROPFILES, wParam, lParam);
            return 0;
        }
        return ::DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    void EnableDropOnWindowAndChildren(HWND hwnd)
    {
        ::DragAcceptFiles(hwnd, TRUE);
        for (HWND child = ::GetWindow(hwnd, GW_CHILD); child; child = ::GetWindow(child, GW_HWNDNEXT))
        {
            ::DragAcceptFiles(child, TRUE);
            ::SetWindowSubclass(child, ForwardDropToParent, 0u, (DWORD_PTR)hwnd);
        }
    }

    // 校验拖入/选中的路径能不能当游戏主程序用。
    bool IsUsableGameExe(HWND owner, const std::wstring& path)
    {
        if (path.empty())
        {
            return false;
        }

        DWORD attributes = ::GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            ::MessageBoxW(owner, FormatString(L"无法读取该文件：\r\n%s", path.c_str()).c_str(),
                          L"CxdecExtractorLoader", MB_OK | MB_ICONERROR);
            return false;
        }

        if (_wcsicmp(Path::GetExtension(path).c_str(), L".exe") != 0)
        {
            ::MessageBoxW(owner, L"请拖入游戏主程序（.exe 文件）。",
                          L"CxdecExtractorLoader", MB_OK | MB_ICONWARNING);
            return false;
        }

        if (!g_LoaderFullPath.empty() && _wcsicmp(path.c_str(), g_LoaderFullPath.c_str()) == 0)
        {
            ::MessageBoxW(owner, L"这是启动器自身，请选择游戏主程序。",
                          L"CxdecExtractorLoader", MB_OK | MB_ICONWARNING);
            return false;
        }

        return true;
    }

    // ---------- 双击启动时的独立拖放窗口 ----------

    struct SelectExeContext
    {
        std::wstring Chosen;
    };

    INT_PTR CALLBACK SelectExeDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        SelectExeContext* context = (SelectExeContext*)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);

        switch (msg)
        {
            case WM_INITDIALOG:
            {
                context = (SelectExeContext*)lParam;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);
                EnableDropOnWindowAndChildren(hwnd);
                return TRUE;
            }
            case WM_DROPFILES:
            {
                HDROP drop = (HDROP)wParam;
                const UINT count = ::DragQueryFileW(drop, 0xFFFFFFFFu, nullptr, 0u);
                std::wstring path;
                if (count > 0u)
                {
                    const UINT length = ::DragQueryFileW(drop, 0u, nullptr, 0u);
                    path.resize((size_t)length + 1u, L'\0');
                    ::DragQueryFileW(drop, 0u, &path[0], length + 1u);
                    path.resize((size_t)length);
                }
                ::DragFinish(drop);

                if (count > 1u)
                {
                    ::MessageBoxW(hwnd, L"一次只能处理一个游戏主程序，已取用第一个。",
                                  L"CxdecExtractorLoader", MB_OK | MB_ICONINFORMATION);
                }
                if (context && IsUsableGameExe(hwnd, path))
                {
                    context->Chosen = path;
                    ::EndDialog(hwnd, TRUE);
                }
                return TRUE;
            }
            case WM_COMMAND:
                if (!context)
                {
                    break;
                }
                if (LOWORD(wParam) == IDC_BrowseExe)
                {
                    std::wstring path = BrowseForExe(hwnd);
                    if (IsUsableGameExe(hwnd, path))
                    {
                        context->Chosen = path;
                        ::EndDialog(hwnd, TRUE);
                    }
                    return TRUE;
                }
                if (LOWORD(wParam) == IDCANCEL)
                {
                    ::EndDialog(hwnd, FALSE);
                    return TRUE;
                }
                break;
            case WM_CLOSE:
                ::EndDialog(hwnd, FALSE);
                return TRUE;
        }
        return FALSE;
    }

    // 返回 true 表示用户已经选好 exe。
    bool ShowSelectExeDialog(HINSTANCE instance, std::wstring& chosen)
    {
        SelectExeContext context{};
        INT_PTR result = ::DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_SelectExe), nullptr,
                                           SelectExeDialogProc, (LPARAM)&context);
        if (result != TRUE)
        {
            return false;
        }
        chosen = context.Chosen;
        return true;
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
                case IDC_KeyStatic:
                    // 只做静态提取；运行时动态提取已废弃，不再注入 CxdecKeyDumper.dll。
                    RunStaticKeyExtraction(hwnd);
                    break;
                case IDC_Repack:
                    // 封包只在本进程里跑，不进游戏，所以不设 injectDllFileName。
                    ShowRepackDialog(hwnd);
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
                // 用 CREATE_SUSPENDED + RemoteThread 替代 DetourCreateProcessWithDllW
                // 避免 ANSI 编码在日文路径下损坏 DLL 路径
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

                if (CreateProcessW(g_KrkrExeFullPath.c_str(), NULL, NULL, NULL, FALSE,
                                   CREATE_SUSPENDED, NULL, g_KrkrExeDirectory.c_str(), &si, &pi))
                {
                    SIZE_T pathBytes = (injectDllFullPath.length() + 1) * sizeof(wchar_t);
                    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, pathBytes,
                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (pRemote) {
                        WriteProcessMemory(pi.hProcess, pRemote, injectDllFullPath.c_str(), pathBytes, NULL);
                        auto* pLL = (LPTHREAD_START_ROUTINE)GetProcAddress(
                            GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
                        HANDLE hTh = CreateRemoteThread(pi.hProcess, NULL, 0, pLL, pRemote, 0, NULL);
                        if (hTh) { WaitForSingleObject(hTh, INFINITE); CloseHandle(hTh); }
                        VirtualFreeEx(pi.hProcess, pRemote, 0, MEM_RELEASE);
                    }
                    ResumeThread(pi.hThread);

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
            // 只关心第一个参数；空命令行时 CommandLineToArgvW 会返回自身路径，
            // 那种情况必须当成没有参数，否则会往 loader 自己进程里注入
            std::wstring candidate = argv[0];
            if (_wcsicmp(candidate.c_str(), loaderFullPath.c_str()) != 0)
            {
                krkrExeFullPath = candidate;
                krkrExeDirectory = Path::GetDirectoryName(krkrExeFullPath);
            }
        }
        ::LocalFree(argv);
    }

    g_LoaderFullPath = loaderFullPath;
    g_LoaderCurrentDirectory = loaderCurrentDirectory;

    // 双击启动（命令行没带游戏 exe）时，先弹一个专门的拖放窗口拿目标。
    // 参数解析处已排除"空命令行被 CommandLineToArgvW 返回自身路径"的情况。
    if (krkrExeFullPath.empty())
    {
        std::wstring chosen;
        if (!ShowSelectExeDialog(hInstance, chosen))
        {
            return 0;
        }
        krkrExeFullPath = chosen;
        krkrExeDirectory = Path::GetDirectoryName(krkrExeFullPath);
    }

    g_KrkrExeFullPath = krkrExeFullPath;
    g_KrkrExeDirectory = krkrExeDirectory;

    // 带壳的游戏在这里先脱壳；脱壳流程自己会退出，不会再进功能窗口。
    if (RunSteamStubPrecheck(nullptr, krkrExeFullPath))
    {
        return 0;
    }

    HWND hwnd = ::CreateDialogParamW((HINSTANCE)hInstance, MAKEINTRESOURCEW(IDD_MainForm), NULL, LoaderDialogWindProc, 0u);
    if (!hwnd)
    {
        return -1;
    }
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

    return 0;
}
