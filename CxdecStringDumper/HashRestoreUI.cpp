#include "HashRestoreUI.h"

#include <CommCtrl.h>
#include <ShObjIdl.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <strsafe.h>

#include <algorithm>
#include <cwctype>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace
{
    constexpr wchar_t WindowClassName[] = L"CxdecHashRestoreWindow";
    constexpr size_t MaxPathChars = 1024u;
    constexpr UINT WM_RESTORE_PROGRESS = WM_APP + 0x501u;
    constexpr UINT WM_LOAD_PROGRESS = WM_APP + 0x502u;
    constexpr int IDC_SELECT_FOLDER = 2001;
    constexpr int IDC_PROGRESS = 2002;
    constexpr int IDC_STATUS = 2003;
    constexpr int IDC_MAP_INFO = 2004;
    constexpr int IDC_SOURCE_EDIT = 2005;
    constexpr int IDC_SOURCE_BROWSE = 2006;
    constexpr int IDC_MAP_EDIT = 2009;
    constexpr int IDC_MAP_BROWSE = 2010;
    constexpr int IDC_STOP = 2011;
    constexpr int IDC_SUMMARY = 2012;
    constexpr int IDC_CURRENT_FILE = 2013;
    constexpr int IDC_COLLECT_NAMES = 2014;
    constexpr int IDC_IMPORT_MATCH = 2015;
    volatile LONG g_WindowActive = 0;
    HWND g_WindowHandle = nullptr;

    struct ProgressMessage
    {
        unsigned int Current;
        unsigned int Total;
        unsigned int Restored;
        unsigned int Remaining;
        unsigned int Unresolved;
        unsigned int Failed;
        unsigned int DirectoryMapCount;
        unsigned int FileNameMapCount;
        unsigned int SupplementalMapCount;
        bool Finished;
        bool Succeeded;
        wchar_t Detail[MaxPathChars];
    };

    struct LoadProgressMessage
    {
        unsigned int Percent;
        bool Finished;
        wchar_t Summary[MaxPathChars];
        wchar_t CurrentFile[MaxPathChars];
        wchar_t Status[MaxPathChars];
        wchar_t MapInfo[MaxPathChars];
    };

    struct RestoreContext
    {
        HWND Window;
        HWND Button;
        HWND StopButton;
        HWND SourceEdit;
        HWND MapEdit;
        HWND Progress;
        HWND Status;
        HWND Summary;
        HWND CurrentFile;
        HWND MapInfo;
        HFONT UiFont;
        HANDLE CancelEvent;
        LONG LoadingState;
        std::wstring GameDirectory;
        std::wstring HashLogDirectory;
        std::wstring ExternalMapPath;
        std::wstring InitialSourceDirectory;
        bool ShowCrackTools;
        bool Running;
    };

    struct LoadProgressThreadParameter
    {
        HWND Window;
        std::wstring SourceDirectory;
        std::wstring HashLogDirectory;
        std::wstring ExternalMapPath;
    };

    struct RestoreThreadParameter
    {
        HWND Window;
        HANDLE CancelEvent;
        std::wstring SourceDirectory;
        std::wstring HashLogDirectory;
        std::wstring ExternalMapPath;
        std::wstring OutputDirectory;
    };

    struct HashFileCandidate
    {
        std::wstring SourcePath;
        std::wstring RelativePath;
        std::vector<std::wstring> Parts;
        std::wstring DirectoryHash;
        std::wstring FileHash;
    };

    std::wstring MakeRelativePath(const std::wstring& root, const std::wstring& path);
    std::vector<std::wstring> SplitRelativePath(const std::wstring& relativePath);
    void CollectFilesRecursive(const std::wstring& directory, std::vector<std::wstring>& files);
    void AppendUtf8Line(const std::wstring& filePath, const std::wstring& line);
    void SortRecoveredNameList(const std::wstring& filePath);
    void RefreshLoadedProgress(RestoreContext* context);
    void PostProgress(HWND window,
                      unsigned int current,
                      unsigned int total,
                      unsigned int restored,
                      unsigned int remaining,
                      unsigned int unresolved,
                      unsigned int failed,
                      unsigned int directoryMapCount,
                      unsigned int fileNameMapCount,
                      unsigned int supplementalMapCount,
                      bool finished,
                      bool succeeded,
                      const std::wstring& detail);

    std::wstring FormatString(const wchar_t* format, ...)
    {
        wchar_t buffer[1024]{};
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

    std::wstring TrimPathSeparators(std::wstring path)
    {
        while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        {
            path.pop_back();
        }
        return path;
    }

    std::wstring NormalizeRelativeDirectory(std::wstring directory)
    {
        if (directory == L"%EmptyString%")
        {
            return std::wstring();
        }
        std::replace(directory.begin(), directory.end(), L'/', L'\\');
        return TrimPathSeparators(directory);
    }

    std::wstring ToUpperString(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return (wchar_t)towupper(ch); });
        return value;
    }

    bool IsHexStringLength(const std::wstring& value, size_t length)
    {
        if (value.length() != length)
        {
            return false;
        }
        for (wchar_t ch : value)
        {
            if (!iswxdigit(ch))
            {
                return false;
            }
        }
        return true;
    }

    std::wstring BrowseFolder(HWND owner, const std::wstring& title)
    {
        std::wstring result;
        IFileDialog* dialog = nullptr;
        HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
        if (FAILED(hr) || !dialog)
        {
            return result;
        }

        DWORD options = 0u;
        if (SUCCEEDED(dialog->GetOptions(&options)))
        {
            dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        }
        dialog->SetTitle(title.c_str());

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
        return result;
    }

    std::wstring BrowseMapFile(HWND owner)
    {
        std::wstring result;
        IFileDialog* dialog = nullptr;
        HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
        if (FAILED(hr) || !dialog)
        {
            return result;
        }

        DWORD options = 0u;
        if (SUCCEEDED(dialog->GetOptions(&options)))
        {
            dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST);
        }
        dialog->SetTitle(L"选择补充lst映射");
        COMDLG_FILTERSPEC filters[] =
        {
            { L"Hash name maps", L"*.lst;*.log;*.txt" },
            { L"All files", L"*.*" }
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

    HFONT CreateUiFont(HWND hwnd)
    {
        HDC dc = ::GetDC(hwnd);
        int dpiY = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
        if (dc)
        {
            ::ReleaseDC(hwnd, dc);
        }

        return ::CreateFontW(-::MulDiv(9, dpiY, 72),
                             0,
                             0,
                             0,
                             FW_NORMAL,
                             FALSE,
                             FALSE,
                             FALSE,
                             DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE,
                             L"Microsoft YaHei UI");
    }

    BOOL CALLBACK ApplyFontToChild(HWND child, LPARAM font)
    {
        ::SendMessageW(child, WM_SETFONT, (WPARAM)font, TRUE);
        return TRUE;
    }

    void ApplyUiFont(RestoreContext* context)
    {
        if (!context || !context->Window || !context->UiFont)
        {
            return;
        }

        ::SendMessageW(context->Window, WM_SETFONT, (WPARAM)context->UiFont, TRUE);
        ::EnumChildWindows(context->Window, ApplyFontToChild, (LPARAM)context->UiFont);
    }

    bool IsCancelRequested(HANDLE cancelEvent)
    {
        return cancelEvent && ::WaitForSingleObject(cancelEvent, 0u) == WAIT_OBJECT_0;
    }

    void UpdateBusyControls(RestoreContext* context)
    {
        if (!context || !context->Window)
        {
            return;
        }

        bool loading = ::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0;
        bool running = context->Running;
        BOOL editable = (!loading && !running) ? TRUE : FALSE;

        ::EnableWindow(context->SourceEdit, editable);
        ::EnableWindow(context->MapEdit, editable);
        ::EnableWindow(::GetDlgItem(context->Window, IDC_SOURCE_BROWSE), editable);
        ::EnableWindow(::GetDlgItem(context->Window, IDC_MAP_BROWSE), editable);
        ::EnableWindow(::GetDlgItem(context->Window, IDC_COLLECT_NAMES), editable);
        ::EnableWindow(::GetDlgItem(context->Window, IDC_IMPORT_MATCH), editable);
        ::EnableWindow(context->Button, loading ? FALSE : TRUE);
        ::EnableWindow(context->StopButton, FALSE);

        if (context->Button)
        {
            ::SetWindowTextW(context->Button,
                             loading ? L"正在加载..."
                                     : (running ? L"停止实时恢复" : L"开始实时恢复"));
        }
    }

    std::wstring ReadUtf16File(const std::wstring& path)
    {
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return std::wstring();
        }

        LARGE_INTEGER size{};
        if (!::GetFileSizeEx(file, &size) || size.QuadPart <= 0 || (size.QuadPart % sizeof(wchar_t)) != 0)
        {
            ::CloseHandle(file);
            return std::wstring();
        }

        std::wstring content((size_t)(size.QuadPart / sizeof(wchar_t)), L'\0');
        DWORD read = 0u;
        BOOL ok = ::ReadFile(file, content.data(), (DWORD)size.QuadPart, &read, nullptr);
        ::CloseHandle(file);
        if (!ok || read != (DWORD)size.QuadPart)
        {
            return std::wstring();
        }

        if (!content.empty() && content[0] == 0xFEFF)
        {
            content.erase(content.begin());
        }
        return content;
    }

    std::string ReadBinaryFile(const std::wstring& path)
    {
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return std::string();
        }

        LARGE_INTEGER size{};
        if (!::GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 0x7fffffff)
        {
            ::CloseHandle(file);
            return std::string();
        }

        std::string content((size_t)size.QuadPart, '\0');
        DWORD read = 0u;
        BOOL ok = ::ReadFile(file, content.data(), (DWORD)content.size(), &read, nullptr);
        ::CloseHandle(file);
        if (!ok || read != content.size())
        {
            return std::string();
        }
        return content;
    }

    std::wstring DecodeTextFile(const std::wstring& path)
    {
        std::string bytes = ReadBinaryFile(path);
        if (bytes.empty())
        {
            return std::wstring();
        }

        if (bytes.size() >= 2u && (unsigned char)bytes[0] == 0xFF && (unsigned char)bytes[1] == 0xFE)
        {
            size_t count = (bytes.size() - 2u) / sizeof(wchar_t);
            return std::wstring((const wchar_t*)(bytes.data() + 2), count);
        }

        int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), nullptr, 0);
        UINT codePage = CP_UTF8;
        DWORD flags = MB_ERR_INVALID_CHARS;
        if (length <= 0)
        {
            codePage = CP_ACP;
            flags = 0;
            length = ::MultiByteToWideChar(codePage, flags, bytes.data(), (int)bytes.size(), nullptr, 0);
        }

        if (length <= 0)
        {
            return std::wstring();
        }

        std::wstring text((size_t)length, L'\0');
        ::MultiByteToWideChar(codePage, flags, bytes.data(), (int)bytes.size(), text.data(), length);
        return text;
    }

    bool LoadHashMap(const std::wstring& path, bool directoryMap, std::unordered_map<std::wstring, std::wstring>& output)
    {
        output.clear();
        std::wstring content = ReadUtf16File(path);
        if (content.empty())
        {
            return false;
        }

        size_t start = 0u;
        while (start < content.length())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                std::wstring line = content.substr(start, end - start);
                size_t split = line.find(L"##YSig##");
                if (split != std::wstring::npos)
                {
                    std::wstring name = line.substr(0, split);
                    std::wstring hash = ToUpperString(line.substr(split + 8u));
                    if (!hash.empty() && output.find(hash) == output.end())
                    {
                        output.emplace(hash, directoryMap ? NormalizeRelativeDirectory(name) : name);
                    }
                }
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
        return !output.empty();
    }

    unsigned int LoadExternalHashList(const std::wstring& path,
                                      std::unordered_map<std::wstring, std::wstring>& directoryMap,
                                      std::unordered_map<std::wstring, std::wstring>& fileNameMap)
    {
        std::wstring content = DecodeTextFile(path);
        if (content.empty())
        {
            return 0u;
        }

        unsigned int addedCount = 0u;
        size_t start = 0u;
        while (start < content.length())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                std::wstring line = content.substr(start, end - start);
                size_t split = line.find(L':');
                if (split != std::wstring::npos)
                {
                    std::wstring hash = ToUpperString(line.substr(0, split));
                    std::wstring name = line.substr(split + 1u);
                    if (IsHexStringLength(hash, 16u))
                    {
                        if (name == L"/")
                        {
                            name.clear();
                        }
                        if (directoryMap.emplace(hash, NormalizeRelativeDirectory(name)).second)
                        {
                            ++addedCount;
                        }
                    }
                    else if (IsHexStringLength(hash, 64u))
                    {
                        if (fileNameMap.emplace(hash, name).second)
                        {
                            ++addedCount;
                        }
                    }
                }
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
        return addedCount;
    }

    void LoadLineSet(const std::wstring& path, std::unordered_set<std::wstring>& lines)
    {
        std::wstring content = DecodeTextFile(path);
        if (content.empty())
        {
            return;
        }

        size_t start = 0u;
        while (start < content.length())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                lines.insert(content.substr(start, end - start));
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
    }

    bool LoadLineSetWithProgress(const std::wstring& path,
                                 std::unordered_set<std::wstring>& lines,
                                 HWND window,
                                 HANDLE cancelEvent,
                                 unsigned int progressStart,
                                 unsigned int progressEnd,
                                 unsigned int restoredCount,
                                 unsigned int failedCount,
                                 const std::wstring& displayName)
    {
        PostProgress(window,
                     progressStart,
                     100u,
                     restoredCount,
                     0u,
                     0u,
                     failedCount,
                     0u,
                     0u,
                     0u,
                     false,
                     true,
                     L"正在读取 " + displayName + L"...");

        std::wstring content = DecodeTextFile(path);
        if (content.empty())
        {
            PostProgress(window,
                         progressEnd,
                         100u,
                         restoredCount,
                         0u,
                         0u,
                         failedCount,
                         0u,
                         0u,
                         0u,
                         false,
                         true,
                         displayName + L" 为空或不存在，继续恢复。");
            return !IsCancelRequested(cancelEvent);
        }

        unsigned int lastPercent = progressStart;
        unsigned int lineCount = 0u;
        size_t start = 0u;
        while (start < content.length())
        {
            if (IsCancelRequested(cancelEvent))
            {
                return false;
            }

            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                lines.insert(content.substr(start, end - start));
                ++lineCount;
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }

            unsigned int percent = progressStart;
            if (progressEnd > progressStart)
            {
                percent = progressStart + (unsigned int)(((unsigned long long)(progressEnd - progressStart) * start) / content.length());
            }
            if (percent != lastPercent || (lineCount % 4096u) == 0u)
            {
                lastPercent = percent;
                PostProgress(window,
                             percent,
                             100u,
                             restoredCount,
                             0u,
                             0u,
                             failedCount,
                             0u,
                             0u,
                             0u,
                             false,
                             true,
                             FormatString(L"正在加载 %s：%u 行", displayName.c_str(), lineCount));
            }
        }

        PostProgress(window,
                     progressEnd,
                     100u,
                     restoredCount,
                     0u,
                     0u,
                     failedCount,
                     0u,
                     0u,
                     0u,
                     false,
                     true,
                     FormatString(L"%s 加载完成：%u 行", displayName.c_str(), lineCount));
        return true;
    }

    void CountReportStatus(const std::wstring& path,
                           std::unordered_set<std::wstring>& restoredKeys,
                           std::unordered_set<std::wstring>& failedKeys)
    {
        std::wstring content = DecodeTextFile(path);
        if (content.empty())
        {
            return;
        }

        size_t start = 0u;
        while (start < content.length())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                std::wstring line = content.substr(start, end - start);
                if (line.find(L"SourcePath\tDirectoryHash\tFileHash") != 0)
                {
                    std::vector<std::wstring> columns;
                    size_t columnStart = 0u;
                    while (columnStart <= line.length())
                    {
                        size_t columnEnd = line.find(L'\t', columnStart);
                        if (columnEnd == std::wstring::npos)
                        {
                            columnEnd = line.length();
                        }
                        columns.push_back(line.substr(columnStart, columnEnd - columnStart));
                        if (columnEnd == line.length())
                        {
                            break;
                        }
                        columnStart = columnEnd + 1u;
                    }

                    if (columns.size() >= 7u)
                    {
                        std::wstring key = columns[5].empty() ? columns[0] : columns[5];
                        std::wstring status = ToUpperString(columns[6]);
                        if (status == L"OK")
                        {
                            restoredKeys.insert(key);
                            failedKeys.erase(key);
                        }
                        else if (status == L"FAILED")
                        {
                            if (restoredKeys.find(key) == restoredKeys.end())
                            {
                                failedKeys.insert(key);
                            }
                        }
                    }
                }
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
    }

    unsigned int CountCurrentHashFiles(const std::wstring& sourceDirectory)
    {
        if (sourceDirectory.empty())
        {
            return 0u;
        }

        std::vector<std::wstring> files;
        CollectFilesRecursive(sourceDirectory, files);

        unsigned int count = 0u;
        for (const std::wstring& sourcePath : files)
        {
            std::wstring relative = MakeRelativePath(sourceDirectory, sourcePath);
            std::vector<std::wstring> parts = SplitRelativePath(relative);
            if (parts.size() < 3u)
            {
                continue;
            }

            std::wstring dirHash = ToUpperString(parts[parts.size() - 2u]);
            std::wstring fileHash = ToUpperString(parts.back());
            if (IsHexStringLength(dirHash, 16u) && IsHexStringLength(fileHash, 64u))
            {
                ++count;
            }
        }
        return count;
    }

    void BuildHashFileCandidates(const std::wstring& sourceDirectory,
                                 const std::vector<std::wstring>& files,
                                 std::vector<HashFileCandidate>& candidates)
    {
        candidates.clear();
        for (const std::wstring& sourcePath : files)
        {
            std::wstring relative = MakeRelativePath(sourceDirectory, sourcePath);
            std::vector<std::wstring> parts = SplitRelativePath(relative);
            if (parts.size() < 3u)
            {
                continue;
            }

            std::wstring dirHash = ToUpperString(parts[parts.size() - 2u]);
            std::wstring fileHash = ToUpperString(parts.back());
            if (!IsHexStringLength(dirHash, 16u) || !IsHexStringLength(fileHash, 64u))
            {
                continue;
            }

            HashFileCandidate candidate{};
            candidate.SourcePath = sourcePath;
            candidate.RelativePath = relative;
            candidate.Parts = parts;
            candidate.DirectoryHash = dirHash;
            candidate.FileHash = fileHash;
            candidates.push_back(candidate);
        }
    }

    void PostLoadProgress(HWND window,
                          unsigned int percent,
                          bool finished,
                          const std::wstring& summary,
                          const std::wstring& currentFile,
                          const std::wstring& status,
                          const std::wstring& mapInfo)
    {
        LoadProgressMessage* message = (LoadProgressMessage*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LoadProgressMessage));
        if (!message)
        {
            return;
        }

        message->Percent = percent > 100u ? 100u : percent;
        message->Finished = finished;
        StringCchCopyW(message->Summary, _countof(message->Summary), summary.c_str());
        StringCchCopyW(message->CurrentFile, _countof(message->CurrentFile), currentFile.c_str());
        StringCchCopyW(message->Status, _countof(message->Status), status.c_str());
        StringCchCopyW(message->MapInfo, _countof(message->MapInfo), mapInfo.c_str());

        if (!::PostMessageW(window, WM_LOAD_PROGRESS, 0, (LPARAM)message))
        {
            ::HeapFree(::GetProcessHeap(), 0, message);
        }
    }

    DWORD WINAPI LoadProgressThreadProc(LPVOID parameter)
    {
        LoadProgressThreadParameter* load = (LoadProgressThreadParameter*)parameter;
        if (!load)
        {
            return 0u;
        }

        std::unordered_map<std::wstring, std::wstring> directoryMap;
        std::unordered_map<std::wstring, std::wstring> fileNameMap;

        PostLoadProgress(load->Window,
                         5u,
                         false,
                         L"已处理：加载Hash日志...",
                         L"当前文件：DirectoryHash.log",
                         L"正在加载 DirectoryHash.log...",
                         FormatString(L"Hash日志：%s\r\n正在加载目录映射...", load->HashLogDirectory.c_str()));
        LoadHashMap(CombinePath(load->HashLogDirectory, L"DirectoryHash.log"), true, directoryMap);

        PostLoadProgress(load->Window,
                         20u,
                         false,
                         L"已处理：加载Hash日志...",
                         L"当前文件：FileNameHash.log",
                         L"正在加载 FileNameHash.log...",
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 正在加载文件映射...",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size()));
        LoadHashMap(CombinePath(load->HashLogDirectory, L"FileNameHash.log"), false, fileNameMap);

        PostLoadProgress(load->Window,
                         40u,
                         false,
                         L"已处理：加载补充lst...",
                         L"当前文件：补充lst映射",
                         load->ExternalMapPath.empty() ? L"未选择补充lst，跳过。" : L"正在加载补充lst映射...",
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 正在加载补充lst...",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size(),
                                      (unsigned int)fileNameMap.size()));
        unsigned int supplementalMapCount = LoadExternalHashList(load->ExternalMapPath, directoryMap, fileNameMap);

        std::unordered_set<std::wstring> recoveredNameLines;
        PostLoadProgress(load->Window,
                         60u,
                         false,
                         L"已处理：加载恢复映射表...",
                         L"当前文件：HashRestore_RecoveredNames.lst",
                         L"正在加载 HashRestore_RecoveredNames.lst...",
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 补充lst映射：%u条 | 正在加载已记录映射...",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size(),
                                      (unsigned int)fileNameMap.size(),
                                      supplementalMapCount));
        LoadLineSet(CombinePath(load->HashLogDirectory, L"HashRestore_RecoveredNames.lst"), recoveredNameLines);

        std::unordered_set<std::wstring> restoredKeys;
        std::unordered_set<std::wstring> failedKeys;
        PostLoadProgress(load->Window,
                         75u,
                         false,
                         L"已处理：读取恢复报告...",
                         L"当前文件：HashRestore_Report.tsv",
                         L"正在读取历史恢复报告...",
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 补充lst映射：%u条 | 已记录映射：%u",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size(),
                                      (unsigned int)fileNameMap.size(),
                                      supplementalMapCount,
                                      (unsigned int)recoveredNameLines.size()));
        if (!load->SourceDirectory.empty())
        {
            CountReportStatus(CombinePath(load->SourceDirectory, L"HashRestore_Report.tsv"), restoredKeys, failedKeys);
            CountReportStatus(CombinePath(CombinePath(load->SourceDirectory, L"Extractor_Log"), L"HashRestore_Report.tsv"), restoredKeys, failedKeys);
        }

        unsigned int restoredCount = (unsigned int)restoredKeys.size();
        unsigned int failedCount = (unsigned int)failedKeys.size();

        PostLoadProgress(load->Window,
                         88u,
                         false,
                         L"已处理：扫描纯Hash目录...",
                         L"当前文件：扫描中...",
                         L"正在扫描当前待恢复文件数量...",
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 补充lst映射：%u条 | 已记录映射：%u",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size(),
                                      (unsigned int)fileNameMap.size(),
                                      supplementalMapCount,
                                      (unsigned int)recoveredNameLines.size()));
        unsigned int remainingCount = CountCurrentHashFiles(load->SourceDirectory);
        unsigned int total = restoredCount + failedCount + remainingCount;
        unsigned int processed = restoredCount + failedCount;
        unsigned int percent = total == 0u ? 0u : (processed * 100u) / total;

        PostLoadProgress(load->Window,
                         percent,
                         true,
                         FormatString(L"已处理：%u/%u | 进度：%u%% | 已恢复 %u | 剩余 %u | 失败 %u",
                                      processed,
                                      total,
                                      percent,
                                      restoredCount,
                                      remainingCount,
                                      failedCount),
                         L"当前文件：-",
                         recoveredNameLines.empty()
                             ? L"已加载目录状态，未发现 HashRestore_RecoveredNames.lst。"
                             : FormatString(L"已加载已有进度，恢复映射表 %u 条。", (unsigned int)recoveredNameLines.size()),
                         FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 补充lst映射：%u条 | 已记录映射：%u | %s",
                                      load->HashLogDirectory.c_str(),
                                      (unsigned int)directoryMap.size(),
                                      (unsigned int)fileNameMap.size(),
                                      supplementalMapCount,
                                      (unsigned int)recoveredNameLines.size(),
                                      load->ExternalMapPath.empty() ? L"（无）" : load->ExternalMapPath.c_str()));

        delete load;
        return 0u;
    }

    void RefreshLoadedProgress(RestoreContext* context)
    {
        if (!context || context->Running)
        {
            return;
        }
        if (::InterlockedCompareExchange(&context->LoadingState, 1, 0) != 0)
        {
            return;
        }
        UpdateBusyControls(context);

        LoadProgressThreadParameter* parameter = new LoadProgressThreadParameter{};
        parameter->Window = context->Window;
        parameter->SourceDirectory = GetWindowTextString(context->SourceEdit);
        parameter->HashLogDirectory = context->HashLogDirectory;
        parameter->ExternalMapPath = GetWindowTextString(context->MapEdit);

        ::SendMessageW(context->Progress, PBM_SETPOS, 0, 0);
        ::SendMessageW(context->Progress, PBM_SETMARQUEE, TRUE, 30);
        ::SetWindowTextW(context->Summary, L"已处理：加载状态中...");
        ::SetWindowTextW(context->CurrentFile, L"当前文件：准备加载...");
        ::SetWindowTextW(context->Status, L"正在加载已有映射与恢复进度...");

        HANDLE thread = ::CreateThread(nullptr, 0u, LoadProgressThreadProc, parameter, 0u, nullptr);
        if (!thread)
        {
            delete parameter;
            ::InterlockedExchange(&context->LoadingState, 0);
            UpdateBusyControls(context);
            ::SendMessageW(context->Progress, PBM_SETMARQUEE, FALSE, 0);
            ::SetWindowTextW(context->Status, L"创建加载线程失败。");
            return;
        }
        ::CloseHandle(thread);
    }

    std::wstring GetTimestampString()
    {
        SYSTEMTIME time{};
        ::GetLocalTime(&time);
        return FormatString(L"%04u_%02u_%02u_%02u_%02u", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
    }

    void WriteUtf16Lines(const std::wstring& filePath, const std::vector<std::wstring>& lines)
    {
        HANDLE file = ::CreateFileW(filePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        const wchar_t bom = 0xFEFF;
        DWORD written = 0u;
        ::WriteFile(file, &bom, sizeof(bom), &written, nullptr);
        for (const std::wstring& line : lines)
        {
            ::WriteFile(file, line.c_str(), (DWORD)(line.length() * sizeof(wchar_t)), &written, nullptr);
            ::WriteFile(file, L"\r\n", 4u, &written, nullptr);
        }
        ::CloseHandle(file);
    }

    void CollectNameCandidatesRecursive(const std::wstring& root,
                                        const std::wstring& directory,
                                        std::unordered_set<std::wstring>& directoryNames,
                                        std::unordered_set<std::wstring>& fileNames)
    {
        std::wstring pattern = CombinePath(directory, L"*");
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(pattern.c_str(), &data);
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

            std::wstring fullPath = CombinePath(directory, data.cFileName);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                std::wstring relative = MakeRelativePath(root, fullPath);
                std::replace(relative.begin(), relative.end(), L'\\', L'/');
                if (!relative.empty())
                {
                    directoryNames.insert(relative);
                }
                CollectNameCandidatesRecursive(root, fullPath, directoryNames, fileNames);
            }
            else
            {
                std::wstring relative = MakeRelativePath(root, fullPath);
                std::replace(relative.begin(), relative.end(), L'\\', L'/');
                if (!relative.empty())
                {
                    fileNames.insert(relative);
                    std::vector<std::wstring> parts = SplitRelativePath(relative);
                    if (!parts.empty())
                    {
                        fileNames.insert(parts.back());
                    }
                }
            }
        } while (::FindNextFileW(find, &data));

        ::FindClose(find);
    }

    std::vector<std::wstring> SortedLinesFromSet(const std::unordered_set<std::wstring>& values)
    {
        std::vector<std::wstring> lines(values.begin(), values.end());
        std::sort(lines.begin(), lines.end(), [](const std::wstring& left, const std::wstring& right)
        {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        });
        return lines;
    }

    void CollectHashCrackCandidates(HWND owner, RestoreContext* context)
    {
        std::wstring sourceDirectory = BrowseFolder(owner, L"选择需要收集候选名称的目录");
        if (sourceDirectory.empty())
        {
            return;
        }

        ::SHCreateDirectoryExW(nullptr, context->HashLogDirectory.c_str(), nullptr);
        std::unordered_set<std::wstring> directoryNames;
        std::unordered_set<std::wstring> fileNames;
        directoryNames.insert(L"/");
        CollectNameCandidatesRecursive(sourceDirectory, sourceDirectory, directoryNames, fileNames);

        std::wstring stamp = GetTimestampString();
        std::wstring dirsPath = CombinePath(context->HashLogDirectory, L"dirs_" + stamp + L".txt");
        std::wstring filesPath = CombinePath(context->HashLogDirectory, L"files_" + stamp + L".txt");
        WriteUtf16Lines(dirsPath, SortedLinesFromSet(directoryNames));
        WriteUtf16Lines(filesPath, SortedLinesFromSet(fileNames));

        SetWindowTextW(context->Status,
                       FormatString(L"候选名称收集完成：目录=%u 文件=%u",
                                    (unsigned int)directoryNames.size(),
                                    (unsigned int)fileNames.size()).c_str());
        SetWindowTextW(context->CurrentFile,
                       FormatString(L"Saved: %s | %s", dirsPath.c_str(), filesPath.c_str()).c_str());
    }

    bool ImportMatchFileToRecoveredList(const std::wstring& matchPath, const std::wstring& recoveredListPath)
    {
        std::wstring content = DecodeTextFile(matchPath);
        if (content.empty())
        {
            return false;
        }

        std::unordered_set<std::wstring> recoveredLines;
        LoadLineSet(recoveredListPath, recoveredLines);
        bool changed = false;
        size_t start = 0u;
        while (start < content.length())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.length();
            }

            if (end > start)
            {
                std::wstring line = content.substr(start, end - start);
                size_t split = line.rfind(L',');
                if (split != std::wstring::npos)
                {
                    std::wstring name = line.substr(0, split);
                    std::wstring hash = ToUpperString(line.substr(split + 1u));
                    if ((IsHexStringLength(hash, 16u) || IsHexStringLength(hash, 64u)) && !name.empty())
                    {
                        std::replace(name.begin(), name.end(), L'\\', L'/');
                        if (name == L"%EmptyString%")
                        {
                            name = L"/";
                        }
                        std::wstring recoveredLine = hash + L":" + name;
                        if (recoveredLines.insert(recoveredLine).second)
                        {
                            AppendUtf8Line(recoveredListPath, recoveredLine + L"\r\n");
                            changed = true;
                        }
                    }
                }
            }

            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }

        if (changed)
        {
            SortRecoveredNameList(recoveredListPath);
        }
        return true;
    }

    void CollectFilesRecursive(const std::wstring& directory, std::vector<std::wstring>& files)
    {
        std::wstring pattern = CombinePath(directory, L"*");
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(pattern.c_str(), &data);
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

            std::wstring fullPath = CombinePath(directory, data.cFileName);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (_wcsicmp(data.cFileName, L"ExtractLog") == 0 || _wcsicmp(data.cFileName, L"Extractor_Log") == 0)
                {
                    continue;
                }
                CollectFilesRecursive(fullPath, files);
            }
            else
            {
                files.push_back(fullPath);
            }
        } while (::FindNextFileW(find, &data));

        ::FindClose(find);
    }

    std::wstring MakeRelativePath(const std::wstring& root, const std::wstring& path)
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

    std::vector<std::wstring> SplitRelativePath(const std::wstring& relativePath)
    {
        std::vector<std::wstring> parts;
        size_t start = 0u;
        while (start < relativePath.length())
        {
            size_t end = relativePath.find_first_of(L"\\/", start);
            if (end == std::wstring::npos)
            {
                end = relativePath.length();
            }
            if (end > start)
            {
                parts.push_back(relativePath.substr(start, end - start));
            }
            start = end + 1u;
        }
        return parts;
    }

    std::wstring JoinPathParts(const std::vector<std::wstring>& parts, size_t begin, size_t end)
    {
        std::wstring result;
        for (size_t index = begin; index < end && index < parts.size(); ++index)
        {
            result = result.empty() ? parts[index] : CombinePath(result, parts[index]);
        }
        return result;
    }

    bool EnsureDirectoryForFile(const std::wstring& filePath)
    {
        wchar_t directory[MaxPathChars]{};
        StringCchCopyW(directory, _countof(directory), filePath.c_str());
        if (!PathRemoveFileSpecW(directory))
        {
            return true;
        }
        return ::SHCreateDirectoryExW(nullptr, directory, nullptr) == ERROR_SUCCESS
            || ::GetFileAttributesW(directory) != INVALID_FILE_ATTRIBUTES;
    }

    std::wstring MakeUniquePath(const std::wstring& path)
    {
        if (::GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            return path;
        }

        wchar_t directory[MaxPathChars]{};
        wchar_t baseName[MaxPathChars]{};
        wchar_t extension[MaxPathChars]{};
        StringCchCopyW(directory, _countof(directory), path.c_str());
        PathRemoveFileSpecW(directory);
        StringCchCopyW(baseName, _countof(baseName), PathFindFileNameW(path.c_str()));
        StringCchCopyW(extension, _countof(extension), PathFindExtensionW(path.c_str()));
        if (extension[0] != L'\0')
        {
            baseName[wcslen(baseName) - wcslen(extension)] = L'\0';
        }

        for (unsigned int index = 1u; index < 10000u; ++index)
        {
            std::wstring candidate = CombinePath(directory, FormatString(L"%s__dup%u%s", baseName, index, extension));
            if (::GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                return candidate;
            }
        }
        return path;
    }

    void AppendUtf8Line(const std::wstring& filePath, const std::wstring& line)
    {
        HANDLE file = ::CreateFileW(filePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        int utf8Length = ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), nullptr, 0, nullptr, nullptr);
        if (utf8Length > 0)
        {
            std::string utf8((size_t)utf8Length, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), utf8.data(), utf8Length, nullptr, nullptr);
            DWORD written = 0u;
            ::WriteFile(file, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        }
        ::CloseHandle(file);
    }

    void WriteUtf8Text(const std::wstring& filePath, const std::wstring& text)
    {
        HANDLE file = ::CreateFileW(filePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        int utf8Length = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.length(), nullptr, 0, nullptr, nullptr);
        if (utf8Length > 0)
        {
            std::string utf8((size_t)utf8Length, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.length(), utf8.data(), utf8Length, nullptr, nullptr);
            DWORD written = 0u;
            ::WriteFile(file, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        }
        ::CloseHandle(file);
    }

    void WriteRestoreLog(const std::wstring& logDirectory, const wchar_t* stage, const wchar_t* format, ...)
    {
        wchar_t message[2048]{};
        va_list ap;
        va_start(ap, format);
        int count = _vsnwprintf_s(message, _countof(message), _TRUNCATE, format, ap);
        va_end(ap);
        if (count <= 0)
        {
            return;
        }

        SYSTEMTIME time{};
        ::GetLocalTime(&time);
        std::wstring line = FormatString(L"%04u-%02u-%02u %02u:%02u:%02u | %s | %s\r\n",
                                         time.wYear,
                                         time.wMonth,
                                         time.wDay,
                                         time.wHour,
                                         time.wMinute,
                                         time.wSecond,
                                         stage,
                                         message);
        AppendUtf8Line(CombinePath(logDirectory, L"HashRestore.log"), line);
    }

    struct HashNameEntry
    {
        std::wstring Line;
        std::wstring Hash;
        std::wstring Name;
        int Rank;
    };

    HashNameEntry ParseHashNameLine(const std::wstring& line)
    {
        HashNameEntry entry{};
        entry.Line = line;
        entry.Rank = 3;

        size_t split = line.find(L':');
        if (split == std::wstring::npos)
        {
            entry.Name = line;
            return entry;
        }

        entry.Hash = ToUpperString(line.substr(0, split));
        entry.Name = line.substr(split + 1u);
        std::replace(entry.Name.begin(), entry.Name.end(), L'\\', L'/');

        if (IsHexStringLength(entry.Hash, 16u))
        {
            entry.Rank = entry.Name == L"/" ? 0 : 1;
        }
        else if (IsHexStringLength(entry.Hash, 64u))
        {
            entry.Rank = 2;
        }
        return entry;
    }

    void SortRecoveredNameList(const std::wstring& filePath)
    {
        std::unordered_set<std::wstring> lines;
        LoadLineSet(filePath, lines);
        if (lines.empty())
        {
            return;
        }

        std::vector<HashNameEntry> entries;
        entries.reserve(lines.size());
        for (const std::wstring& line : lines)
        {
            entries.push_back(ParseHashNameLine(line));
        }

        std::sort(entries.begin(), entries.end(), [](const HashNameEntry& left, const HashNameEntry& right)
        {
            if (left.Rank != right.Rank)
            {
                return left.Rank < right.Rank;
            }
            int nameCompare = _wcsicmp(left.Name.c_str(), right.Name.c_str());
            if (nameCompare != 0)
            {
                return nameCompare < 0;
            }
            int hashCompare = _wcsicmp(left.Hash.c_str(), right.Hash.c_str());
            if (hashCompare != 0)
            {
                return hashCompare < 0;
            }
            return _wcsicmp(left.Line.c_str(), right.Line.c_str()) < 0;
        });

        std::wstring text;
        for (const HashNameEntry& entry : entries)
        {
            text += entry.Line;
            text += L"\r\n";
        }
        WriteUtf8Text(filePath, text);
    }

    std::wstring EscapeTsv(std::wstring value)
    {
        std::replace(value.begin(), value.end(), L'\t', L' ');
        std::replace(value.begin(), value.end(), L'\r', L' ');
        std::replace(value.begin(), value.end(), L'\n', L' ');
        return value;
    }

    void AppendReportLine(const std::wstring& outputDirectory,
                          const std::wstring& sourcePath,
                          const std::wstring& directoryHash,
                          const std::wstring& fileHash,
                          const std::wstring& directoryName,
                          const std::wstring& fileName,
                          const std::wstring& targetPath,
                          const std::wstring& status)
    {
        std::wstring line = EscapeTsv(sourcePath) + L"\t"
            + EscapeTsv(directoryHash) + L"\t"
            + EscapeTsv(fileHash) + L"\t"
            + EscapeTsv(directoryName) + L"\t"
            + EscapeTsv(fileName) + L"\t"
            + EscapeTsv(targetPath) + L"\t"
            + EscapeTsv(status) + L"\r\n";
        AppendUtf8Line(CombinePath(outputDirectory, L"HashRestore_Report.tsv"), line);
    }

    void AppendRecoveredNameLine(const std::wstring& outputDirectory,
                                 std::unordered_set<std::wstring>& knownLines,
                                 const std::wstring& hash,
                                 const std::wstring& name)
    {
        if (hash.empty() || name.empty())
        {
            return;
        }

        std::wstring normalizedName = name;
        std::replace(normalizedName.begin(), normalizedName.end(), L'\\', L'/');
        std::wstring line = hash + L":" + normalizedName;
        if (knownLines.insert(line).second)
        {
            AppendUtf8Line(CombinePath(outputDirectory, L"HashRestore_RecoveredNames.lst"), line + L"\r\n");
        }
    }

    void PostProgress(HWND window,
                      unsigned int current,
                      unsigned int total,
                      unsigned int restored,
                      unsigned int remaining,
                      unsigned int unresolved,
                      unsigned int failed,
                      unsigned int directoryMapCount,
                      unsigned int fileNameMapCount,
                      unsigned int supplementalMapCount,
                      bool finished,
                      bool succeeded,
                      const std::wstring& detail)
    {
        ProgressMessage* message = (ProgressMessage*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ProgressMessage));
        if (!message)
        {
            return;
        }

        message->Current = current;
        message->Total = total;
        message->Restored = restored;
        message->Remaining = remaining;
        message->Unresolved = unresolved;
        message->Failed = failed;
        message->DirectoryMapCount = directoryMapCount;
        message->FileNameMapCount = fileNameMapCount;
        message->SupplementalMapCount = supplementalMapCount;
        message->Finished = finished;
        message->Succeeded = succeeded;
        StringCchCopyW(message->Detail, _countof(message->Detail), detail.c_str());

        if (!::PostMessageW(window, WM_RESTORE_PROGRESS, 0, (LPARAM)message))
        {
            ::HeapFree(::GetProcessHeap(), 0, message);
        }
    }

    DWORD WINAPI RestoreThreadProc(LPVOID parameter)
    {
        RestoreThreadParameter* restore = (RestoreThreadParameter*)parameter;

        std::unordered_set<std::wstring> restoredSources;
        std::unordered_set<std::wstring> recoveredNameLines;
        unsigned int restoredCount = 0u;
        unsigned int failedCount = 0u;
        unsigned int lastLoggedProcessed = (unsigned int)-1;
        unsigned int lastLoggedRemaining = (unsigned int)-1;
        unsigned int lastLoggedDirectoryMapCount = (unsigned int)-1;
        unsigned int lastLoggedFileNameMapCount = (unsigned int)-1;
        bool reportHeaderWritten = false;
        std::wstring logDirectory = CombinePath(restore->SourceDirectory, L"Extractor_Log");

        ::SHCreateDirectoryExW(nullptr, restore->HashLogDirectory.c_str(), nullptr);
        ::SHCreateDirectoryExW(nullptr, logDirectory.c_str(), nullptr);
        WriteRestoreLog(logDirectory,
                        L"START",
                        L"source=\"%s\" hashLog=\"%s\" supplemental=\"%s\"",
                        restore->SourceDirectory.c_str(),
                        restore->HashLogDirectory.c_str(),
                        restore->ExternalMapPath.empty() ? L"(none)" : restore->ExternalMapPath.c_str());
        PostProgress(restore->Window,
                     0u,
                     100u,
                     restoredCount,
                     0u,
                     0u,
                     failedCount,
                     0u,
                     0u,
                     0u,
                     false,
                     true,
                     L"正在加载恢复映射表...");
        if (!LoadLineSetWithProgress(CombinePath(restore->HashLogDirectory, L"HashRestore_RecoveredNames.lst"),
                                     recoveredNameLines,
                                     restore->Window,
                                     restore->CancelEvent,
                                     0u,
                                     8u,
                                     restoredCount,
                                     failedCount,
                                     L"HashRestore_RecoveredNames.lst"))
        {
            WriteRestoreLog(logDirectory, L"STOP", L"user canceled while loading recovered name map");
            PostProgress(restore->Window,
                         0u,
                         0u,
                         restoredCount,
                         0u,
                         0u,
                         failedCount,
                         0u,
                         0u,
                         0u,
                         true,
                         false,
                         L"已停止：加载恢复映射表时中断");
            delete restore;
            return 0u;
        }
        WriteRestoreLog(logDirectory, L"STATE", L"loadedRecoveredNameMap=%u", (unsigned int)recoveredNameLines.size());

        while (!IsCancelRequested(restore->CancelEvent))
        {
            std::unordered_map<std::wstring, std::wstring> directoryMap;
            std::unordered_map<std::wstring, std::wstring> fileNameMap;
            if (!LoadHashMap(CombinePath(restore->HashLogDirectory, L"DirectoryHash.log"), true, directoryMap)
                || !LoadHashMap(CombinePath(restore->HashLogDirectory, L"FileNameHash.log"), false, fileNameMap))
            {
                if (lastLoggedDirectoryMapCount != 0u || lastLoggedFileNameMapCount != 0u)
                {
                    WriteRestoreLog(logDirectory, L"WAIT", L"waiting for DirectoryHash.log and FileNameHash.log");
                    lastLoggedDirectoryMapCount = 0u;
                    lastLoggedFileNameMapCount = 0u;
                }
                PostProgress(restore->Window,
                             0u,
                             0u,
                             restoredCount,
                             0u,
                             0u,
                             failedCount,
                             0u,
                             0u,
                             0u,
                             false,
                             true,
                             L"监听中...等待Hash日志");
                ::Sleep(1000u);
                continue;
            }

            PostProgress(restore->Window,
                         8u,
                         100u,
                         restoredCount,
                         0u,
                         0u,
                         failedCount,
                         (unsigned int)directoryMap.size(),
                         (unsigned int)fileNameMap.size(),
                         0u,
                         false,
                         true,
                         restore->ExternalMapPath.empty() ? L"未选择补充lst映射，跳过。" : L"正在加载补充lst映射...");
            unsigned int supplementalMapCount = LoadExternalHashList(restore->ExternalMapPath, directoryMap, fileNameMap);
            const unsigned int directoryMapCount = (unsigned int)directoryMap.size();
            const unsigned int fileNameMapCount = (unsigned int)fileNameMap.size();

            if (IsCancelRequested(restore->CancelEvent))
            {
                break;
            }

            std::vector<std::wstring> files;
            PostProgress(restore->Window,
                         10u,
                         100u,
                         restoredCount,
                         0u,
                         0u,
                         failedCount,
                         directoryMapCount,
                         fileNameMapCount,
                         supplementalMapCount,
                         false,
                         true,
                         L"正在扫描纯Hash目录...");
            CollectFilesRecursive(restore->SourceDirectory, files);
            std::vector<HashFileCandidate> candidates;
            BuildHashFileCandidates(restore->SourceDirectory, files, candidates);

            if (!reportHeaderWritten)
            {
                AppendUtf8Line(CombinePath(logDirectory, L"HashRestore_Report.tsv"), L"SourcePath\tDirectoryHash\tFileHash\tDirectoryName\tFileName\tTargetPath\tStatus\r\n");
                reportHeaderWritten = true;
            }

            unsigned int pendingCount = 0u;
            std::wstring lastDetail = L"监听中...";
            unsigned int scannedCount = 0u;
            const unsigned int candidateTotal = (unsigned int)candidates.size();

            for (const HashFileCandidate& candidate : candidates)
            {
                if (IsCancelRequested(restore->CancelEvent))
                {
                    break;
                }

                ++scannedCount;
                const std::wstring& relative = candidate.RelativePath;
                if (restoredSources.find(relative) != restoredSources.end())
                {
                    continue;
                }

                lastDetail = relative;

                auto dirIt = directoryMap.find(candidate.DirectoryHash);
                auto fileIt = fileNameMap.find(candidate.FileHash);
                if (dirIt == directoryMap.end() || fileIt == fileNameMap.end())
                {
                    ++pendingCount;
                    if ((scannedCount % 128u) == 0u || scannedCount == candidateTotal)
                    {
                        unsigned int processedNow = restoredCount + failedCount;
                        PostProgress(restore->Window,
                                     processedNow,
                                     processedNow + pendingCount,
                                     restoredCount,
                                     pendingCount,
                                     pendingCount,
                                     failedCount,
                                     directoryMapCount,
                                     fileNameMapCount,
                                     supplementalMapCount,
                                     false,
                                     true,
                                     FormatString(L"正在检查：%u/%u %s", scannedCount, candidateTotal, relative.c_str()));
                    }
                    continue;
                }

                std::wstring packageRelative = JoinPathParts(candidate.Parts, 0u, candidate.Parts.size() - 2u);
                std::wstring targetRelative = packageRelative;
                if (!dirIt->second.empty())
                {
                    targetRelative = targetRelative.empty() ? dirIt->second : CombinePath(targetRelative, dirIt->second);
                }
                targetRelative = CombinePath(targetRelative, fileIt->second);
                std::wstring targetPath = MakeUniquePath(CombinePath(restore->SourceDirectory, targetRelative));

                bool moved = false;
                if (EnsureDirectoryForFile(targetPath))
                {
                    moved = ::MoveFileW(candidate.SourcePath.c_str(), targetPath.c_str()) != FALSE;
                    if (!moved)
                    {
                        moved = ::CopyFileW(candidate.SourcePath.c_str(), targetPath.c_str(), FALSE) != FALSE
                            && ::DeleteFileW(candidate.SourcePath.c_str()) != FALSE;
                    }
                }

                if (moved)
                {
                    ++restoredCount;
                    restoredSources.insert(relative);
                    restoredSources.insert(targetRelative);
                    AppendRecoveredNameLine(restore->HashLogDirectory, recoveredNameLines, candidate.DirectoryHash, dirIt->second.empty() ? L"/" : dirIt->second);
                    AppendRecoveredNameLine(restore->HashLogDirectory, recoveredNameLines, candidate.FileHash, fileIt->second);
                    WriteRestoreLog(logDirectory,
                                    L"RESTORED",
                                    L"source=\"%s\" target=\"%s\" dirHash=%s dirName=\"%s\" fileHash=%s fileName=\"%s\"",
                                    relative.c_str(),
                                    targetRelative.c_str(),
                                    candidate.DirectoryHash.c_str(),
                                    dirIt->second.empty() ? L"/" : dirIt->second.c_str(),
                                    candidate.FileHash.c_str(),
                                    fileIt->second.c_str());
                    AppendReportLine(logDirectory, relative, candidate.DirectoryHash, candidate.FileHash, dirIt->second, fileIt->second, targetPath, L"OK");
                    lastDetail = targetRelative;
                }
                else
                {
                    ++failedCount;
                    WriteRestoreLog(logDirectory,
                                    L"FAILED",
                                    L"source=\"%s\" target=\"%s\" dirHash=%s dirName=\"%s\" fileHash=%s fileName=\"%s\" error=%u",
                                    relative.c_str(),
                                    targetPath.c_str(),
                                    candidate.DirectoryHash.c_str(),
                                    dirIt->second.empty() ? L"/" : dirIt->second.c_str(),
                                    candidate.FileHash.c_str(),
                                    fileIt->second.c_str(),
                                    ::GetLastError());
                    AppendUtf8Line(CombinePath(logDirectory, L"HashRestore_Unresolved.log"), FormatString(L"FAILED\t%s\t%s\r\n", relative.c_str(), targetPath.c_str()));
                    AppendReportLine(logDirectory, relative, candidate.DirectoryHash, candidate.FileHash, dirIt->second, fileIt->second, targetPath, L"FAILED");
                }

                if ((scannedCount % 64u) == 0u || scannedCount == candidateTotal || moved)
                {
                    unsigned int displayTotalNow = restoredCount + pendingCount + failedCount;
                    unsigned int processedNow = restoredCount + failedCount;
                    PostProgress(restore->Window,
                                 processedNow,
                                 displayTotalNow,
                                 restoredCount,
                                 pendingCount,
                                 pendingCount,
                                 failedCount,
                                 directoryMapCount,
                                 fileNameMapCount,
                                 supplementalMapCount,
                                 false,
                                 true,
                                 FormatString(L"正在恢复：%u/%u %s", scannedCount, candidateTotal, lastDetail.c_str()));
                }
            }

            unsigned int displayTotal = restoredCount + pendingCount + failedCount;
            unsigned int processedCount = restoredCount + failedCount;
            if (processedCount != lastLoggedProcessed
                || pendingCount != lastLoggedRemaining
                || directoryMapCount != lastLoggedDirectoryMapCount
                || fileNameMapCount != lastLoggedFileNameMapCount)
            {
                unsigned int percent = displayTotal == 0u ? 0u : (processedCount * 100u) / displayTotal;
                WriteRestoreLog(logDirectory,
                                L"SCAN",
                                L"processed=%u total=%u percent=%u restored=%u remaining=%u failed=%u dirMap=%u fileMap=%u supplemental=%u",
                                processedCount,
                                displayTotal,
                                percent,
                                restoredCount,
                                pendingCount,
                                failedCount,
                                directoryMapCount,
                                fileNameMapCount,
                                supplementalMapCount);
                lastLoggedProcessed = processedCount;
                lastLoggedRemaining = pendingCount;
                lastLoggedDirectoryMapCount = directoryMapCount;
                lastLoggedFileNameMapCount = fileNameMapCount;
            }
            PostProgress(restore->Window,
                         processedCount,
                         displayTotal,
                         restoredCount,
                         pendingCount,
                         pendingCount,
                         failedCount,
                         directoryMapCount,
                         fileNameMapCount,
                         supplementalMapCount,
                         false,
                         true,
                         lastDetail);

            ::Sleep(1000u);
        }

        SortRecoveredNameList(CombinePath(restore->HashLogDirectory, L"HashRestore_RecoveredNames.lst"));

        std::wstring final = FormatString(L"已停止 | 已恢复 %u | 失败 %u", restoredCount, failedCount);
        WriteRestoreLog(logDirectory, L"STOP", L"restored=%u failed=%u recoveredNameMapSorted=1", restoredCount, failedCount);
        PostProgress(restore->Window,
                     restoredCount + failedCount,
                     restoredCount + failedCount,
                     restoredCount,
                     0u,
                     0u,
                     failedCount,
                     0u,
                     0u,
                     0u,
                     true,
                     false,
                     final);

        delete restore;
        return 0u;
    }

    void StartRestore(RestoreContext* context)
    {
        if (!context)
        {
            return;
        }
        if (context->Running)
        {
            SetWindowTextW(context->Status, L"实时恢复已经在运行，请先停止当前任务。");
            return;
        }
        if (::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
        {
            SetWindowTextW(context->Status, L"正在加载映射与历史进度，请等待完成后再启动实时恢复。");
            return;
        }

        std::wstring sourceDirectory = GetWindowTextString(context->SourceEdit);
        if (sourceDirectory.empty())
        {
            sourceDirectory = BrowseFolder(context->Window, L"选择需要恢复的 Extractor_Output 目录");
            if (!sourceDirectory.empty())
            {
                SetWindowTextW(context->SourceEdit, sourceDirectory.c_str());
            }
        }
        if (sourceDirectory.empty())
        {
            return;
        }

        std::wstring externalMapPath = GetWindowTextString(context->MapEdit);

        RestoreThreadParameter* parameter = new RestoreThreadParameter{};
        parameter->Window = context->Window;
        parameter->CancelEvent = context->CancelEvent;
        parameter->SourceDirectory = sourceDirectory;
        parameter->HashLogDirectory = context->HashLogDirectory;
        parameter->ExternalMapPath = externalMapPath;
        parameter->OutputDirectory = sourceDirectory;

        ResetEvent(context->CancelEvent);
        context->Running = true;
        UpdateBusyControls(context);
        SetWindowTextW(context->Status, L"正在准备实时恢复...");
        SetWindowTextW(context->Summary, L"已处理：加载映射中...");
        SetWindowTextW(context->CurrentFile, L"当前文件：HashRestore_RecoveredNames.lst");
        SendMessageW(context->Progress, PBM_SETPOS, 0, 0);

        HANDLE thread = ::CreateThread(nullptr, 0u, RestoreThreadProc, parameter, 0u, nullptr);
        if (!thread)
        {
            delete parameter;
            context->Running = false;
            UpdateBusyControls(context);
            SetWindowTextW(context->Status, L"创建恢复线程失败");
            return;
        }
        CloseHandle(thread);
    }

    LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        RestoreContext* context = (RestoreContext*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        switch (message)
        {
            case WM_CREATE:
            {
                CREATESTRUCTW* create = (CREATESTRUCTW*)lParam;
                context = (RestoreContext*)create->lpCreateParams;
                context->Window = hwnd;
                context->UiFont = CreateUiFont(hwnd);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);

                CreateWindowW(L"BUTTON", L"恢复目标", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 12, 8, 1040, 88, hwnd, nullptr, nullptr, nullptr);
                CreateWindowW(L"STATIC", L"纯Hash目录：", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 30, 95, 18, hwnd, nullptr, nullptr, nullptr);
                context->SourceEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", context->InitialSourceDirectory.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 120, 27, 720, 23, hwnd, (HMENU)IDC_SOURCE_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 850, 26, 70, 25, hwnd, (HMENU)IDC_SOURCE_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"补充lst映射：", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, 62, 105, 18, hwnd, nullptr, nullptr, nullptr);
                context->MapEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", context->ExternalMapPath.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 130, 59, 710, 23, hwnd, (HMENU)IDC_MAP_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"浏览", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 850, 58, 70, 25, hwnd, (HMENU)IDC_MAP_BROWSE, nullptr, nullptr);

                context->Button = CreateWindowW(L"BUTTON", L"开始实时恢复", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 930, 26, 110, 57, hwnd, (HMENU)IDC_SELECT_FOLDER, nullptr, nullptr);
                context->StopButton = CreateWindowW(L"BUTTON", L"", WS_CHILD | BS_PUSHBUTTON | WS_DISABLED, 930, 58, 110, 25, hwnd, (HMENU)IDC_STOP, nullptr, nullptr);
                if (context->ShowCrackTools)
                {
                    CreateWindowW(L"BUTTON", L"收集候选名称", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 25, 108, 135, 26, hwnd, (HMENU)IDC_COLLECT_NAMES, nullptr, nullptr);
                    CreateWindowW(L"BUTTON", L"导入撞库结果", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 170, 108, 135, 26, hwnd, (HMENU)IDC_IMPORT_MATCH, nullptr, nullptr);
                }
                CreateWindowW(L"BUTTON", L"恢复进度", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 12, context->ShowCrackTools ? 142 : 108, 1040, 255, hwnd, nullptr, nullptr, nullptr);
                int progressTop = context->ShowCrackTools ? 165 : 131;
                context->MapInfo = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, progressTop, 1015, 48, hwnd, (HMENU)IDC_MAP_INFO, nullptr, nullptr);
                context->Progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE | PBS_MARQUEE, 25, progressTop + 60, 1015, 24, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
                context->Summary = CreateWindowW(L"STATIC", L"已处理：0/0 | 进度：0% | 已恢复 0 | 剩余 0 | 失败 0", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, progressTop + 94, 1015, 22, hwnd, (HMENU)IDC_SUMMARY, nullptr, nullptr);
                context->CurrentFile = CreateWindowW(L"STATIC", L"当前文件：-", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, progressTop + 126, 1015, 24, hwnd, (HMENU)IDC_CURRENT_FILE, nullptr, nullptr);
                context->Status = CreateWindowW(L"STATIC", L"就绪。", WS_CHILD | WS_VISIBLE | SS_LEFT, 25, progressTop + 162, 1015, 70, hwnd, (HMENU)IDC_STATUS, nullptr, nullptr);
                SendMessageW(context->Progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                SetWindowTextW(context->MapInfo,
                               FormatString(L"Hash日志：%s\r\n补充lst映射：未选择（可选）",
                                            context->HashLogDirectory.c_str()).c_str());
                ApplyUiFont(context);
                RefreshLoadedProgress(context);
                return 0;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == IDC_SELECT_FOLDER && context)
                {
                    if (context->Running)
                    {
                        SetEvent(context->CancelEvent);
                        SetWindowTextW(context->Status, L"正在停止...");
                        SetWindowTextW(context->CurrentFile, L"当前文件：已请求停止");
                        EnableWindow(context->Button, FALSE);
                        SetWindowTextW(context->Button, L"正在停止...");
                        return 0;
                    }
                    StartRestore(context);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_STOP && context)
                {
                    SetEvent(context->CancelEvent);
                    SetWindowTextW(context->Status, L"正在停止...");
                    SetWindowTextW(context->CurrentFile, L"当前文件：已请求停止");
                    EnableWindow(context->Button, FALSE);
                    SetWindowTextW(context->Button, L"正在停止...");
                    return 0;
                }
                if (LOWORD(wParam) == IDC_SOURCE_BROWSE && context)
                {
                    if (context->Running || ::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
                    {
                        SetWindowTextW(context->Status, L"当前任务未完成，暂不能切换纯Hash目录。");
                        return 0;
                    }
                    std::wstring folder = BrowseFolder(hwnd, L"选择需要恢复的 Extractor_Output 目录");
                    if (!folder.empty())
                    {
                        SetWindowTextW(context->SourceEdit, folder.c_str());
                        RefreshLoadedProgress(context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_MAP_BROWSE && context)
                {
                    if (context->Running || ::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
                    {
                        SetWindowTextW(context->Status, L"当前任务未完成，暂不能切换补充lst映射。");
                        return 0;
                    }
                    std::wstring file = BrowseMapFile(hwnd);
                    if (!file.empty())
                    {
                        SetWindowTextW(context->MapEdit, file.c_str());
                        RefreshLoadedProgress(context);
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_COLLECT_NAMES && context)
                {
                    if (context->Running || ::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
                    {
                        SetWindowTextW(context->Status, L"当前任务未完成，暂不能收集候选名称。");
                        return 0;
                    }
                    CollectHashCrackCandidates(hwnd, context);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_IMPORT_MATCH && context)
                {
                    if (context->Running || ::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
                    {
                        SetWindowTextW(context->Status, L"当前任务未完成，暂不能导入撞库结果。");
                        return 0;
                    }
                    std::wstring matchPath = BrowseMapFile(hwnd);
                    if (!matchPath.empty())
                    {
                        std::wstring recoveredListPath = CombinePath(context->HashLogDirectory, L"HashRestore_RecoveredNames.lst");
                        bool imported = ImportMatchFileToRecoveredList(matchPath, recoveredListPath);
                        SetWindowTextW(context->Status, imported ? L"撞库结果已导入恢复映射表。" : L"导入撞库结果失败。");
                        SetWindowTextW(context->CurrentFile, FormatString(L"撞库结果：%s", matchPath.c_str()).c_str());
                        RefreshLoadedProgress(context);
                    }
                    return 0;
                }
                break;
            case WM_LOAD_PROGRESS:
            {
                LoadProgressMessage* progress = (LoadProgressMessage*)lParam;
                if (progress && context)
                {
                    if (progress->Finished)
                    {
                        ::SendMessageW(context->Progress, PBM_SETMARQUEE, FALSE, 0);
                        ::InterlockedExchange(&context->LoadingState, 0);
                        UpdateBusyControls(context);
                    }
                    else
                    {
                        ::SendMessageW(context->Progress, PBM_SETMARQUEE, TRUE, 30);
                    }
                    ::SendMessageW(context->Progress, PBM_SETPOS, progress->Percent, 0);
                    ::SetWindowTextW(context->Summary, progress->Summary);
                    ::SetWindowTextW(context->CurrentFile, progress->CurrentFile);
                    ::SetWindowTextW(context->Status, progress->Status);
                    ::SetWindowTextW(context->MapInfo, progress->MapInfo);
                    ::HeapFree(::GetProcessHeap(), 0, progress);
                }
                return 0;
            }
            case WM_RESTORE_PROGRESS:
            {
                ProgressMessage* progress = (ProgressMessage*)lParam;
                if (progress && context)
                {
                    unsigned int percent = progress->Total == 0u ? 0u : (progress->Current * 100u) / progress->Total;
                    if (!progress->Finished && progress->Total == 0u)
                    {
                        SendMessageW(context->Progress, PBM_SETMARQUEE, TRUE, 30);
                    }
                    else
                    {
                        SendMessageW(context->Progress, PBM_SETMARQUEE, FALSE, 0);
                    }
                    SendMessageW(context->Progress, PBM_SETPOS, percent, 0);
                    std::wstring summary = FormatString(L"已处理：%u/%u | 进度：%u%% | 已恢复 %u | 剩余 %u | 失败 %u",
                                                        progress->Current,
                                                        progress->Total,
                                                        percent,
                                                        progress->Restored,
                                                        progress->Remaining,
                                                        progress->Failed);
                    SetWindowTextW(context->Summary, summary.c_str());
                    SetWindowTextW(context->CurrentFile, FormatString(L"当前文件：%s", progress->Detail).c_str());
                    SetWindowTextW(context->Status,
                                   progress->Finished
                                       ? progress->Detail
                                       : progress->Detail);
                    std::wstring mapPath = GetWindowTextString(context->MapEdit);
                    SetWindowTextW(context->MapInfo,
                                   FormatString(L"Hash日志：%s\r\n目录映射：%u | 文件映射：%u | 补充lst映射：%u条 | %s",
                                                context->HashLogDirectory.c_str(),
                                                progress->DirectoryMapCount,
                                                progress->FileNameMapCount,
                                                progress->SupplementalMapCount,
                                                 mapPath.empty() ? L"（无）" : mapPath.c_str()).c_str());
                    if (progress->Finished)
                    {
                        context->Running = false;
                        UpdateBusyControls(context);
                    }
                    HeapFree(GetProcessHeap(), 0, progress);
                }
                return 0;
            }
            case WM_CLOSE:
                if (context)
                {
                    if (context->Running)
                    {
                        SetEvent(context->CancelEvent);
                        SetWindowTextW(context->Status, L"正在停止实时恢复，请等待当前任务退出后再关闭窗口。");
                        SetWindowTextW(context->CurrentFile, L"当前文件：已请求停止");
                        EnableWindow(context->Button, FALSE);
                        SetWindowTextW(context->Button, L"正在停止...");
                        return 0;
                    }
                    if (::InterlockedCompareExchange(&context->LoadingState, 0, 0) != 0)
                    {
                        SetWindowTextW(context->Status, L"正在加载映射与历史进度，请等待加载完成后再关闭窗口。");
                        return 0;
                    }
                }
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (context->CancelEvent)
                {
                    SetEvent(context->CancelEvent);
                    CloseHandle(context->CancelEvent);
                    context->CancelEvent = nullptr;
                }
                if (context->UiFont)
                {
                    ::DeleteObject(context->UiFont);
                    context->UiFont = nullptr;
                }
                delete context;
                PostQuitMessage(0);
                return 0;
        }
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    DWORD WINAPI UiThreadProc(LPVOID parameter)
    {
        RestoreContext* context = (RestoreContext*)parameter;
        HRESULT coInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        INITCOMMONCONTROLSEX controls{};
        controls.dwSize = sizeof(controls);
        controls.dwICC = ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&controls);

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = WindowProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        windowClass.lpszClassName = WindowClassName;
        RegisterClassExW(&windowClass);

        HWND hwnd = CreateWindowExW(0,
                                    WindowClassName,
                                    L"Cxdec Hash映射恢复",
                                     WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                     CW_USEDEFAULT,
                                     CW_USEDEFAULT,
                                     1080,
                                     460,
                                     nullptr,
                                     nullptr,
                                     windowClass.hInstance,
                                    context);
        if (!hwnd)
        {
            ::InterlockedExchange(&g_WindowActive, 0);
            g_WindowHandle = nullptr;
            if (context->CancelEvent)
            {
                CloseHandle(context->CancelEvent);
                context->CancelEvent = nullptr;
            }
            delete context;
            if (SUCCEEDED(coInit))
            {
                ::CoUninitialize();
            }
            return 0u;
        }

        g_WindowHandle = hwnd;
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (SUCCEEDED(coInit))
        {
            ::CoUninitialize();
        }
        g_WindowHandle = nullptr;
        ::InterlockedExchange(&g_WindowActive, 0);
        return 0u;
    }
}

namespace Engine
{
    void HashRestoreUI::Start(HMODULE moduleHandle, const std::wstring& gameDirectory)
    {
        Start(moduleHandle, gameDirectory, std::wstring(), true);
    }

    void HashRestoreUI::Start(HMODULE moduleHandle, const std::wstring& gameDirectory, const std::wstring& initialSourceDirectory, bool showCrackTools)
    {
        UNREFERENCED_PARAMETER(moduleHandle);
        if (::InterlockedCompareExchange(&g_WindowActive, 1, 0) != 0)
        {
            HWND window = g_WindowHandle;
            if (window)
            {
                ::ShowWindow(window, SW_SHOWNORMAL);
                ::SetForegroundWindow(window);
            }
            return;
        }

        RestoreContext* context = new RestoreContext{};
        context->GameDirectory = gameDirectory;
        context->HashLogDirectory = CombinePath(gameDirectory, L"StringHashDumper_Output");
        context->ExternalMapPath.clear();
        context->InitialSourceDirectory = initialSourceDirectory;
        context->ShowCrackTools = showCrackTools;
        context->CancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!context->CancelEvent)
        {
            ::InterlockedExchange(&g_WindowActive, 0);
            delete context;
            return;
        }

        HANDLE thread = CreateThread(nullptr, 0u, UiThreadProc, context, 0u, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
        else
        {
            ::InterlockedExchange(&g_WindowActive, 0);
            if (context->CancelEvent)
            {
                CloseHandle(context->CancelEvent);
                context->CancelEvent = nullptr;
            }
            delete context;
        }
    }
}
