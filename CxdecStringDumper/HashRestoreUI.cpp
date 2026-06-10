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

    struct ProgressMessage
    {
        unsigned int Current;
        unsigned int Total;
        unsigned int Restored;
        unsigned int Unresolved;
        unsigned int Failed;
        unsigned int DirectoryMapCount;
        unsigned int FileNameMapCount;
        bool Finished;
        bool Succeeded;
        wchar_t Detail[MaxPathChars];
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
        HANDLE CancelEvent;
        std::wstring GameDirectory;
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
        dialog->SetTitle(L"Select hash name map");
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

    void LoadExternalHashList(const std::wstring& path,
                              std::unordered_map<std::wstring, std::wstring>& directoryMap,
                              std::unordered_map<std::wstring, std::wstring>& fileNameMap)
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
                        directoryMap.emplace(hash, NormalizeRelativeDirectory(name));
                    }
                    else if (IsHexStringLength(hash, 64u))
                    {
                        fileNameMap.emplace(hash, name);
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
                if (_wcsicmp(data.cFileName, L"ExtractLog") == 0)
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
                      unsigned int unresolved,
                      unsigned int failed,
                      unsigned int directoryMapCount,
                      unsigned int fileNameMapCount,
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
        message->Unresolved = unresolved;
        message->Failed = failed;
        message->DirectoryMapCount = directoryMapCount;
        message->FileNameMapCount = fileNameMapCount;
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
        bool reportHeaderWritten = false;
        std::wstring logDirectory = CombinePath(restore->SourceDirectory, L"ExtractLog");

        ::SHCreateDirectoryExW(nullptr, restore->HashLogDirectory.c_str(), nullptr);
        ::SHCreateDirectoryExW(nullptr, logDirectory.c_str(), nullptr);
        AppendUtf8Line(CombinePath(logDirectory, L"HashRestore.log"), L"Hash watch started\r\n");
        LoadLineSet(CombinePath(restore->HashLogDirectory, L"HashRestore_RecoveredNames.lst"), recoveredNameLines);

        while (!restore->CancelEvent || ::WaitForSingleObject(restore->CancelEvent, 0u) != WAIT_OBJECT_0)
        {
            std::unordered_map<std::wstring, std::wstring> directoryMap;
            std::unordered_map<std::wstring, std::wstring> fileNameMap;
            if (!LoadHashMap(CombinePath(restore->HashLogDirectory, L"DirectoryHash.log"), true, directoryMap)
                || !LoadHashMap(CombinePath(restore->HashLogDirectory, L"FileNameHash.log"), false, fileNameMap))
            {
                PostProgress(restore->Window,
                             0u,
                             0u,
                             restoredCount,
                             0u,
                             failedCount,
                             0u,
                             0u,
                             false,
                             true,
                             L"Watching... waiting for hash logs");
                ::Sleep(1000u);
                continue;
            }

            LoadExternalHashList(restore->ExternalMapPath, directoryMap, fileNameMap);
            const unsigned int directoryMapCount = (unsigned int)directoryMap.size();
            const unsigned int fileNameMapCount = (unsigned int)fileNameMap.size();

            std::vector<std::wstring> files;
            CollectFilesRecursive(restore->SourceDirectory, files);

            if (!reportHeaderWritten)
            {
                AppendUtf8Line(CombinePath(logDirectory, L"HashRestore_Report.tsv"), L"SourcePath\tDirectoryHash\tFileHash\tDirectoryName\tFileName\tTargetPath\tStatus\r\n");
                reportHeaderWritten = true;
            }

            unsigned int totalHashFiles = 0u;
            unsigned int pendingCount = 0u;
            std::wstring lastDetail = L"Watching...";

            for (const std::wstring& sourcePath : files)
            {
                std::wstring relative = MakeRelativePath(restore->SourceDirectory, sourcePath);
                if (restoredSources.find(relative) != restoredSources.end())
                {
                    continue;
                }

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

                ++totalHashFiles;
                lastDetail = relative;

                auto dirIt = directoryMap.find(dirHash);
                auto fileIt = fileNameMap.find(fileHash);
                if (dirIt == directoryMap.end() || fileIt == fileNameMap.end())
                {
                    ++pendingCount;
                    continue;
                }

                std::wstring packageRelative = JoinPathParts(parts, 0u, parts.size() - 2u);
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
                    moved = ::MoveFileW(sourcePath.c_str(), targetPath.c_str()) != FALSE;
                    if (!moved)
                    {
                        moved = ::CopyFileW(sourcePath.c_str(), targetPath.c_str(), FALSE) != FALSE
                            && ::DeleteFileW(sourcePath.c_str()) != FALSE;
                    }
                }

                if (moved)
                {
                    ++restoredCount;
                    restoredSources.insert(targetRelative);
                    AppendRecoveredNameLine(restore->HashLogDirectory, recoveredNameLines, dirHash, dirIt->second.empty() ? L"/" : dirIt->second);
                    AppendRecoveredNameLine(restore->HashLogDirectory, recoveredNameLines, fileHash, fileIt->second);
                    AppendUtf8Line(CombinePath(logDirectory, L"HashRestore.log"), FormatString(L"OK\t%s\t%s\r\n", relative.c_str(), targetRelative.c_str()));
                    AppendReportLine(logDirectory, relative, dirHash, fileHash, dirIt->second, fileIt->second, targetPath, L"OK");
                    lastDetail = targetRelative;
                }
                else
                {
                    ++failedCount;
                    ++pendingCount;
                    AppendUtf8Line(CombinePath(logDirectory, L"HashRestore_Unresolved.log"), FormatString(L"FAILED\t%s\t%s\r\n", relative.c_str(), targetPath.c_str()));
                    AppendReportLine(logDirectory, relative, dirHash, fileHash, dirIt->second, fileIt->second, targetPath, L"FAILED");
                }
            }

            unsigned int displayTotal = restoredCount + pendingCount + failedCount;
            PostProgress(restore->Window,
                         restoredCount,
                         displayTotal,
                         restoredCount,
                         pendingCount,
                         failedCount,
                         directoryMapCount,
                         fileNameMapCount,
                         false,
                         true,
                         lastDetail);

            ::Sleep(1000u);
        }

        SortRecoveredNameList(CombinePath(restore->HashLogDirectory, L"HashRestore_RecoveredNames.lst"));

        std::wstring final = FormatString(L"Stopped | Restored %u | Failed %u", restoredCount, failedCount);
        AppendUtf8Line(CombinePath(logDirectory, L"HashRestore.log"), final + L"\r\n");
        PostProgress(restore->Window,
                     restoredCount,
                     restoredCount,
                     restoredCount,
                     0u,
                     failedCount,
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
        std::wstring sourceDirectory = GetWindowTextString(context->SourceEdit);
        if (sourceDirectory.empty())
        {
            sourceDirectory = BrowseFolder(context->Window, L"Select the Extractor_Output folder to restore");
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
        EnableWindow(context->Button, FALSE);
        EnableWindow(context->StopButton, TRUE);
        SetWindowTextW(context->Status, L"Watching...");
        SetWindowTextW(context->Summary, L"Files: scanning... | Restored 0 | Unresolved 0 | Failed 0");
        SetWindowTextW(context->CurrentFile, L"Current file: scanning...");
        SendMessageW(context->Progress, PBM_SETPOS, 0, 0);

        HANDLE thread = ::CreateThread(nullptr, 0u, RestoreThreadProc, parameter, 0u, nullptr);
        if (!thread)
        {
            delete parameter;
            EnableWindow(context->Button, TRUE);
            EnableWindow(context->StopButton, FALSE);
            SetWindowTextW(context->Status, L"Failed to create restore thread");
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
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);

                CreateWindowW(L"STATIC", L"Folder:", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 18, 70, 18, hwnd, nullptr, nullptr, nullptr);
                context->SourceEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 85, 15, 520, 22, hwnd, (HMENU)IDC_SOURCE_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 615, 14, 40, 24, hwnd, (HMENU)IDC_SOURCE_BROWSE, nullptr, nullptr);

                CreateWindowW(L"STATIC", L"Map list:", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 48, 70, 18, hwnd, nullptr, nullptr, nullptr);
                context->MapEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", context->ExternalMapPath.c_str(), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 85, 45, 520, 22, hwnd, (HMENU)IDC_MAP_EDIT, nullptr, nullptr);
                CreateWindowW(L"BUTTON", L"...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 615, 44, 40, 24, hwnd, (HMENU)IDC_MAP_BROWSE, nullptr, nullptr);

                context->Button = CreateWindowW(L"BUTTON", L"Start Watch", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 665, 14, 85, 24, hwnd, (HMENU)IDC_SELECT_FOLDER, nullptr, nullptr);
                context->StopButton = CreateWindowW(L"BUTTON", L"Stop", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 665, 44, 85, 24, hwnd, (HMENU)IDC_STOP, nullptr, nullptr);
                context->MapInfo = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 82, 735, 36, hwnd, (HMENU)IDC_MAP_INFO, nullptr, nullptr);
                context->Progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE, 15, 126, 735, 20, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
                context->Summary = CreateWindowW(L"STATIC", L"Files: 0/0 | Progress: 0% | Restored 0 | Unresolved 0 | Failed 0", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 156, 735, 20, hwnd, (HMENU)IDC_SUMMARY, nullptr, nullptr);
                context->CurrentFile = CreateWindowW(L"STATIC", L"Current file: -", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 184, 735, 22, hwnd, (HMENU)IDC_CURRENT_FILE, nullptr, nullptr);
                context->Status = CreateWindowW(L"STATIC", L"Ready.", WS_CHILD | WS_VISIBLE | SS_LEFT, 15, 214, 735, 44, hwnd, (HMENU)IDC_STATUS, nullptr, nullptr);
                SendMessageW(context->Progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                SetWindowTextW(context->MapInfo,
                               FormatString(L"Hash logs: %s\r\nExternal map: optional",
                                            context->HashLogDirectory.c_str()).c_str());
                return 0;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == IDC_SELECT_FOLDER && context)
                {
                    StartRestore(context);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_STOP && context)
                {
                    SetEvent(context->CancelEvent);
                    SetWindowTextW(context->Status, L"Canceling...");
                    SetWindowTextW(context->CurrentFile, L"Current file: cancel requested");
                    EnableWindow(context->StopButton, FALSE);
                    return 0;
                }
                if (LOWORD(wParam) == IDC_SOURCE_BROWSE && context)
                {
                    std::wstring folder = BrowseFolder(hwnd, L"Select the Extractor_Output folder to restore");
                    if (!folder.empty())
                    {
                        SetWindowTextW(context->SourceEdit, folder.c_str());
                    }
                    return 0;
                }
                if (LOWORD(wParam) == IDC_MAP_BROWSE && context)
                {
                    std::wstring file = BrowseMapFile(hwnd);
                    if (!file.empty())
                    {
                        SetWindowTextW(context->MapEdit, file.c_str());
                    }
                    return 0;
                }
                break;
            case WM_RESTORE_PROGRESS:
            {
                ProgressMessage* progress = (ProgressMessage*)lParam;
                if (progress && context)
                {
                    unsigned int percent = progress->Total == 0u ? 0u : (progress->Current * 100u) / progress->Total;
                    SendMessageW(context->Progress, PBM_SETPOS, percent, 0);
                    std::wstring summary = FormatString(L"Files: %u/%u | Progress: %u%% | Restored %u | Unresolved %u | Failed %u",
                                                        progress->Current,
                                                        progress->Total,
                                                        percent,
                                                        progress->Restored,
                                                        progress->Unresolved,
                                                        progress->Failed);
                    SetWindowTextW(context->Summary, summary.c_str());
                    SetWindowTextW(context->CurrentFile, FormatString(L"Current file: %s", progress->Detail).c_str());
                    SetWindowTextW(context->Status, progress->Finished ? progress->Detail : L"Watching...");
                    std::wstring mapPath = GetWindowTextString(context->MapEdit);
                    SetWindowTextW(context->MapInfo,
                                   FormatString(L"Hash logs: %s\r\nDirectory map: %u | File map: %u | External: %s",
                                                context->HashLogDirectory.c_str(),
                                                progress->DirectoryMapCount,
                                                progress->FileNameMapCount,
                                                mapPath.empty() ? L"(none)" : mapPath.c_str()).c_str());
                    if (progress->Finished)
                    {
                        EnableWindow(context->Button, TRUE);
                        EnableWindow(context->StopButton, FALSE);
                    }
                    HeapFree(GetProcessHeap(), 0, progress);
                }
                return 0;
            }
            case WM_CLOSE:
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                if (context->CancelEvent)
                {
                    SetEvent(context->CancelEvent);
                    CloseHandle(context->CancelEvent);
                    context->CancelEvent = nullptr;
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
                                    L"Cxdec String Hash Restore",
                                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                    CW_USEDEFAULT,
                                    CW_USEDEFAULT,
                                    785,
                                    315,
                                    nullptr,
                                    nullptr,
                                    windowClass.hInstance,
                                    context);
        if (!hwnd)
        {
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
        return 0u;
    }
}

namespace Engine
{
    void HashRestoreUI::Start(HMODULE moduleHandle, const std::wstring& gameDirectory)
    {
        UNREFERENCED_PARAMETER(moduleHandle);

        RestoreContext* context = new RestoreContext{};
        context->GameDirectory = gameDirectory;
        context->HashLogDirectory = CombinePath(gameDirectory, L"StringHashDumper_Output");
        context->ExternalMapPath.clear();
        context->CancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        HANDLE thread = CreateThread(nullptr, 0u, UiThreadProc, context, 0u, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
        else
        {
            if (context->CancelEvent)
            {
                CloseHandle(context->CancelEvent);
                context->CancelEvent = nullptr;
            }
            delete context;
        }
    }
}
