#include "HashCore.h"
#include "pe.h"
#include "file.h"
#include "directory.h"
#include "path.h"
#include "stringhelper.h"
#include "ExtendUtils.h"
#include "loaderipc.h"

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <vector>

namespace
{
    constexpr wchar_t HashCrackModeEnvName[] = L"CXDEC_HASH_CRACK_MODE";
    constexpr wchar_t HashCrackDirsFileEnvName[] = L"CXDEC_HASH_CRACK_DIRS_FILE";
    constexpr wchar_t HashCrackFilesFileEnvName[] = L"CXDEC_HASH_CRACK_FILES_FILE";
    constexpr wchar_t HashCrackPureHashDirEnvName[] = L"CXDEC_HASH_CRACK_PURE_HASH_DIR";
    constexpr wchar_t HashCrackSupplementalMapEnvName[] = L"CXDEC_HASH_CRACK_SUPPLEMENTAL_MAP";
    constexpr wchar_t RecoveredNamesFileName[] = L"HashRestore_RecoveredNames.lst";
    constexpr wchar_t ExtractorLogDirectoryName[] = L"Extractor_Log";
    constexpr wchar_t HashCrackLogFileName[] = L"HashCrack.log";

    struct HashCrackThreadParameter
    {
        Engine::CompoundStorageMedia* StorageMedia;
        const Engine::IStringHasher::VptrTable* PathNameHasherOriginalVtPtr;
        const Engine::IStringHasher::VptrTable* FileNameHasherOriginalVtPtr;
        std::wstring OutputDirectory;
    };

    bool IsFileEmptyOrMissing(const std::wstring& path)
    {
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return true;
        }

        bool empty = true;
        if (_fseeki64(fp, 0, SEEK_END) == 0)
        {
            empty = _ftelli64(fp) <= 0;
        }

        fclose(fp);
        return empty;
    }

    void LoadUnicodeHashLines(const std::wstring& path, std::unordered_set<std::wstring>& lines)
    {
        lines.clear();

        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return;
        }

        if (_fseeki64(fp, 0, SEEK_END) != 0)
        {
            fclose(fp);
            return;
        }

        const long long size = _ftelli64(fp);
        if (size <= 0 || (size % sizeof(wchar_t)) != 0)
        {
            fclose(fp);
            return;
        }

        if (_fseeki64(fp, 0, SEEK_SET) != 0)
        {
            fclose(fp);
            return;
        }

        std::wstring content;
        content.resize(static_cast<size_t>(size / sizeof(wchar_t)));
        if (fread(content.data(), sizeof(wchar_t), content.size(), fp) != content.size())
        {
            fclose(fp);
            return;
        }

        fclose(fp);

        if (!content.empty() && content[0] == 0xFEFF)
        {
            content.erase(content.begin());
        }

        size_t start = 0;
        while (start < content.size())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.size();
            }

            if (end > start)
            {
                lines.insert(content.substr(start, end - start));
            }

            start = end;
            while (start < content.size() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
    }

    bool IsHashCrackModeEnabled()
    {
        wchar_t value[16]{};
        DWORD length = ::GetEnvironmentVariableW(HashCrackModeEnvName, value, _countof(value));
        return length > 0 && value[0] == L'1';
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

    bool IsMatchTextFileName(const wchar_t* fileName)
    {
        std::wstring name = fileName ? fileName : L"";
        std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
        return name.ends_with(L"_match.txt") || name.ends_with(L"_tmp.txt");
    }

    bool FindLatestFileByPattern(const std::wstring& directory, const wchar_t* pattern, bool skipMatchFile, std::wstring& path)
    {
        WIN32_FIND_DATAW data{};
        HANDLE find = ::FindFirstFileW(CombinePathLocal(directory, pattern).c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        bool found = false;
        FILETIME latest{};
        do
        {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                continue;
            }
            if (skipMatchFile && IsMatchTextFileName(data.cFileName))
            {
                continue;
            }
            if (!found || ::CompareFileTime(&data.ftLastWriteTime, &latest) > 0)
            {
                found = true;
                latest = data.ftLastWriteTime;
                path = CombinePathLocal(directory, data.cFileName);
            }
        } while (::FindNextFileW(find, &data));

        ::FindClose(find);
        return found;
    }

    bool FindLatestCandidateFile(const std::wstring& directory, const wchar_t* pattern, std::wstring& path)
    {
        return FindLatestFileByPattern(directory, pattern, true, path);
    }

    bool FindLatestMatchFile(const std::wstring& directory, const wchar_t* pattern, std::wstring& path)
    {
        return FindLatestFileByPattern(directory, pattern, false, path);
    }

    std::vector<std::wstring> ReadUtf16Lines(const std::wstring& path)
    {
        std::vector<std::wstring> lines;
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return lines;
        }

        if (_fseeki64(fp, 0, SEEK_END) != 0)
        {
            fclose(fp);
            return lines;
        }

        long long size = _ftelli64(fp);
        if (size <= 0 || (size % sizeof(wchar_t)) != 0)
        {
            fclose(fp);
            return lines;
        }

        if (_fseeki64(fp, 0, SEEK_SET) != 0)
        {
            fclose(fp);
            return lines;
        }

        std::wstring content((size_t)(size / sizeof(wchar_t)), L'\0');
        if (fread(content.data(), sizeof(wchar_t), content.size(), fp) != content.size())
        {
            fclose(fp);
            return lines;
        }
        fclose(fp);

        if (!content.empty() && content[0] == 0xFEFF)
        {
            content.erase(content.begin());
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
                lines.push_back(content.substr(start, end - start));
            }
            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
        return lines;
    }

    std::string ReadBinaryFileLocal(const std::wstring& path)
    {
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return std::string();
        }
        if (_fseeki64(fp, 0, SEEK_END) != 0)
        {
            fclose(fp);
            return std::string();
        }
        long long size = _ftelli64(fp);
        if (size <= 0 || size > 64ll * 1024ll * 1024ll)
        {
            fclose(fp);
            return std::string();
        }
        if (_fseeki64(fp, 0, SEEK_SET) != 0)
        {
            fclose(fp);
            return std::string();
        }
        std::string bytes((size_t)size, '\0');
        fread(bytes.data(), 1, bytes.size(), fp);
        fclose(fp);
        return bytes;
    }

    std::wstring DecodeTextFileLocal(const std::wstring& path)
    {
        std::string bytes = ReadBinaryFileLocal(path);
        if (bytes.empty())
        {
            return std::wstring();
        }
        if (bytes.size() >= 3u &&
            (unsigned char)bytes[0] == 0xEF &&
            (unsigned char)bytes[1] == 0xBB &&
            (unsigned char)bytes[2] == 0xBF)
        {
            bytes.erase(bytes.begin(), bytes.begin() + 3);
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

    void LoadTextLineSet(const std::wstring& path, std::unordered_set<std::wstring>& lines)
    {
        std::wstring content = DecodeTextFileLocal(path);
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
                if (!line.empty() && line[0] == 0xFEFF)
                {
                    line.erase(line.begin());
                }
                if (!line.empty())
                {
                    lines.insert(line);
                }
            }
            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
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

    std::wstring ToUpperStringLocal(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return (wchar_t)towupper(ch); });
        return value;
    }

    void NormalizeNameForRecoveredList(std::wstring& name)
    {
        std::replace(name.begin(), name.end(), L'\\', L'/');
        if (name.empty() || name == L"%EmptyString%")
        {
            name = L"/";
        }
    }

    std::wstring MakeRecoveredNameLine(std::wstring hash, std::wstring name)
    {
        hash = ToUpperStringLocal(hash);
        if (!IsHexStringLength(hash, 16u) && !IsHexStringLength(hash, 64u))
        {
            return std::wstring();
        }
        NormalizeNameForRecoveredList(name);
        return hash + L":" + name;
    }

    bool AddRecoveredNameLine(std::unordered_set<std::wstring>& lines, const std::wstring& hash, const std::wstring& name)
    {
        std::wstring line = MakeRecoveredNameLine(hash, name);
        if (line.empty())
        {
            return false;
        }
        return lines.insert(line).second;
    }

    unsigned int ImportMatchTextToRecoveredLines(const std::wstring& matchPath, std::unordered_set<std::wstring>& recoveredLines)
    {
        std::wstring content = DecodeTextFileLocal(matchPath);
        unsigned int count = 0u;
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
                    if (AddRecoveredNameLine(recoveredLines, line.substr(split + 1u), line.substr(0, split)))
                    {
                        ++count;
                    }
                }
            }
            start = end;
            while (start < content.length() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
        return count;
    }

    std::vector<std::wstring> SortRecoveredNameLines(const std::unordered_set<std::wstring>& recoveredLines)
    {
        std::vector<std::wstring> lines(recoveredLines.begin(), recoveredLines.end());
        std::sort(lines.begin(), lines.end(), [](const std::wstring& left, const std::wstring& right)
        {
            size_t leftSplit = left.find(L':');
            size_t rightSplit = right.find(L':');
            std::wstring leftHash = leftSplit == std::wstring::npos ? left : left.substr(0, leftSplit);
            std::wstring rightHash = rightSplit == std::wstring::npos ? right : right.substr(0, rightSplit);
            std::wstring leftName = leftSplit == std::wstring::npos ? std::wstring() : left.substr(leftSplit + 1u);
            std::wstring rightName = rightSplit == std::wstring::npos ? std::wstring() : right.substr(rightSplit + 1u);
            int leftRank = IsHexStringLength(leftHash, 16u) ? 0 : (IsHexStringLength(leftHash, 64u) ? 1 : 2);
            int rightRank = IsHexStringLength(rightHash, 16u) ? 0 : (IsHexStringLength(rightHash, 64u) ? 1 : 2);
            if (leftRank != rightRank)
            {
                return leftRank < rightRank;
            }
            int nameCompare = _wcsicmp(leftName.c_str(), rightName.c_str());
            if (nameCompare != 0)
            {
                return nameCompare < 0;
            }
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        });
        return lines;
    }

    void WriteRecoveredNameList(const std::wstring& outputDirectory, const std::unordered_set<std::wstring>& recoveredLines)
    {
        std::vector<std::wstring> lines = SortRecoveredNameLines(recoveredLines);
        std::wstring text;
        for (const std::wstring& line : lines)
        {
            text += line;
            text += L"\r\n";
        }

        std::wstring path = CombinePathLocal(outputDirectory, RecoveredNamesFileName);
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"wb") != 0 || fp == nullptr)
        {
            return;
        }
        int length = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.length(), nullptr, 0, nullptr, nullptr);
        if (length > 0)
        {
            std::string utf8((size_t)length, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.length(), utf8.data(), length, nullptr, nullptr);
            fwrite(utf8.data(), 1, utf8.size(), fp);
        }
        fclose(fp);
    }

    void AppendUtf8LineLocal(const std::wstring& filePath, const std::wstring& line)
    {
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, filePath.c_str(), L"ab") != 0 || fp == nullptr)
        {
            return;
        }
        int length = ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), nullptr, 0, nullptr, nullptr);
        if (length > 0)
        {
            std::string utf8((size_t)length, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), utf8.data(), length, nullptr, nullptr);
            fwrite(utf8.data(), 1, utf8.size(), fp);
        }
        fclose(fp);
    }

    std::wstring GetHashCrackLogDirectory(const std::wstring& outputDirectory)
    {
        std::wstring pureHashDirectory = GetEnvironmentString(HashCrackPureHashDirEnvName);
        std::wstring baseDirectory = pureHashDirectory.empty() ? outputDirectory : pureHashDirectory;
        std::wstring logDirectory = CombinePathLocal(baseDirectory, ExtractorLogDirectoryName);
        ::CreateDirectoryW(logDirectory.c_str(), nullptr);
        return logDirectory;
    }

    void WriteHashCrackLog(const std::wstring& logDirectory, const std::wstring& message)
    {
        SYSTEMTIME st{};
        ::GetLocalTime(&st);
        wchar_t prefix[64]{};
        swprintf_s(prefix,
                   L"[%04u-%02u-%02u %02u:%02u:%02u] ",
                   st.wYear,
                   st.wMonth,
                   st.wDay,
                   st.wHour,
                   st.wMinute,
                   st.wSecond);
        AppendUtf8LineLocal(CombinePathLocal(logDirectory, HashCrackLogFileName), std::wstring(prefix) + message + L"\r\n");
    }

    HWND GetLoaderWindowFromEnvironment()
    {
        wchar_t loaderWindowValue[64]{};
        DWORD valueLength = ::GetEnvironmentVariableW(LoaderIpc::LoaderWindowHandleEnvName,
                                                      loaderWindowValue,
                                                      (DWORD)_countof(loaderWindowValue));
        if (valueLength == 0u || valueLength >= (DWORD)_countof(loaderWindowValue))
        {
            return nullptr;
        }

        HWND loaderWindow = (HWND)(ULONG_PTR)_wcstoui64(loaderWindowValue, nullptr, 10);
        return loaderWindow && ::IsWindow(loaderWindow) ? loaderWindow : nullptr;
    }

    void NotifyLoaderHashCrackProgress(unsigned int percent)
    {
        if (percent > 100u)
        {
            percent = 100u;
        }
        HWND loaderWindow = GetLoaderWindowFromEnvironment();
        if (loaderWindow)
        {
            ::PostMessageW(loaderWindow, LoaderIpc::ProgressMessage(), (WPARAM)percent, 1);
        }
    }

    void NotifyLoaderHashCrackCompleted()
    {
        HWND loaderWindow = GetLoaderWindowFromEnvironment();
        if (loaderWindow)
        {
            ::PostMessageW(loaderWindow, LoaderIpc::CompletedMessage(), 0u, 1);
        }
    }

    std::wstring GetTimestampStringLocal()
    {
        SYSTEMTIME time{};
        ::GetLocalTime(&time);
        wchar_t buffer[32]{};
        swprintf_s(buffer,
                   L"%04u_%02u_%02u_%02u_%02u_%02u",
                   time.wYear,
                   time.wMonth,
                   time.wDay,
                   time.wHour,
                   time.wMinute,
                   time.wSecond);
        return buffer;
    }

    bool HasNameToken(std::wstring name, const wchar_t* token)
    {
        std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return (wchar_t)towlower(ch); });
        return name.find(token) != std::wstring::npos;
    }

    void ArchiveCandidateFile(const std::wstring& path, const std::wstring& outputDirectory, const std::wstring& logDirectory)
    {
        if (path.empty())
        {
            return;
        }
        if (_wcsicmp(GetParentDirectoryLocal(path).c_str(), outputDirectory.c_str()) != 0)
        {
            return;
        }

        std::wstring fileName = GetFileNameLocal(path);
        if (HasNameToken(fileName, L"_tmp") || HasNameToken(fileName, L"_match"))
        {
            return;
        }

        size_t dot = fileName.find_last_of(L'.');
        std::wstring archivedName = dot == std::wstring::npos
            ? fileName + L"_tmp"
            : fileName.substr(0, dot) + L"_tmp" + fileName.substr(dot);
        std::wstring archivedPath = CombinePathLocal(outputDirectory, archivedName);
        if (::GetFileAttributesW(archivedPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            archivedName = dot == std::wstring::npos
                ? fileName + L"_" + GetTimestampStringLocal() + L"_tmp"
                : fileName.substr(0, dot) + L"_" + GetTimestampStringLocal() + L"_tmp" + fileName.substr(dot);
            archivedPath = CombinePathLocal(outputDirectory, archivedName);
        }

        if (::MoveFileExW(path.c_str(), archivedPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            WriteHashCrackLog(logDirectory, L"候选表已归档为tmp: " + archivedPath);
        }
        else
        {
            WriteHashCrackLog(logDirectory, L"候选表归档失败: " + path + L" error=" + std::to_wstring(::GetLastError()));
        }
    }

    unsigned int CountUtf16CandidateLines(const std::wstring& path)
    {
        return (unsigned int)ReadUtf16Lines(path).size();
    }

    std::wstring CalculateNameHash(Engine::IStringHasher* hasher, const Engine::IStringHasher::VptrTable* originalVt, const tTJSString* seed, const std::wstring& name)
    {
        tTJSVariant hashValueRet;
        tTJSString tjsName(name.c_str());
        tjs_int hashSize = originalVt->Calculate(hasher, nullptr, &hashValueRet, &tjsName, seed);
        tTJSVariantOctet* hashValue = hashValueRet.AsOctetNoAddRef();
        if (!hashValue || hashSize <= 0)
        {
            return std::wstring();
        }
        return StringHelper::BytesToHexStringW(hashValue->GetData(), hashValue->GetLength());
    }

    unsigned int WriteCandidateFileToRecoveredList(const std::wstring& inputPath,
                                                   Engine::IStringHasher* hasher,
                                                   const Engine::IStringHasher::VptrTable* originalVt,
                                                   const tTJSString* seed,
                                                   const std::wstring& outputDirectory,
                                                   std::unordered_set<std::wstring>& recoveredLines,
                                                   const std::wstring& logDirectory,
                                                   unsigned int& processedCount,
                                                   unsigned int totalCount)
    {
        std::vector<std::wstring> lines = ReadUtf16Lines(inputPath);
        if (lines.empty())
        {
            WriteHashCrackLog(logDirectory, L"候选表为空或无法读取: " + inputPath);
            return 0u;
        }

        unsigned int count = 0u;
        std::wstring recoveredListPath = CombinePathLocal(outputDirectory, RecoveredNamesFileName);
        for (std::wstring name : lines)
        {
            if (name == L"/")
            {
                name.clear();
            }
            std::wstring hash = CalculateNameHash(hasher, originalVt, seed, name);
            if (hash.empty())
            {
                continue;
            }

            std::wstring displayName = name.empty() ? L"%EmptyString%" : name;
            std::wstring recoveredLine = MakeRecoveredNameLine(hash, displayName);
            if (!recoveredLine.empty() && recoveredLines.insert(recoveredLine).second)
            {
                AppendUtf8LineLocal(recoveredListPath, recoveredLine + L"\r\n");
            }
            ++count;
            ++processedCount;
            if (totalCount > 0u && (processedCount == totalCount || (processedCount % 128u) == 0u))
            {
                NotifyLoaderHashCrackProgress((processedCount * 100u) / totalCount);
            }
        }

        WriteRecoveredNameList(outputDirectory, recoveredLines);
        WriteHashCrackLog(logDirectory, L"候选表已直接写入恢复映射表: " + inputPath + L" generated=" + std::to_wstring(count));
        return count;
    }

    DWORD WINAPI HashCrackThreadProc(LPVOID parameter)
    {
        HashCrackThreadParameter* crack = (HashCrackThreadParameter*)parameter;
        if (!crack || !crack->StorageMedia)
        {
            delete crack;
            return 0u;
        }

        std::wstring dirsPath = GetEnvironmentString(HashCrackDirsFileEnvName);
        std::wstring filesPath = GetEnvironmentString(HashCrackFilesFileEnvName);
        std::wstring supplementalPath = GetEnvironmentString(HashCrackSupplementalMapEnvName);
        std::wstring logDirectory = GetHashCrackLogDirectory(crack->OutputDirectory);
        std::unordered_set<std::wstring> recoveredLines;
        LoadTextLineSet(CombinePathLocal(crack->OutputDirectory, RecoveredNamesFileName), recoveredLines);
        if (!supplementalPath.empty())
        {
            size_t before = recoveredLines.size();
            LoadTextLineSet(supplementalPath, recoveredLines);
            WriteHashCrackLog(logDirectory, L"已加载补充lst映射: " + supplementalPath + L" added=" + std::to_wstring(recoveredLines.size() - before));
        }

        WriteHashCrackLog(logDirectory, L"Hook撞库恢复Hash映射开始，Hash输出目录: " + crack->OutputDirectory);
        bool hasDirsPath = (dirsPath.empty() && FindLatestCandidateFile(crack->OutputDirectory, L"dirs_*.txt", dirsPath)) || !dirsPath.empty();
        bool hasFilesPath = (filesPath.empty() && FindLatestCandidateFile(crack->OutputDirectory, L"files_*.txt", filesPath)) || !filesPath.empty();
        unsigned int totalCount = 0u;
        if (hasDirsPath)
        {
            totalCount += CountUtf16CandidateLines(dirsPath);
        }
        if (hasFilesPath)
        {
            totalCount += CountUtf16CandidateLines(filesPath);
        }
        unsigned int processedCount = 0u;
        NotifyLoaderHashCrackProgress(0u);

        if (hasDirsPath)
        {
            WriteHashCrackLog(logDirectory, L"目录候选表: " + dirsPath);
            WriteCandidateFileToRecoveredList(dirsPath,
                                              crack->StorageMedia->PathNameHasher,
                                              crack->PathNameHasherOriginalVtPtr,
                                              &crack->StorageMedia->HasherSeed,
                                              crack->OutputDirectory,
                                              recoveredLines,
                                              logDirectory,
                                              processedCount,
                                              totalCount);
        }
        else
        {
            std::wstring matchPath;
            if (FindLatestMatchFile(crack->OutputDirectory, L"dirs_*_match.txt", matchPath))
            {
                unsigned int imported = ImportMatchTextToRecoveredLines(matchPath, recoveredLines);
                WriteRecoveredNameList(crack->OutputDirectory, recoveredLines);
                WriteHashCrackLog(logDirectory, L"未找到目录候选表，已导入已有目录match: " + matchPath + L" imported=" + std::to_wstring(imported));
            }
            else
            {
                WriteHashCrackLog(logDirectory, L"未找到目录候选表。");
            }
        }
        if (hasFilesPath)
        {
            WriteHashCrackLog(logDirectory, L"文件候选表: " + filesPath);
            WriteCandidateFileToRecoveredList(filesPath,
                                              crack->StorageMedia->FileNameHasher,
                                              crack->FileNameHasherOriginalVtPtr,
                                              &crack->StorageMedia->HasherSeed,
                                              crack->OutputDirectory,
                                              recoveredLines,
                                              logDirectory,
                                              processedCount,
                                              totalCount);
        }
        else
        {
            std::wstring matchPath;
            if (FindLatestMatchFile(crack->OutputDirectory, L"files_*_match.txt", matchPath))
            {
                unsigned int imported = ImportMatchTextToRecoveredLines(matchPath, recoveredLines);
                WriteRecoveredNameList(crack->OutputDirectory, recoveredLines);
                WriteHashCrackLog(logDirectory, L"未找到文件候选表，已导入已有文件match: " + matchPath + L" imported=" + std::to_wstring(imported));
            }
            else
            {
                WriteHashCrackLog(logDirectory, L"未找到文件候选表。");
            }
        }

        WriteRecoveredNameList(crack->OutputDirectory, recoveredLines);
        WriteHashCrackLog(logDirectory, L"HashRestore_RecoveredNames.lst 已更新，总映射数: " + std::to_wstring(recoveredLines.size()));
        if (hasDirsPath)
        {
            ArchiveCandidateFile(dirsPath, crack->OutputDirectory, logDirectory);
        }
        if (hasFilesPath)
        {
            ArchiveCandidateFile(filesPath, crack->OutputDirectory, logDirectory);
        }
        NotifyLoaderHashCrackProgress(100u);
        NotifyLoaderHashCrackCompleted();

        delete crack;
        return 0u;
    }
}

namespace Engine
{
    //**********IStringHasher***********//
    tjs_int IStringHasher::GetSaltLength() const
    {
        return this->mSaltSize;
    }

    const tjs_uint8* IStringHasher::GetSaltBytes() const
    {
        return this->mSalt;
    }

    IStringHasher::VptrTable* IStringHasher::GetVptrTable()
    {
        return *(IStringHasher::VptrTable**)this;
    }

    void IStringHasher::SetVptrTable(const VptrTable* vt)
    {
        *(const IStringHasher::VptrTable**)this = vt;
    }
    //================================//


    //*****************Dumper******************//

    static HashCore* g_Instance = nullptr;      //单实例
    HashCore::tCreateCompoundStorageMedia g_CreateStorageMediaFunc = nullptr;     //TVPStorageMedia[Cxdec]接口

    const CompoundStorageMedia* g_StorageMedia = nullptr;                        //封包管理媒体
    const IStringHasher::VptrTable* g_PathNameHasherOriginalVtPtr = nullptr;     //文件夹路径Hash原虚表指针
    const IStringHasher::VptrTable* g_FileNameHasherOriginalVtPtr = nullptr;     //文件名Hash原虚表指针

    IStringHasher::VptrTable g_PathNameHasherHookVt;         //文件夹路径Hash Hook虚表
    IStringHasher::VptrTable g_FileNameHasherHookVt;         //文件名Hash Hook虚表

    tjs_int __fastcall HookPathNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed);
    tjs_int __fastcall HookFileNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed);

    //创建Media Hook
    tjs_error __cdecl HookCreateCompoundStorageMedia(CompoundStorageMedia** retTVPStorageMedia, tTJSVariant* tjsVarPrefix, int argc, void* argv)
    {
        tjs_error result = g_CreateStorageMediaFunc(retTVPStorageMedia, tjsVarPrefix, argc, argv);
        if (TJS_SUCCEEDED(result))
        {
            //Unhook
            HookUtils::InlineHook::UnHook(g_CreateStorageMediaFunc, HookCreateCompoundStorageMedia);

            //获取媒体对象
            CompoundStorageMedia* storageMedia = *retTVPStorageMedia;
            g_StorageMedia = storageMedia;

            //打印Hash参数
            {
                HashCore* dumper = g_Instance;
                Log::Logger& uniLogger = dumper->mUniversalLogger;
                
                uniLogger.WriteUnicode(L"Hash Seed:%s\r\n", storageMedia->HasherSeed.c_str());
                uniLogger.WriteUnicode(L"PathNameHasherSalt:%s\r\n", StringHelper::BytesToHexStringW(storageMedia->PathNameHasher->GetSaltBytes(), storageMedia->PathNameHasher->GetSaltLength()).c_str());
                uniLogger.WriteUnicode(L"FileNameHasherSalt:%s\r\n", StringHelper::BytesToHexStringW(storageMedia->FileNameHasher->GetSaltBytes(), storageMedia->FileNameHasher->GetSaltLength()).c_str());
            }

            //文件夹路径Hash虚表Hook
            {
                IStringHasher::VptrTable* pnHasherVt = storageMedia->PathNameHasher->GetVptrTable();
                g_PathNameHasherOriginalVtPtr = pnHasherVt;

                g_PathNameHasherHookVt = *pnHasherVt;
                g_PathNameHasherHookVt.Calculate = HookPathNameHasherCalcute;
                storageMedia->PathNameHasher->SetVptrTable(&g_PathNameHasherHookVt);
            }

            //文件名Hash虚表Hook
            {
                IStringHasher::VptrTable* fnHasherVt = storageMedia->FileNameHasher->GetVptrTable();
                g_FileNameHasherOriginalVtPtr = fnHasherVt;

                g_FileNameHasherHookVt = *fnHasherVt;
                g_FileNameHasherHookVt.Calculate = HookFileNameHasherCalcute;
                storageMedia->FileNameHasher->SetVptrTable(&g_FileNameHasherHookVt);
            }

            if (IsHashCrackModeEnabled())
            {
                HashCrackThreadParameter* parameter = new HashCrackThreadParameter{};
                parameter->StorageMedia = storageMedia;
                parameter->PathNameHasherOriginalVtPtr = g_PathNameHasherOriginalVtPtr;
                parameter->FileNameHasherOriginalVtPtr = g_FileNameHasherOriginalVtPtr;
                parameter->OutputDirectory = g_Instance->mDumperDirectoryPath;
                HANDLE thread = ::CreateThread(nullptr, 0u, HashCrackThreadProc, parameter, 0u, nullptr);
                if (thread)
                {
                    ::CloseHandle(thread);
                }
                else
                {
                    delete parameter;
                }
            }
        }
        return result;
    }

    //文件夹路径Hash计算Hook fastcall模拟thiscall
    tjs_int __fastcall HookPathNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed)
    {
        tjs_int len = g_PathNameHasherOriginalVtPtr->Calculate(thisObj, nullptr, hashValueRet, str, seed);

        const wchar_t* relativeDirPath = str->c_str();
        //空文件夹替换
        if (*relativeDirPath == L'\0')
        {
            relativeDirPath = L"%EmptyString%";
        }

        tTJSVariantOctet* hashValue = hashValueRet->AsOctetNoAddRef();
        //打印 String[Sign]Hash[NewLine]
        g_Instance->WriteDirectoryHash(relativeDirPath, StringHelper::BytesToHexStringW(hashValue->GetData(), hashValue->GetLength()));

        return len;
    }

    //文件名Hash计算Hook fastcall模拟thiscall
    tjs_int __fastcall HookFileNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed)
    {
        tjs_int len = g_FileNameHasherOriginalVtPtr->Calculate(thisObj, nullptr, hashValueRet, str, seed);

        const wchar_t* fileName = str->c_str();

        tTJSVariantOctet* hashValue = hashValueRet->AsOctetNoAddRef();
        //打印 String[Sign]Hash[NewLine]
        g_Instance->WriteFileNameHash(fileName, StringHelper::BytesToHexStringW(hashValue->GetData(), hashValue->GetLength()));

        return len;
    }

    //================================//


    //**********HashCore***********//
    HashCore::HashCore()
    {
        InitializeCriticalSection(&this->mHashLineLock);
    }

    HashCore::~HashCore()
    {
        DeleteCriticalSection(&this->mHashLineLock);
    }

    void HashCore::SetOutputDirectory(const std::wstring& directory)
    {
        std::wstring dumpOutDirectory = Path::Combine(directory, HashCore::FolderName);
        this->SetHashOutputDirectory(dumpOutDirectory);
    }

    void HashCore::SetHashOutputDirectory(const std::wstring& directory)
    {
        this->mDumperDirectoryPath = directory;

        //创建输出目录
        Directory::Create(directory);

        //日志初始化。Hash日志作为长期映射库追加写入，不再删除旧记录。
        std::wstring directoryHashLogPath = Path::Combine(directory, HashCore::DirectoryHashFileName);
        std::wstring fileNameHashLogPath = Path::Combine(directory, HashCore::FileNameHashFileName);
        std::wstring universalLogPath = Path::Combine(directory, HashCore::UniversalFileName);

        this->mDirectoryHashLogger.Close();
        this->mFileNameHashLogger.Close();
        this->mUniversalLogger.Close();

        const bool writeDirectoryBom = IsFileEmptyOrMissing(directoryHashLogPath);
        const bool writeFileNameBom = IsFileEmptyOrMissing(fileNameHashLogPath);

        LoadUnicodeHashLines(directoryHashLogPath, this->mKnownDirectoryHashLines);
        LoadUnicodeHashLines(fileNameHashLogPath, this->mKnownFileNameHashLines);

        File::Delete(universalLogPath);
        this->mDirectoryHashLogger.Open(directoryHashLogPath.c_str());
        this->mFileNameHashLogger.Open(fileNameHashLogPath.c_str());
        this->mUniversalLogger.Open(universalLogPath.c_str());

        //写UTF-16LE bom头。追加已有Hash日志时不能在中间再次写BOM。
        {
            WORD bom = 0xFEFF;
            if (writeDirectoryBom)
            {
                this->mDirectoryHashLogger.WriteData(&bom, sizeof(bom));
            }

            if (writeFileNameBom)
            {
                this->mFileNameHashLogger.WriteData(&bom, sizeof(bom));
            }

            this->mUniversalLogger.WriteData(&bom, sizeof(bom));
        }
    }

    void HashCore::WriteDirectoryHash(const std::wstring& relativeDirPath, const std::wstring& hash)
    {
        std::wstring line = relativeDirPath + HashCore::Split + hash;

        EnterCriticalSection(&this->mHashLineLock);
        if (this->mKnownDirectoryHashLines.insert(line).second)
        {
            this->mDirectoryHashLogger.WriteUnicode(L"%s\r\n", line.c_str());
        }
        LeaveCriticalSection(&this->mHashLineLock);
    }

    void HashCore::WriteFileNameHash(const std::wstring& fileName, const std::wstring& hash)
    {
        std::wstring line = fileName + HashCore::Split + hash;

        EnterCriticalSection(&this->mHashLineLock);
        if (this->mKnownFileNameHashLines.insert(line).second)
        {
            this->mFileNameHashLogger.WriteUnicode(L"%s\r\n", line.c_str());
        }
        LeaveCriticalSection(&this->mHashLineLock);
    }

    void HashCore::Initialize(PVOID codeVa, DWORD codeSize)
    {
        PVOID createMedia = PE::SearchPattern(codeVa, codeSize, HashCore::CreateCompoundStorageMediaSignature, sizeof(HashCore::CreateCompoundStorageMediaSignature) - 1);
        if (createMedia)
        {
            g_CreateStorageMediaFunc = (tCreateCompoundStorageMedia)createMedia;

            //Hook创建媒体接口
            HookUtils::InlineHook::Hook(g_CreateStorageMediaFunc, HookCreateCompoundStorageMedia);
        }
    }

    bool HashCore::IsInitialized()
    {
        return g_CreateStorageMediaFunc != nullptr;
    }

    //************=====Static=====************//

    HashCore* HashCore::GetInstance()
    {
        if (g_Instance == nullptr)
        {
            g_Instance = new HashCore();
        }
        return g_Instance;
    }

    void HashCore::Release()
    {
        if (g_Instance)
        {
            delete g_Instance;
            g_Instance = nullptr;
        }
    }
    //================================//
}
