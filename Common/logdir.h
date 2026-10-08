#pragma once

// 全项目的日志落点都从这里算，别再一处一个目录。
//
// 规则：<工具根>\Log\ —— 工具根就是 loader.exe 所在目录。各模块自己的 DLL 通常
// 放在子目录 CxdecExtractordll 里，所以传进来的模块目录若是那一层就上跳一级。
// 工具根写不了（装在 Program Files、或整个目录只读）时退到
// %LOCALAPPDATA%\KrkrExtract\Log\，并把最终位置写进日志头。
//
// 写成头文件形式：CxdecExtractorUI / CxdecAntiMalform 这两个工程是独立的
// （不编 Common 的 cpp），头文件形式不用去改它们的源码列表。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <cwctype>
#include <string>

namespace Log
{
    struct LogDirectory
    {
        std::wstring path;         // 最终用的目录
        bool fallback = false;     // true = 工具根写不了，用了 %LOCALAPPDATA%
        std::wstring primaryPath;  // 本来该用的目录（写进日志头，说明为什么换了地方）
        DWORD primaryError = 0;    // 主位置建不出来的错误码；0 = 没失败
    };

    namespace DirectoryDetail
    {
        inline std::wstring StripTrailingSeparators(const std::wstring& path)
        {
            size_t end = path.size();
            while (end > 0 && (path[end - 1] == L'\\' || path[end - 1] == L'/'))
            {
                --end;
            }
            return path.substr(0, end);
        }

        inline std::wstring LeafName(const std::wstring& path)
        {
            const size_t separator = path.find_last_of(L"\\/");
            return separator == std::wstring::npos ? path : path.substr(separator + 1);
        }

        inline std::wstring ParentDirectory(const std::wstring& path)
        {
            const size_t separator = path.find_last_of(L"\\/");
            return separator == std::wstring::npos ? std::wstring() : path.substr(0, separator);
        }

        inline std::wstring ToLower(const std::wstring& text)
        {
            std::wstring lower = text;
            for (wchar_t& ch : lower)
            {
                ch = static_cast<wchar_t>(::towlower(ch));
            }
            return lower;
        }

        // 逐级建目录。父级可能也不存在（%LOCALAPPDATA%\KrkrExtract\Log 的第一级）。
        // 已存在算成功——多个进程同时起，谁先建都正常。
        inline bool EnsureDirectory(const std::wstring& path, DWORD* errorOut = nullptr)
        {
            if (errorOut != nullptr)
            {
                *errorOut = 0;
            }
            if (path.empty())
            {
                return false;
            }

            const DWORD attributes = ::GetFileAttributesW(path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES)
            {
                return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            }

            std::wstring current;
            size_t index = 0;
            if (path.size() >= 2 && path[1] == L':')
            {
                current.assign(path, 0, 2);  // 盘符前缀单独留着，别拼成 "C:foo"
                index = 2;
            }
            else if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\')
            {
                // UNC：\\server\share 这两段必须整体存在，逐段建会失败，
                // 于是"工具放在网络共享上"会直接把日志退到 %LOCALAPPDATA%。
                // 跳过它们，第一次 CreateDirectoryW 就是完整的 \\server\share\Log。
                const size_t shareEnd = path.find_first_of(L"\\/", 2);
                index = shareEnd == std::wstring::npos ? path.size() : shareEnd + 1;
            }

            while (index <= path.size())
            {
                const size_t separator = path.find_first_of(L"\\/", index);
                const size_t end = separator == std::wstring::npos ? path.size() : separator;
                if (end > index)
                {
                    current.assign(path.begin(), path.begin() + end);
                    if (!::CreateDirectoryW(current.c_str(), nullptr) &&
                        ::GetLastError() != ERROR_ALREADY_EXISTS)
                    {
                        if (errorOut != nullptr)
                        {
                            *errorOut = ::GetLastError();
                        }
                        return false;
                    }
                }
                if (separator == std::wstring::npos)
                {
                    break;
                }
                index = separator + 1;
            }

            const DWORD finalAttributes = ::GetFileAttributesW(path.c_str());
            if (finalAttributes != INVALID_FILE_ATTRIBUTES && (finalAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                return true;
            }
            if (errorOut != nullptr)
            {
                // 建到一半失败、或路径被同名文件占着；重新拿一次错误码（可能是 0，看日志的人自己判断）
                *errorOut = ::GetLastError();
            }
            return false;
        }

        inline std::wstring EnvironmentValue(const wchar_t* name)
        {
            wchar_t buffer[MAX_PATH]{};
            const DWORD length = ::GetEnvironmentVariableW(name, buffer, _countof(buffer));
            if (length == 0 || length >= _countof(buffer))
            {
                return std::wstring();
            }
            return std::wstring(buffer, length);
        }
    }

    // ownModuleDirectory：调用方自己的模块所在目录（DLL 目录就行，不必是 exe）。
    inline LogDirectory ResolveLogDirectory(const std::wstring& ownModuleDirectory)
    {
        using namespace DirectoryDetail;

        LogDirectory result;

        std::wstring root = StripTrailingSeparators(ownModuleDirectory);
        if (ToLower(LeafName(root)) == L"cxdecextractordll")
        {
            root = ParentDirectory(root);
        }

        result.primaryPath = root.empty() ? L"Log" : root + L"\\Log";
        if (EnsureDirectory(result.primaryPath, &result.primaryError))
        {
            result.path = result.primaryPath;
            return result;
        }

        // 工具根不可写就退到用户目录：日志是要用户发回来的东西，
        // 不能因为工具装在只读位置就整个丢掉。
        const std::wstring localAppData = EnvironmentValue(L"LOCALAPPDATA");
        if (!localAppData.empty())
        {
            const std::wstring base = localAppData + L"\\KrkrExtract";
            const std::wstring alternative = base + L"\\Log";
            if (EnsureDirectory(alternative))
            {
                result.path = alternative;
                result.fallback = true;
                return result;
            }
        }

        // 兜底：仍然用主位置，让后面的 Open 把真实错误码记下来
        result.path = result.primaryPath;
        result.fallback = true;
        return result;
    }

    inline std::wstring LogFilePath(const LogDirectory& directory, const wchar_t* fileName)
    {
        const std::wstring name = fileName != nullptr ? fileName : L"";
        if (directory.path.empty())
        {
            return name;
        }
        return directory.path + L"\\" + name;
    }

    // 手边没有模块句柄时的入口：传**本模块里任意一个函数/静态变量的地址**，
    // 由系统反查它属于哪个模块，再算出统一日志目录。
    //
    // 给 HashCore.cpp 那种"同一份源码编进两个模块"的场景用——运行时按地址
    // 反查出来的就是当前这个模块，不会认错。
    inline LogDirectory ResolveLogDirectoryFromCallerModule(const void* callerAddress)
    {
        HMODULE module = nullptr;
        if (callerAddress == nullptr ||
            !::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                      GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                  reinterpret_cast<LPCWSTR>(callerAddress),
                                  &module) ||
            module == nullptr)
        {
            return ResolveLogDirectory(std::wstring());
        }

        wchar_t buffer[MAX_PATH]{};
        const DWORD length = ::GetModuleFileNameW(module, buffer, _countof(buffer));
        if (length == 0 || length >= _countof(buffer))
        {
            return ResolveLogDirectory(std::wstring());
        }
        return ResolveLogDirectory(DirectoryDetail::ParentDirectory(std::wstring(buffer, length)));
    }
}
