#pragma once

// 往文件尾部追加一行 UTF-8 文本。
//
// 这段代码原来在三个地方各抄了一份（批量解包 UI、Hash 还原 UI、HashCore），
// 实现略有出入（CreateFileW / _wfopen，共享模式也不同），行为却是一样的。
// 合成一份：UTF-8 无 BOM、追加、WriteFile 显式共享读+写。
//
// 注意这是**产物写入**用的（HashRestore_Report.tsv、HashRestore_Unresolved.log 等），
// 不是会话日志——会话日志走 Common/log.h 的 Log::Logger（带时间戳/级别/线程）。
//
// header-only：CxdecExtractorUI / CxdecAntiMalform 这两个工程不编 Common 的 cpp，
// 头文件形式不用去改它们的源码列表。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <string>

namespace Utf8Text
{
    inline std::string ToUtf8(const std::wstring& text)
    {
        if (text.empty())
        {
            return std::string();
        }

        const int length = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                                 static_cast<int>(text.size()), nullptr, 0, nullptr,
                                                 nullptr);
        if (length <= 0)
        {
            return std::string();
        }

        std::string utf8(static_cast<size_t>(length), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), &utf8[0],
                              length, nullptr, nullptr);
        return utf8;
    }

    // 追加一行。文件不存在就建；写失败（盘满/权限/占用）就静默放弃——
    // 这些调用的位置都已经没有更好的上报渠道，调用方另有失败日志。
    inline void AppendLine(const std::wstring& filePath, const std::wstring& line)
    {
        const std::string utf8 = ToUtf8(line);
        if (utf8.empty())
        {
            return;
        }

        HANDLE file = ::CreateFileW(filePath.c_str(),
                                    FILE_APPEND_DATA,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        DWORD written = 0;
        ::WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        ::CloseHandle(file);
    }

    // 覆盖写整份文本。
    inline void WriteAll(const std::wstring& filePath, const std::wstring& text)
    {
        const std::string utf8 = ToUtf8(text);

        HANDLE file = ::CreateFileW(filePath.c_str(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        DWORD written = 0;
        if (!utf8.empty())
        {
            ::WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        }
        ::CloseHandle(file);
    }
}

// 各调用点原来的名字，保留下来免得改一大片调用代码
inline void AppendUtf8Line(const std::wstring& filePath, const std::wstring& line)
{
    Utf8Text::AppendLine(filePath, line);
}

inline void WriteUtf8Text(const std::wstring& filePath, const std::wstring& text)
{
    Utf8Text::WriteAll(filePath, text);
}
