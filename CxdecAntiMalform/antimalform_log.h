#pragma once

// AntiMalform 模块的日志。
//
// 原来 tjs_patcher.cpp / runtime_hook.cpp / tjs2_parser.cpp 各抄了一份，名字还都不一样
// （TjsLog / AmLog / T2Log）：每写一行都 _wfopen_s 开一次，文本模式走 ANSI，没有时间戳。
// 现在合成这一份：UTF-8 字节写入，落点跟其余日志一样在 <工具根>\Log\。
//
// 本模块不编 Common 的 cpp，所以这里只用 header-only 的 logdir.h。

#include "logdir.h"

#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

namespace AntiMalformLog
{
    namespace Detail
    {
        // 取本模块地址反查工具根。这个函数在 AntiMalform 的每个 .cpp 里都会实例一份，
        // 但都属于同一个模块，算出来是同一个目录。
        inline const std::wstring& LogFilePath()
        {
            static const std::wstring path = Log::LogFilePath(
                Log::ResolveLogDirectoryFromCallerModule(
                    reinterpret_cast<const void*>(&AntiMalformLog::Detail::LogFilePath)),
                L"CxdecAntiMalform.log");
            return path;
        }

        inline void WriteV(const wchar_t* format, va_list args)
        {
            wchar_t buffer[512];
            if (_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args) <= 0)
            {
                return;
            }

            ::OutputDebugStringW(buffer);

            // 行首格式与 Common 的 Log::Logger 对齐：时间 | 级别 | 线程 | 正文。
            // 这边只出 Info 级的行，级别位照样留着，方便和别的日志一起筛。
            SYSTEMTIME st{};
            ::GetLocalTime(&st);
            wchar_t line[640];
            if (swprintf_s(line,
                           _countof(line),
                           L"%04u-%02u-%02u %02u:%02u:%02u | I | T%04lX | %s",
                           st.wYear,
                           st.wMonth,
                           st.wDay,
                           st.wHour,
                           st.wMinute,
                           st.wSecond,
                           static_cast<unsigned long>(::GetCurrentThreadId()),
                           buffer) <= 0)
            {
                return;
            }

            // 转成 UTF-8 再写。以前是 _wfopen_s(L"a") + fwprintf(L"%s")，
            // 按系统 ANSI 代码页落盘，非中文系统上中文全是问号。
            const int needed = ::WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
            if (needed <= 1)
            {
                return;
            }
            std::string utf8(static_cast<size_t>(needed), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, line, -1, &utf8[0], needed, nullptr, nullptr);
            utf8.resize(static_cast<size_t>(needed - 1));
            utf8 += "\r\n";

            FILE* file = nullptr;
            if (_wfopen_s(&file, LogFilePath().c_str(), L"ab") != 0 || file == nullptr)
            {
                return;
            }
            fwrite(utf8.data(), 1, utf8.size(), file);
            fflush(file);
            fclose(file);
        }
    }
}

// 模块内统一用这个
inline void AmLog(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    AntiMalformLog::Detail::WriteV(format, args);
    va_end(args);
}
