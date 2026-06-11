﻿﻿﻿/**
 * @file log.cpp
 * @brief 日志工具类实现
 * 
 * 提供线程安全的日志记录功能，支持多种编码格式输出。
 */

#include <cstdarg>
#include <ctime>
#include "log.h"
#include "stringhelper.h"
#include "encoding.h"


namespace Log
{
    /**
     * @brief 默认构造函数
     * 
     * 初始化临界区，日志文件句柄设置为空。
     */
	Logger::Logger() : m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
	}

    /**
     * @brief 构造函数（带文件名）
     * 
     * 初始化临界区并打开指定的日志文件。
     * 
     * @param lpFileName 日志文件路径
     */
	Logger::Logger(const wchar_t* lpFileName)
		: m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
		Open(lpFileName);
	}

    /**
     * @brief 析构函数
     * 
     * 关闭日志文件并释放临界区资源。
     */
	Logger::~Logger()
	{
		Close();
		DeleteCriticalSection(&m_Lock);
	}

    /**
     * @brief 打开日志文件
     * 
     * 使用 _wfsopen 以追加二进制模式打开文件，
     * 共享模式设置为拒绝其他进程写入（_SH_DENYWR）。
     * 
     * @param lpFileName 日志文件路径
     */
	void Logger::Open(const wchar_t* lpFileName)
	{
		EnterCriticalSection(&m_Lock);
		m_pOutput = _wfsopen(lpFileName, L"ab", _SH_DENYWR);
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 关闭日志文件
     * 
     * 刷新缓冲区，关闭文件句柄并置为空指针。
     */
	void Logger::Close()
	{
		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fflush(m_pOutput);
		}

		if (m_pOutput)
		{
			fclose(m_pOutput);
			m_pOutput = nullptr;
		}
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 刷新缓冲区
     * 
     * 将用户缓冲区数据强制写入内核缓冲区，确保数据不丢失。
     */
	void Logger::Flush()
	{
		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 获取当前时间字符串
     * 
     * 格式：YYYY-MM-DD HH:MM:SS
     * 
     * @return 时间字符串
     */
	static std::string GetTimeString()
	{
		time_t tv;
		struct tm tm;
		char buf[32];

		time(&tv);
		localtime_s(&tm, &tv);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

		return std::string(buf);
	}

    /**
     * @brief 写入 ANSI 格式日志（指定代码页）
     * 
     * 编码转换流程：
     * 1. 使用 va_list 格式化字符串
     * 2. ANSI -> Unicode（指定代码页）
     * 3. Unicode -> UTF-8
     * 4. 写入文件并刷新
     * 
     * @param iCodePage 代码页
     * @param lpFormat 格式化字符串
     * @param ... 可变参数
     */
	void Logger::WriteAnsi(int iCodePage, const char* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto unicode = Encoding::AnsiToUnicode(content, iCodePage);
		auto output = Encoding::UnicodeToAnsi(unicode, Encoding::CodePage::UTF_8);

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 写入 ANSI 格式日志（带时间戳）
     * 
     * 同 WriteAnsi，但在日志前添加时间戳前缀。
     * 格式：[YYYY-MM-DD HH:MM:SS] | 日志内容
     * 
     * @param iCodePage 代码页
     * @param lpFormat 格式化字符串
     * @param ... 可变参数
     */
	void Logger::WriteLineAnsi(int iCodePage, const char* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto unicode = Encoding::AnsiToUnicode(content, iCodePage);
		auto utf = Encoding::UnicodeToAnsi(unicode, Encoding::CodePage::UTF_8);
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\r\n";

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 写入 Unicode 格式日志
     * 
     * 编码转换流程：
     * 1. 使用 va_list 格式化 Unicode 字符串
     * 2. Unicode -> UTF-8
     * 3. 写入文件并刷新
     * 
     * @param lpFormat 格式化字符串
     * @param ... 可变参数
     */
	void Logger::Write(const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto output = Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8);

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

    /**
     * @brief 写入 Unicode 格式日志（带时间戳）
     * 
     * 同 Write，但在日志前添加时间戳前缀。
     * 格式：[YYYY-MM-DD HH:MM:SS] | 日志内容
     * 
     * @param lpFormat 格式化字符串
     * @param ... 可变参数
     */
	void Logger::WriteLine(const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto utf = Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8);
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\r\n";

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}


    /**
     * @brief 直接写入 Unicode 原始数据
     * 
     * 不进行编码转换，直接写入 UTF-16LE 编码的数据。
     * 每个字符占 2 字节。
     * 
     * @param lpFormat 格式化字符串
     * @param ... 可变参数
     */
	void Logger::WriteUnicode(const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(content.data(), content.length() * 2, 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}


    /**
     * @brief 写入二进制数据
     * 
     * 直接将二进制数据写入日志文件，不进行任何编码转换。
     * 
     * @param data 数据指针
     * @param size 数据大小（字节）
     */
	void Logger::WriteData(void* data, unsigned int size) 
	{
		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fwrite(data, size, 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

}
