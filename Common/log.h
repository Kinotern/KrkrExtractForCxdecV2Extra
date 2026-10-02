#pragma once

#include <Windows.h>
#include <cstdio>

namespace Log
{
	class Logger
	{
	public:
		Logger();

		Logger(const wchar_t* lpFileName);

		~Logger();

        // 禁用拷贝构造和赋值
		Logger(const Logger&) = delete;
		Logger& operator=(const Logger&) = delete;

		void Open(const wchar_t* lpFileName);

		void Close();

		void Flush();

		void WriteAnsi(int iCodePage, const char* lpFormat, ...);

		void WriteLineAnsi(int iCodePage, const char* lpFormat, ...);

		void Write(const wchar_t* lpFormat, ...);

		void WriteLine(const wchar_t* lpFormat, ...);

		void WriteUnicode(const wchar_t* lpFormat, ...);

		void WriteData(void* data, unsigned int size);

	private:
		FILE* m_pOutput;           // 日志文件句柄
		CRITICAL_SECTION m_Lock;   // 线程安全锁
	};
}
