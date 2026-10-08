#pragma once

#include <Windows.h>
#include <cstdio>
#include <string>

#include "win32error.h"

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

		// 打开前把已有的非空文件挪成 <路径>.1（旧的 .1 被覆盖）。
		//
		// 解包日志以前是每次运行直接删掉重建：用户"重跑一次看看"，
		// 上一次的失败现场就没了 —— 而那正是最常见的操作。留一代即可保住现场。
		void OpenKeepingPrevious(const wchar_t* lpFileName);

		void Close();

		void Flush();

		void WriteAnsi(int iCodePage, const char* lpFormat, ...);

		void WriteLineAnsi(int iCodePage, const char* lpFormat, ...);

		void Write(const wchar_t* lpFormat, ...);

		void WriteLine(const wchar_t* lpFormat, ...);

		void WriteUnicode(const wchar_t* lpFormat, ...);

		void WriteData(void* data, unsigned int size);

		// 日志文件没打开成功时，之后所有写入都是**静默丢弃**的 ——
		// 于是"日志是空的"既可能是"没出事"，也可能是"日志压根没开成"。
		// 这两个接口让调用方能判断并回退/上报（例如弹提示、或改用别处的日志）。
		bool IsOpen() const { return m_pOutput != nullptr; }

		const Win32Error::Info& LastOpenError() const { return m_OpenError; }

		// 日志自己写失败（盘满、IO 错）也要能被告知，
		// 否则失败现场会跟着日志一起丢掉。
		bool WriteFailed() const { return m_WriteFailed; }

		const Win32Error::Info& FirstWriteError() const { return m_WriteError; }

	private:
		// 记下第一次写失败的原因（之后的失败多半是同一个原因，不必刷屏）
		void NoteWriteFailure();

	private:
		FILE* m_pOutput;           // 日志文件句柄
		CRITICAL_SECTION m_Lock;   // 线程安全锁
		Win32Error::Info m_OpenError;   // 打开失败的原因
		Win32Error::Info m_WriteError;  // 第一次写失败的原因
		bool m_WriteFailed = false;
	};
}
