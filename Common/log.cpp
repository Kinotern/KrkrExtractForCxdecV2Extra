#include <cstdarg>
#include <ctime>
#include "log.h"
#include "stringhelper.h"
#include "encoding.h"

namespace Log
{
	static std::string GetTimeString();

	Logger::Logger() : m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
		// 默认给日志行一个上限：一个解包任务上千条失败是常见的，每条都带
		// 路径和错误码；不设上限就有"日志把盘写满"的可能，而盘满正是我们要
		// 诊断的失败之一，让它成为原因就说不清了。32 MiB ≈ 十几万行。
		m_SizeLimit = 32ull * 1024ull * 1024ull;
	}

	Logger::Logger(const wchar_t* lpFileName)
		: m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
		m_SizeLimit = 32ull * 1024ull * 1024ull;
		Open(lpFileName);
	}

	Logger::~Logger()
	{
		Close();
		DeleteCriticalSection(&m_Lock);
	}

	void Logger::Open(const wchar_t* lpFileName)
	{
		EnterCriticalSection(&m_Lock);
		m_pOutput = _wfsopen(lpFileName, L"ab", _SH_DENYWR);
		if (m_pOutput == nullptr)
		{
			// 打不开就是**整场日志静默丢弃**，必须留下原因：
			// 否则用户报"日志是空的"时，我们分不清是没出事还是日志没开成。
			m_OpenError = Win32Error::CaptureBoth();
		}
		else
		{
			m_OpenError = Win32Error::Info{};

			// 同一个 Logger 会被重开（例如产物目录与日志目录分两次设），
			// 上限计数要按这一次重新起算。
			m_LineBytes = 0;
			m_Truncated = false;
		}
		LeaveCriticalSection(&m_Lock);
	}

	void Logger::OpenKeepingPrevious(const wchar_t* lpFileName)
	{
		// 只在"确实有内容"时才挪：空文件挪来挪去没有意义，还会让 .1 看起来像是有历史
		const DWORD attributes = ::GetFileAttributesW(lpFileName);
		if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			WIN32_FILE_ATTRIBUTE_DATA data{};
			if (::GetFileAttributesExW(lpFileName, GetFileExInfoStandard, &data) &&
				data.nFileSizeHigh == 0 && data.nFileSizeLow > 0)
			{
				const std::wstring previous = std::wstring(lpFileName) + L".1";
				::MoveFileExW(lpFileName, previous.c_str(), MOVEFILE_REPLACE_EXISTING);
			}
		}

		Open(lpFileName);
	}

	void Logger::NoteWriteFailure()
	{
		// 只记第一次：后面的失败多半是同一个原因，刷屏没有意义
		if (!m_WriteFailed)
		{
			m_WriteFailed = true;
			m_WriteError = Win32Error::CaptureBoth();
		}
	}

	// 已持锁的裸写。fwrite + fflush 都查，否则盘满会静默丢日志。
	void Logger::WriteRawLocked(const void* data, size_t size)
	{
		if (m_pOutput == nullptr || data == nullptr || size == 0)
		{
			return;
		}
		if (fwrite(data, size, 1, m_pOutput) != 1)
		{
			NoteWriteFailure();
			return;
		}
		if (fflush(m_pOutput) != 0)
		{
			NoteWriteFailure();
		}
	}

	void Logger::SetMinimumLevel(Level level)
	{
		EnterCriticalSection(&m_Lock);
		m_MinLevel = level;
		LeaveCriticalSection(&m_Lock);
	}

	void Logger::SetSizeLimit(unsigned long long bytes)
	{
		EnterCriticalSection(&m_Lock);
		m_SizeLimit = bytes;
		LeaveCriticalSection(&m_Lock);
	}

	unsigned long long Logger::LineBytesWritten()
	{
		EnterCriticalSection(&m_Lock);
		const unsigned long long bytes = m_LineBytes;
		LeaveCriticalSection(&m_Lock);
		return bytes;
	}

	bool Logger::Truncated()
	{
		EnterCriticalSection(&m_Lock);
		const bool truncated = m_Truncated;
		LeaveCriticalSection(&m_Lock);
		return truncated;
	}

	// "2026-10-08 20:49:31 | E | T1a2c | 正文"
	//
	// 级别和线程号都进正文前缀：解包是多个 worker 线程并行跑的，日志会交错；
	// 没有线程号就分不清"同一个域一直失败"还是"几个线程各失败一次"。
	std::string Logger::BuildLine(Level level, const std::string& utf8Text)
	{
		char tag = 'I';
		switch (level)
		{
			case Level::Debug: tag = 'D'; break;
			case Level::Warn:  tag = 'W'; break;
			case Level::Error: tag = 'E'; break;
			case Level::Info:
			default:           tag = 'I'; break;
		}

		char threadTag[32] = {};
		sprintf_s(threadTag, "T%04lX", static_cast<unsigned long>(::GetCurrentThreadId()));

		return GetTimeString() + " | " + tag + " | " + threadTag + " | " + utf8Text + "\r\n";
	}

	void Logger::WriteLineText(const std::string& utf8Text, Level level)
	{
		EnterCriticalSection(&m_Lock);

		if (m_pOutput != nullptr)
		{
			if (level < m_MinLevel)
			{
				LeaveCriticalSection(&m_Lock);
				return;
			}

			if (m_SizeLimit > 0 && m_LineBytes >= m_SizeLimit)
			{
				// 只提示一次，然后静默——否则"日志满了"这句话本身会把盘写满。
				// 措辞要挡住一种误读：截断不等于"后面没事"，只是没记下来。
				if (!m_Truncated)
				{
					m_Truncated = true;
					const std::string marker = BuildLine(
						Level::Warn,
						"日志行已达上限 " + std::to_string(m_SizeLimit) +
							" 字节，后续日志行不再写入（这里是截断，不代表后面没有出错）");
					WriteRawLocked(marker.data(), marker.size());
				}
				LeaveCriticalSection(&m_Lock);
				return;
			}

			const std::string output = BuildLine(level, utf8Text);
			m_LineBytes += output.size();
			WriteRawLocked(output.data(), output.size());
		}

		LeaveCriticalSection(&m_Lock);
	}

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

	void Logger::Flush()
	{
		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}

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
			if (fwrite(output.data(), output.length(), 1, m_pOutput) != 1)
			{
				NoteWriteFailure();
			}
			else if (fflush(m_pOutput) != 0)
			{
				NoteWriteFailure();
			}
		}
		LeaveCriticalSection(&m_Lock);
	}

	void Logger::WriteLineAnsi(int iCodePage, const char* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		auto unicode = Encoding::AnsiToUnicode(content, iCodePage);
		auto utf = Encoding::UnicodeToAnsi(unicode, Encoding::CodePage::UTF_8);

		WriteLineText(utf, Level::Info);
	}

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
			if (fwrite(output.data(), output.length(), 1, m_pOutput) != 1)
			{
				NoteWriteFailure();
			}
			else if (fflush(m_pOutput) != 0)
			{
				NoteWriteFailure();
			}
		}
		LeaveCriticalSection(&m_Lock);
	}

	void Logger::WriteLine(const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		WriteLineText(Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8), Level::Info);
	}

	void Logger::WriteLineLevel(Level level, const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		WriteLineText(Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8), level);
	}

	void Logger::WriteUnicode(const wchar_t* lpFormat, ...)
	{
		va_list ap;

		va_start(ap, lpFormat);
		auto content = StringHelper::VFormat(lpFormat, ap);
		va_end(ap);

		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			if (fwrite(content.data(), content.length() * 2, 1, m_pOutput) != 1)
			{
				NoteWriteFailure();
			}
			else if (fflush(m_pOutput) != 0)
			{
				NoteWriteFailure();
			}
		}
		LeaveCriticalSection(&m_Lock);
	}

	void Logger::WriteData(void* data, unsigned int size) 
	{
		EnterCriticalSection(&m_Lock);
		if (m_pOutput)
		{
			if (fwrite(data, size, 1, m_pOutput) != 1)
			{
				NoteWriteFailure();
			}
			else if (fflush(m_pOutput) != 0)
			{
				NoteWriteFailure();
			}
		}
		LeaveCriticalSection(&m_Lock);
	}

}
