#include <cstdarg>
#include <ctime>
#include "log.h"
#include "stringhelper.h"
#include "encoding.h"

namespace Log
{
	Logger::Logger() : m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
	}

	Logger::Logger(const wchar_t* lpFileName)
		: m_pOutput{}
	{
		InitializeCriticalSection(&m_Lock);
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
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\r\n";

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

		auto utf = Encoding::UnicodeToAnsi(content, Encoding::CodePage::UTF_8);
		auto timestamp = GetTimeString();

		auto output = timestamp + " | " + utf + "\r\n";

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
