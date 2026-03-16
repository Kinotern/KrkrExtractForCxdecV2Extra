// log.cpp

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
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
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
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
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
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
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
			fwrite(output.data(), output.length(), 1, m_pOutput);
			fflush(m_pOutput);
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
			fwrite(content.data(), content.length() * 2, 1, m_pOutput);
			fflush(m_pOutput);
		}
		LeaveCriticalSection(&m_Lock);
	}


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
