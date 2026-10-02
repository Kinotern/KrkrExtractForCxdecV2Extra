#include <algorithm>
#include <string>
#include <cstdarg>
#include <vector>
#include "stringhelper.h"

namespace StringHelper
{
	bool StartsWith(const char* source, const char* sub)
	{
		std::string_view vsource(source);
		std::string_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(0, vsub.length(), sub) == 0;
	}

	bool StartsWith(const wchar_t* source, const wchar_t* sub)
	{
		std::wstring_view vsource(source);
		std::wstring_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(0, vsub.length(), sub) == 0;
	}

	bool StartsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

	bool StartsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

	bool EndsWith(const char* source, const char* sub)
	{
		std::string_view vsource(source);
		std::string_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(vsource.length() - vsub.length(), vsub.length(), sub) == 0;
	}

	bool EndsWith(const wchar_t* source, const wchar_t* sub)
	{
		std::wstring_view vsource(source);
		std::wstring_view vsub(sub);

		if (vsource.length() == 0 || vsub.length() == 0 || vsource.length() < vsub.length())
		{
			return false;
		}

		return vsource.compare(vsource.length() - vsub.length(), vsub.length(), sub) == 0;
	}

	bool EndsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

	bool EndsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

	std::string ToLower(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::tolower(c); });

		return output;
	}

	std::wstring ToLower(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::tolower(c); });

		return output;
	}

	std::string ToUpper(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::toupper(c); });

		return output;
	}

	std::wstring ToUpper(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::toupper(c); });

		return output;
	}

	std::string Format(const char* format, ...)
	{
		char buf[1024];
		int count;
		va_list ap;

		va_start(ap, format);
		count = vsnprintf(buf, sizeof(buf), format, ap);
		va_end(ap);

		if (count <= 0)
		{
			return std::string();
		}

		if (count < sizeof(buf))
		{
			return std::string(buf, count);
		}

		std::string output(count, '\0');

		va_start(ap, format);
		count = vsnprintf(const_cast<std::string::pointer>(output.data()), output.size() + 1, format, ap);
		va_end(ap);

		if (count <= 0)
		{
			return std::string();
		}

		return output;
	}

	std::string VFormat(const char* format, va_list ap)
	{
		char buf[1024];
		int count;

		count = vsnprintf(buf, sizeof(buf), format, ap);

		if (count <= 0)
		{
			return std::string();
		}

		if (count < sizeof(buf))
		{
			return std::string(buf, count);
		}

		std::string output(count, '\0');

		count = vsnprintf(const_cast<std::string::pointer>(output.data()), output.size() + 1, format, ap);

		if (count <= 0)
		{
			return std::string();
		}

		return output;
	}

	std::wstring Format(const wchar_t* format, ...)
	{
		va_list ap;

		va_start(ap, format);
		int count = _vscwprintf(format, ap);
		va_end(ap);

		if (count <= 0)
		{
			return std::wstring();
		}

		std::wstring output((size_t)count, L'\0');
		va_start(ap, format);
		_vsnwprintf_s(&output[0], output.size() + 1, _TRUNCATE, format, ap);
		va_end(ap);

		return output;
	}

	std::wstring VFormat(const wchar_t* format, va_list ap)
	{
		va_list ap2;
		va_copy(ap2, ap);
		int count = _vscwprintf(format, ap2);
		va_end(ap2);

		if (count <= 0)
		{
			return std::wstring();
		}

		std::wstring output((size_t)count, L'\0');
		_vsnwprintf_s(&output[0], output.size() + 1, _TRUNCATE, format, ap);

		return output;
	}

	std::wstring BytesToHexStringW(const unsigned __int8* data, unsigned __int32 length)
	{
		constexpr const wchar_t hexStringW[32] = L"0123456789ABCDEF";

		std::wstring s;
		for (unsigned __int32 index = 0; index < length; index++)
		{
			s += hexStringW[(data[index] & 0xF0) >> 4];
			s += hexStringW[(data[index] & 0x0F) >> 0];
		}
		return s;
	}
}
