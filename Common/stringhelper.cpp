﻿﻿﻿/**
 * @file stringhelper.cpp
 * @brief 字符串操作工具类实现
 * 
 * 提供常用的字符串操作功能，包括前缀/后缀判断、大小写转换、
 * 格式化输出和字节转十六进制等功能。
 */

#include <algorithm>
#include <string>
#include <cstdarg>
#include <vector>
#include "stringhelper.h"

namespace StringHelper
{
    /**
     * @brief 判断字符串是否以指定前缀开头（char*版本）
     * 
     * 使用 std::string_view 进行高效比较，避免不必要的内存分配。
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
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

    /**
     * @brief 判断字符串是否以指定前缀开头（wchar_t*版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
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

    /**
     * @brief 判断字符串是否以指定前缀开头（std::string版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

    /**
     * @brief 判断字符串是否以指定前缀开头（std::wstring版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(0, sub.length(), sub) == 0;
	}

    /**
     * @brief 判断字符串是否以指定后缀结尾（char*版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
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

    /**
     * @brief 判断字符串是否以指定后缀结尾（wchar_t*版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
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

    /**
     * @brief 判断字符串是否以指定后缀结尾（std::string版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const std::string& source, const std::string& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

    /**
     * @brief 判断字符串是否以指定后缀结尾（std::wstring版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const std::wstring& source, const std::wstring& sub)
	{
		if (source.length() == 0 || sub.length() == 0 || source.length() < sub.length())
		{
			return false;
		}

		return source.compare(source.length() - sub.length(), sub.length(), sub) == 0;
	}

    /**
     * @brief 转换字符串为小写（std::string版本）
     * 
     * 使用 std::transform 和 lambda 表达式进行逐字符转换。
     * 
     * @param source 源字符串
     * @return 转换后的小写字符串
     */
	std::string ToLower(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::tolower(c); });

		return output;
	}

    /**
     * @brief 转换字符串为小写（std::wstring版本）
     * 
     * @param source 源字符串
     * @return 转换后的小写字符串
     */
	std::wstring ToLower(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::tolower(c); });

		return output;
	}

    /**
     * @brief 转换字符串为大写（std::string版本）
     * 
     * @param source 源字符串
     * @return 转换后的大写字符串
     */
	std::string ToUpper(const std::string& source)
	{
		std::string output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::string::value_type)std::toupper(c); });

		return output;
	}

    /**
     * @brief 转换字符串为大写（std::wstring版本）
     * 
     * @param source 源字符串
     * @return 转换后的大写字符串
     */
	std::wstring ToUpper(const std::wstring& source)
	{
		std::wstring output = source;

		std::transform(output.begin(), output.end(), output.begin(), [](auto c) { return (std::wstring::value_type)std::toupper(c); });

		return output;
	}

    /**
     * @brief 格式化字符串（ANSI版本）
     * 
     * 优化策略：
     * 1. 先尝试写入 1024 字节的小缓冲区
     * 2. 如果返回值大于缓冲区大小，说明需要更大的缓冲区
     * 3. 根据返回值动态分配足够大的缓冲区
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     * @return 格式化后的字符串，失败返回空字符串
     */
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

    /**
     * @brief 格式化字符串（ANSI版本，va_list）
     * 
     * 与 Format 类似，但接受 va_list 参数，用于嵌套调用。
     * 
     * @param format 格式化字符串
     * @param ap va_list 参数
     * @return 格式化后的字符串，失败返回空字符串
     */
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

    /**
     * @brief 格式化字符串（Unicode版本）
     * 
     * 使用 _vsnwprintf_s 进行安全的宽字符格式化。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::wstring Format(const wchar_t* format, ...)
	{
		wchar_t buf[1024];
		int count;
		va_list ap;

		va_start(ap, format);
		count = _vsnwprintf_s(buf, _countof(buf), format, ap);
		va_end(ap);

		if (count <= 0)
		{
			return std::wstring();
		}

		if (count < sizeof(buf))
		{
			return std::wstring(buf, count);
		}

		std::wstring output(count, '\0');

		va_start(ap, format);
		count = _vsnwprintf_s(const_cast<std::wstring::pointer>(output.data()), output.size() + 1, output.size() + 1, format, ap);
		va_end(ap);

		if (count <= 0)
		{
			return std::wstring();
		}

		return output;
	}

    /**
     * @brief 格式化字符串（Unicode版本，va_list）
     * 
     * @param format 格式化字符串
     * @param ap va_list 参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::wstring VFormat(const wchar_t* format, va_list ap)
	{
		wchar_t buf[1024];
		int count;

		count = _vsnwprintf_s(buf, _countof(buf), format, ap);

		if (count <= 0)
		{
			return std::wstring();
		}

		if (count < sizeof(buf))
		{
			return std::wstring(buf, count);
		}

		std::wstring output(count, '\0');

		count = _vsnwprintf_s(const_cast<std::wstring::pointer>(output.data()), output.size() + 1, output.size() + 1, format, ap);

		if (count <= 0)
		{
			return std::wstring();
		}

		return output;
	}

    /**
     * @brief 将字节数组转换为十六进制字符串
     * 
     * 每个字节转换为两个大写十六进制字符。
     * 使用预定义的查找表提高转换效率。
     * 
     * @param data 字节数组指针
     * @param length 字节数组长度
     * @return 十六进制字符串
     */
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
