﻿/**
 * @file encoding.cpp
 * @brief 编码转换工具类实现
 * 
 * 提供 ANSI 与 Unicode 之间的编码转换功能，支持多种代码页。
 */

#include <windows.h>
#include "encoding.h"

#undef max

namespace Encoding
{
    /**
     * @brief ANSI 转 Unicode
     * 
     * 使用 Windows API MultiByteToWideChar 进行编码转换。
     * 转换流程：
     * 1. 检查输入字符串是否为空
     * 2. 检查字符串长度是否超过 int 最大值
     * 3. 调用 MultiByteToWideChar 获取目标缓冲区大小
     * 4. 分配缓冲区并执行转换
     * 
     * @param source ANSI 字符串
     * @param codePage 代码页
     * @return Unicode 字符串，转换失败返回空字符串
     */
	std::wstring AnsiToUnicode(const std::string& source, int codePage)
	{
		if (source.length() == 0)
		{
			return std::wstring();
		}

		if (source.length() > (size_t)std::numeric_limits<int>::max())
		{
			return std::wstring();
		}

		int length = MultiByteToWideChar(codePage, 0, source.c_str(), (int)source.length(), NULL, 0);

		if (length <= 0)
		{
			return std::wstring();
		}

		std::wstring output(length, L'\0');

		if (MultiByteToWideChar(codePage, 0, source.c_str(), (int)source.length(), (LPWSTR)output.data(), (int)output.length() + 1) == 0)
		{
			return std::wstring();
		}

		return output;
	}

    /**
     * @brief Unicode 转 ANSI
     * 
     * 使用 Windows API WideCharToMultiByte 进行编码转换。
     * 转换流程与 AnsiToUnicode 类似。
     * 
     * @param source Unicode 字符串
     * @param codePage 代码页
     * @return ANSI 字符串，转换失败返回空字符串
     */
	std::string UnicodeToAnsi(const std::wstring& source, int codePage)
	{
		if (source.length() == 0)
		{
			return std::string();
		}

		if (source.length() > (size_t)std::numeric_limits<int>::max())
		{
			return std::string();
		}

		int length = WideCharToMultiByte(codePage, 0, source.c_str(), (int)source.length(), NULL, 0, NULL, NULL);

		if (length <= 0)
		{
			return std::string();
		}

		std::string output(length, '\0');

		if (WideCharToMultiByte(codePage, 0, source.c_str(), (int)source.length(), (LPSTR)output.data(), (int)output.length() + 1, NULL, NULL) == 0)
		{
			return std::string();
		}

		return output;
	}
}
