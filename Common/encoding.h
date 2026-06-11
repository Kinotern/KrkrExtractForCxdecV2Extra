﻿﻿﻿/**
 * @file encoding.h
 * @brief 编码转换工具类
 * 
 * 提供 ANSI 与 Unicode 之间的编码转换功能，支持多种代码页。
 */

#pragma once

#include <string>

namespace Encoding
{
    /**
     * @brief 代码页枚举
     * 
     * 支持的代码页类型：
     * - ACP: 系统默认 ANSI 代码页
     * - UTF_8: UTF-8 编码
     * - SHIFT_JIS: Shift-JIS 编码（日文）
     * - GBK: GBK 编码（简体中文）
     */
	enum CodePage
	{
		ACP = 0,
		UTF_8 = 65001,
		SHIFT_JIS = 932,
		GBK = 936,
	};

    /**
     * @brief ANSI 转 Unicode
     * 
     * 使用 Windows API MultiByteToWideChar 进行编码转换。
     * 
     * @param source ANSI 字符串
     * @param codePage 代码页
     * @return Unicode 字符串，转换失败返回空字符串
     */
	std::wstring AnsiToUnicode(const std::string& source, int codePage);

    /**
     * @brief Unicode 转 ANSI
     * 
     * 使用 Windows API WideCharToMultiByte 进行编码转换。
     * 
     * @param source Unicode 字符串
     * @param codePage 代码页
     * @return ANSI 字符串，转换失败返回空字符串
     */
	std::string UnicodeToAnsi(const std::wstring& source, int codePage);
}
