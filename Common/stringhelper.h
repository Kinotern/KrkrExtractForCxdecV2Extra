﻿﻿﻿/**
 * @file stringhelper.h
 * @brief 字符串操作工具类
 * 
 * 提供常用的字符串操作功能，包括前缀/后缀判断、大小写转换、
 * 格式化输出和字节转十六进制等功能。
 */

#pragma once

#include <string>
#include <vector>

namespace StringHelper
{
    /**
     * @brief 判断字符串是否以指定前缀开头（char*版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const char* source, const char* sub);

    /**
     * @brief 判断字符串是否以指定前缀开头（wchar_t*版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const wchar_t* source, const wchar_t* sub);

    /**
     * @brief 判断字符串是否以指定前缀开头（std::string版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const std::string& source, const std::string& sub);

    /**
     * @brief 判断字符串是否以指定前缀开头（std::wstring版本）
     * 
     * @param source 源字符串
     * @param sub 前缀字符串
     * @return 以指定前缀开头返回 true，否则返回 false
     */
	bool StartsWith(const std::wstring& source, const std::wstring& sub);

    /**
     * @brief 判断字符串是否以指定后缀结尾（char*版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const char* source, const char* sub);

    /**
     * @brief 判断字符串是否以指定后缀结尾（wchar_t*版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const wchar_t* source, const wchar_t* sub);

    /**
     * @brief 判断字符串是否以指定后缀结尾（std::string版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const std::string& source, const std::string& sub);

    /**
     * @brief 判断字符串是否以指定后缀结尾（std::wstring版本）
     * 
     * @param source 源字符串
     * @param sub 后缀字符串
     * @return 以指定后缀结尾返回 true，否则返回 false
     */
	bool EndsWith(const std::wstring& source, const std::wstring& sub);

    /**
     * @brief 转换字符串为小写（std::string版本）
     * 
     * 使用 std::transform 和 std::tolower 进行转换。
     * 
     * @param source 源字符串
     * @return 转换后的小写字符串
     */
	std::string ToLower(const std::string& source);

    /**
     * @brief 转换字符串为小写（std::wstring版本）
     * 
     * 使用 std::transform 和 std::tolower 进行转换。
     * 
     * @param source 源字符串
     * @return 转换后的小写字符串
     */
	std::wstring ToLower(const std::wstring& source);

    /**
     * @brief 转换字符串为大写（std::string版本）
     * 
     * 使用 std::transform 和 std::toupper 进行转换。
     * 
     * @param source 源字符串
     * @return 转换后的大写字符串
     */
	std::string ToUpper(const std::string& source);

    /**
     * @brief 转换字符串为大写（std::wstring版本）
     * 
     * 使用 std::transform 和 std::toupper 进行转换。
     * 
     * @param source 源字符串
     * @return 转换后的大写字符串
     */
	std::wstring ToUpper(const std::wstring& source);

    /**
     * @brief 格式化字符串（ANSI版本）
     * 
     * 使用可变参数进行格式化，类似于 sprintf。
     * 优化策略：先尝试写入小缓冲区（1024字节），如果不够再动态分配。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::string Format(const char* format, ...);

    /**
     * @brief 格式化字符串（ANSI版本，va_list）
     * 
     * 与 Format 类似，但接受 va_list 参数。
     * 
     * @param format 格式化字符串
     * @param ap va_list 参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::string VFormat(const char* format, va_list ap);

    /**
     * @brief 格式化字符串（Unicode版本）
     * 
     * 使用可变参数进行格式化，类似于 swprintf。
     * 优化策略：先尝试写入小缓冲区（1024字节），如果不够再动态分配。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::wstring Format(const wchar_t* format, ...);

    /**
     * @brief 格式化字符串（Unicode版本，va_list）
     * 
     * 与 Format 类似，但接受 va_list 参数。
     * 
     * @param format 格式化字符串
     * @param ap va_list 参数
     * @return 格式化后的字符串，失败返回空字符串
     */
	std::wstring VFormat(const wchar_t* format, va_list ap);

    /**
     * @brief 将字节数组转换为十六进制字符串
     * 
     * 每个字节转换为两个十六进制字符（大写）。
     * 
     * @param data 字节数组指针
     * @param length 字节数组长度
     * @return 十六进制字符串
     */
	std::wstring BytesToHexStringW(const unsigned __int8* data, unsigned __int32 length);
}
