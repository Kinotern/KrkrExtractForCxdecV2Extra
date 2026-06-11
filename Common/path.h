﻿/**
 * @file path.h
 * @brief 路径操作工具类
 * 
 * 提供跨平台路径处理功能，支持 ANSI 和 Unicode 路径，
 * 处理 Windows 和 Unix 风格路径分隔符。
 */

#pragma once

#include <string>

namespace Path
{
    /**
     * @brief 获取路径中的文件名（ANSI路径）
     * 
     * 支持 '\\' 和 '/' 作为路径分隔符。
     * 
     * @param path 文件路径（ANSI）
     * @return 文件名（不含路径）
     */
	std::string GetFileName(const std::string& path);

    /**
     * @brief 获取路径中的文件名（Unicode路径）
     * 
     * 支持 '\\' 和 '/' 作为路径分隔符。
     * 
     * @param path 文件路径（Unicode）
     * @return 文件名（不含路径）
     */
	std::wstring GetFileName(const std::wstring& path);

    /**
     * @brief 获取路径中的文件名（不含扩展名，ANSI路径）
     * 
     * 获取最后一个路径分隔符后的部分，并移除文件扩展名。
     * 
     * @param path 文件路径（ANSI）
     * @return 文件名（不含路径和扩展名）
     */
	std::string GetFileNameWithoutExtension(const std::string& path);

    /**
     * @brief 获取路径中的文件名（不含扩展名，Unicode路径）
     * 
     * 获取最后一个路径分隔符后的部分，并移除文件扩展名。
     * 
     * @param path 文件路径（Unicode）
     * @return 文件名（不含路径和扩展名）
     */
	std::wstring GetFileNameWithoutExtension(const std::wstring& path);

    /**
     * @brief 获取路径中的目录名（ANSI路径）
     * 
     * 返回最后一个路径分隔符之前的部分。
     * 
     * @param path 文件路径（ANSI）
     * @return 目录路径（不含文件名），失败返回空字符串
     */
	std::string GetDirectoryName(const std::string& path);

    /**
     * @brief 获取路径中的目录名（Unicode路径）
     * 
     * 返回最后一个路径分隔符之前的部分。
     * 
     * @param path 文件路径（Unicode）
     * @return 目录路径（不含文件名），失败返回空字符串
     */
	std::wstring GetDirectoryName(const std::wstring& path);

    /**
     * @brief 获取文件扩展名（ANSI路径）
     * 
     * 返回最后一个 '.' 之后的部分，包含 '.' 字符。
     * 如果文件名以 '.' 开头（如 .gitignore），则返回空字符串。
     * 
     * @param path 文件路径（ANSI）
     * @return 文件扩展名（包含 '.'），无扩展名返回空字符串
     */
	std::string GetExtension(const std::string& path);

    /**
     * @brief 获取文件扩展名（Unicode路径）
     * 
     * 返回最后一个 '.' 之后的部分，包含 '.' 字符。
     * 如果文件名以 '.' 开头（如 .gitignore），则返回空字符串。
     * 
     * @param path 文件路径（Unicode）
     * @return 文件扩展名（包含 '.'），无扩展名返回空字符串
     */
	std::wstring GetExtension(const std::wstring& path);

    /**
     * @brief 更改文件扩展名（ANSI路径）
     * 
     * 如果新扩展名不以 '.' 开头，会自动添加。
     * 如果新扩展名为空，则移除原扩展名。
     * 
     * @param path 文件路径（ANSI）
     * @param ext 新扩展名（可带或不带 '.'）
     * @return 修改后的路径
     */
	std::string ChangeExtension(const std::string& path, const std::string& ext);

    /**
     * @brief 更改文件扩展名（Unicode路径）
     * 
     * 如果新扩展名不以 '.' 开头，会自动添加。
     * 如果新扩展名为空，则移除原扩展名。
     * 
     * @param path 文件路径（Unicode）
     * @param ext 新扩展名（可带或不带 '.'）
     * @return 修改后的路径
     */
	std::wstring ChangeExtension(const std::wstring& path, const std::wstring& ext);

    /**
     * @brief 获取文件完整路径（ANSI路径）
     * 
     * 使用 Windows API GetFullPathNameA 将相对路径转换为绝对路径。
     * 支持长路径（超过 MAX_PATH）。
     * 
     * @param path 文件路径（ANSI）
     * @return 完整的绝对路径，失败返回空字符串
     */
	std::string GetFullPath(const std::string& path);

    /**
     * @brief 获取文件完整路径（Unicode路径）
     * 
     * 使用 Windows API GetFullPathNameW 将相对路径转换为绝对路径。
     * 支持长路径（超过 MAX_PATH）。
     * 
     * @param path 文件路径（Unicode）
     * @return 完整的绝对路径，失败返回空字符串
     */
	std::wstring GetFullPath(const std::wstring& path);

    /**
     * @brief 组合路径（ANSI路径）
     * 
     * 将目录路径和文件名组合成完整路径。
     * 如果目录路径末尾没有分隔符，会自动添加 '\\'。
     * 
     * @param dir 目录路径（ANSI）
     * @param fileName 文件名（ANSI）
     * @return 组合后的完整路径
     */
	std::string Combine(const std::string& dir, const std::string& fileName);

    /**
     * @brief 组合路径（Unicode路径）
     * 
     * 将目录路径和文件名组合成完整路径。
     * 如果目录路径末尾没有分隔符，会自动添加 '\\'。
     * 
     * @param dir 目录路径（Unicode）
     * @param fileName 文件名（Unicode）
     * @return 组合后的完整路径
     */
	std::wstring Combine(const std::wstring& dir, const std::wstring& fileName);

    /**
     * @brief 检查文件是否存在（ANSI路径）
     * 
     * 使用 GetFileAttributesA 检查文件是否存在。
     * 返回 false 如果文件不存在或路径指向目录。
     * 
     * @param filePath 文件路径（ANSI）
     * @return 文件存在返回 true，否则返回 false
     */
	bool Exists(const std::string& filePath);

    /**
     * @brief 检查文件是否存在（Unicode路径）
     * 
     * 使用 GetFileAttributesW 检查文件是否存在。
     * 返回 false 如果文件不存在或路径指向目录。
     * 
     * @param filePath 文件路径（Unicode）
     * @return 文件存在返回 true，否则返回 false
     */
	bool Exists(const std::wstring& filePath);
}
