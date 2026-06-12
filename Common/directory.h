/**
 * @file directory.h
 * @brief 目录操作工具类
 * 
 * 提供目录存在性检查和目录创建功能。
 */

#pragma once

#include <string>

namespace Directory
{
    /**
     * @brief 检查目录是否存在（ANSI路径）
     * 
     * 使用 GetFileAttributesA 检查目录是否存在。
     * 
     * @param dirPath 目录路径（ANSI）
     * @return 目录存在返回 true，否则返回 false
     */
	bool Exists(const std::string& dirPath);

    /**
     * @brief 检查目录是否存在（Unicode路径）
     * 
     * 使用 GetFileAttributesW 检查目录是否存在。
     * 
     * @param dirPath 目录路径（Unicode）
     * @return 目录存在返回 true，否则返回 false
     */
	bool Exists(const std::wstring& dirPath);

    /**
     * @brief 创建目录（ANSI路径）
     * 
     * 使用 CreateDirectoryA 创建目录，支持递归创建多级目录。
     * 
     * @param dirPath 目录路径（ANSI）
     */
	void Create(const std::string& dirPath);

    /**
     * @brief 创建目录（Unicode路径）
     * 
     * 使用 CreateDirectoryW 创建目录，支持递归创建多级目录。
     * 
     * @param dirPath 目录路径（Unicode）
     */
	void Create(const std::wstring& dirPath);
}
