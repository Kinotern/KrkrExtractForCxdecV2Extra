﻿/**
 * @file file.h
 * @brief 文件操作工具类
 * 
 * 提供基础的文件读写操作封装，支持 ANSI 和 Unicode 路径，
 * 自动处理 UTF-8 BOM 标记。
 */

#pragma once

#include <string>

namespace File
{
    /**
     * @brief 读取文本文件全部内容（ANSI路径）
     * 
     * 自动检测并跳过 UTF-8 BOM（0xEF 0xBB 0xBF），返回纯文本内容。
     * 文件打开失败或读取异常时返回空字符串。
     * 
     * @param path 文件路径（ANSI）
     * @return 文件内容字符串，失败时返回空字符串
     */
	std::string ReadAllText(const std::string& path);

    /**
     * @brief 读取文本文件全部内容（Unicode路径）
     * 
     * 自动检测并跳过 UTF-8 BOM（0xEF 0xBB 0xBF），返回纯文本内容。
     * 文件打开失败或读取异常时返回空字符串。
     * 
     * @param path 文件路径（Unicode）
     * @return 文件内容字符串，失败时返回空字符串
     */
	std::string ReadAllText(const std::wstring& path);

    /**
     * @brief 写入字节数据到文件（ANSI路径）
     * 
     * 以二进制模式写入文件，写入前会清空原文件内容。
     * 
     * @param path 文件路径（ANSI）
     * @param buffer 数据缓冲区指针
     * @param size 数据大小（字节）
     * @return 写入成功返回 true，失败返回 false
     */
	bool WriteAllBytes(const std::string& path, const void* buffer, size_t size);

    /**
     * @brief 写入字节数据到文件（Unicode路径）
     * 
     * 以二进制模式写入文件，写入前会清空原文件内容。
     * 
     * @param path 文件路径（Unicode）
     * @param buffer 数据缓冲区指针
     * @param size 数据大小（字节）
     * @return 写入成功返回 true，失败返回 false
     */
	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size);

    /**
     * @brief 删除文件（ANSI路径）
     * 
     * 删除指定路径的文件，忽略删除失败（如文件不存在）。
     * 
     * @param path 文件路径（ANSI）
     */
	void Delete(const std::string& path);

    /**
     * @brief 删除文件（Unicode路径）
     * 
     * 删除指定路径的文件，忽略删除失败（如文件不存在）。
     * 
     * @param path 文件路径（Unicode）
     */
	void Delete(const std::wstring& path);
}
