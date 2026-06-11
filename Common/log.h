﻿﻿﻿/**
 * @file log.h
 * @brief 日志工具类
 * 
 * 提供线程安全的日志记录功能，支持多种编码格式输出，
 * 包括 ANSI、Unicode 和 UTF-8。
 */

#pragma once

#include <Windows.h>
#include <cstdio>

namespace Log
{
    /**
     * @brief 日志记录器类
     * 
     * 提供线程安全的日志写入功能，支持多种输出格式：
     * - ANSI 编码输出（带时间戳）
     * - Unicode 编码输出（直接写入）
     * - UTF-8 编码输出（带时间戳）
     * 
     * 使用 CRITICAL_SECTION 保证多线程环境下的安全性。
     */
	class Logger
	{
	public:
        /**
         * @brief 默认构造函数
         * 
         * 初始化临界区，日志文件未打开。
         */
		Logger();

        /**
         * @brief 构造函数（带文件名）
         * 
         * 初始化临界区并打开指定的日志文件。
         * 
         * @param lpFileName 日志文件路径
         */
		Logger(const wchar_t* lpFileName);

        /**
         * @brief 析构函数
         * 
         * 关闭日志文件并释放临界区。
         */
		~Logger();

        // 禁用拷贝构造和赋值
		Logger(const Logger&) = delete;
		Logger& operator=(const Logger&) = delete;

        /**
         * @brief 打开日志文件
         * 
         * 以追加模式打开日志文件，共享模式为拒绝写入（_SH_DENYWR）。
         * 
         * @param lpFileName 日志文件路径
         */
		void Open(const wchar_t* lpFileName);

        /**
         * @brief 关闭日志文件
         * 
         * 刷新缓冲区并关闭文件句柄。
         */
		void Close();

        /**
         * @brief 刷新缓冲区
         * 
         * 将缓冲区内容强制写入磁盘。
         */
		void Flush();

        /**
         * @brief 写入 ANSI 格式日志（指定代码页）
         * 
         * 将指定代码页的 ANSI 字符串转换为 Unicode，再转换为 UTF-8 写入。
         * 
         * @param iCodePage 代码页（如 CP_ACP, CP_UTF8）
         * @param lpFormat 格式化字符串
         * @param ... 可变参数
         */
		void WriteAnsi(int iCodePage, const char* lpFormat, ...);

        /**
         * @brief 写入 ANSI 格式日志（带时间戳）
         * 
         * 同 WriteAnsi，但在日志前添加时间戳前缀。
         * 
         * @param iCodePage 代码页
         * @param lpFormat 格式化字符串
         * @param ... 可变参数
         */
		void WriteLineAnsi(int iCodePage, const char* lpFormat, ...);

        /**
         * @brief 写入 Unicode 格式日志
         * 
         * 将 Unicode 字符串转换为 UTF-8 写入日志文件。
         * 
         * @param lpFormat 格式化字符串
         * @param ... 可变参数
         */
		void Write(const wchar_t* lpFormat, ...);

        /**
         * @brief 写入 Unicode 格式日志（带时间戳）
         * 
         * 同 Write，但在日志前添加时间戳前缀。
         * 
         * @param lpFormat 格式化字符串
         * @param ... 可变参数
         */
		void WriteLine(const wchar_t* lpFormat, ...);

        /**
         * @brief 直接写入 Unicode 原始数据
         * 
         * 不进行编码转换，直接写入 UTF-16LE 编码的数据。
         * 
         * @param lpFormat 格式化字符串
         * @param ... 可变参数
         */
		void WriteUnicode(const wchar_t* lpFormat, ...);

        /**
         * @brief 写入二进制数据
         * 
         * 直接将二进制数据写入日志文件。
         * 
         * @param data 数据指针
         * @param size 数据大小（字节）
         */
		void WriteData(void* data, unsigned int size);

	private:
		FILE* m_pOutput;           ///< 日志文件句柄
		CRITICAL_SECTION m_Lock;   ///< 线程安全锁
	};
}
