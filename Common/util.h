/**
 * @file util.h
 * @brief 实用工具函数集合
 * 
 * 提供多种实用工具函数，包括模块路径获取、错误处理、调试输出等功能。
 */

#pragma once

#include <windows.h>
#include <string>

namespace Util
{
    /**
     * @brief 获取指定模块的完整路径（ANSI版本）
     * 
     * 使用 GetModuleFileNameA 获取模块路径，支持长路径（超过 MAX_PATH）。
     * 
     * @param hModule 模块句柄，NULL 表示当前进程的可执行文件
     * @return 模块完整路径，失败返回空字符串
     */
	std::string GetModulePathA(HMODULE hModule);

    /**
     * @brief 获取指定模块的完整路径（Unicode版本）
     * 
     * 使用 GetModuleFileNameW 获取模块路径，支持长路径（超过 MAX_PATH）。
     * 
     * @param hModule 模块句柄，NULL 表示当前进程的可执行文件
     * @return 模块完整路径，失败返回空字符串
     */
	std::wstring GetModulePathW(HMODULE hModule);

    /**
     * @brief 获取当前应用程序的完整路径（ANSI版本）
     * 
     * 调用 GetModulePathA(NULL) 获取当前进程可执行文件路径。
     * 
     * @return 应用程序完整路径，失败返回空字符串
     */
	std::string GetAppPathA();

    /**
     * @brief 获取当前应用程序的完整路径（Unicode版本）
     * 
     * 调用 GetModulePathW(NULL) 获取当前进程可执行文件路径。
     * 
     * @return 应用程序完整路径，失败返回空字符串
     */
	std::wstring GetAppPathW();

    /**
     * @brief 获取当前应用程序所在目录（ANSI版本）
     * 
     * 获取应用程序路径并移除文件名部分。
     * 
     * @return 应用程序目录路径，失败返回空字符串
     */
	std::string GetAppDirectoryA();

    /**
     * @brief 获取当前应用程序所在目录（Unicode版本）
     * 
     * 获取应用程序路径并移除文件名部分。
     * 
     * @return 应用程序目录路径，失败返回空字符串
     */
	std::wstring GetAppDirectoryW();

    /**
     * @brief 获取最后一个 Win32 错误的描述信息（ANSI版本）
     * 
     * 使用 FormatMessageA 获取错误码对应的描述字符串。
     * 
     * @return 错误描述信息，失败返回空字符串
     */
	std::string GetLastErrorMessageA();

    /**
     * @brief 获取最后一个 Win32 错误的描述信息（Unicode版本）
     * 
     * 使用 FormatMessageW 获取错误码对应的描述字符串。
     * 
     * @return 错误描述信息，失败返回空字符串
     */
	std::wstring GetLastErrorMessageW();

    /**
     * @brief 显示错误消息并终止应用程序（ANSI版本）
     * 
     * 显示消息框提示错误，然后调用 ExitProcess(1) 终止进程。
     * 使用 __declspec(noreturn) 标记表示此函数不会返回。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	__declspec(noreturn) void ThrowError(const char* format, ...);

    /**
     * @brief 显示错误消息并终止应用程序（Unicode版本）
     * 
     * 显示消息框提示错误，然后调用 ExitProcess(1) 终止进程。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	__declspec(noreturn) void ThrowError(const wchar_t* format, ...);

    /**
     * @brief 向调试器发送消息（ANSI版本）
     * 
     * 使用 OutputDebugStringA 将消息发送到调试器。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	void WriteDebugMessage(const char* format, ...);

    /**
     * @brief 向调试器发送消息（Unicode版本）
     * 
     * 使用 OutputDebugStringW 将消息发送到调试器。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	void WriteDebugMessage(const wchar_t* format, ...);

    /**
     * @brief 显示文件夹选择对话框（ANSI版本）
     * 
     * 使用 SHBrowseForFolderA 显示标准的文件夹选择对话框。
     * 
     * @param title 对话框标题
     * @return 用户选择的文件夹路径，取消选择返回空字符串
     */
	std::string OpenFolderDialog(const std::string& title);

    /**
     * @brief 显示文件夹选择对话框（Unicode版本）
     * 
     * 使用 SHBrowseForFolderW 显示标准的文件夹选择对话框。
     * 
     * @param title 对话框标题
     * @return 用户选择的文件夹路径，取消选择返回空字符串
     */
	std::wstring OpenFolderDialog(const std::wstring& title);
}
