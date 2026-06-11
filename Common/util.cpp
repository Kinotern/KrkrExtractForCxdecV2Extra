﻿﻿﻿/**
 * @file util.cpp
 * @brief 实用工具函数实现
 * 
 * 提供多种实用工具函数，包括模块路径获取、错误处理、调试输出等功能。
 */

#include <windows.h>
#include <shlobj.h>
#include "stringhelper.h"

namespace Util
{
    /**
     * @brief 获取指定模块的完整路径（ANSI版本）
     * 
     * 使用 GetModuleFileNameA 获取模块路径。
     * 优化策略：先尝试使用 MAX_PATH 大小的缓冲区，如果不够则逐步扩大缓冲区。
     * 
     * @param hModule 模块句柄，NULL 表示当前进程的可执行文件
     * @return 模块完整路径，失败返回空字符串
     */
    std::string GetModulePathA(HMODULE hModule)
    {
        DWORD dwBufferSize = MAX_PATH;

        std::string output;

        while (dwBufferSize < USHRT_MAX)
        {
            output.resize(dwBufferSize);

            SetLastError(ERROR_SUCCESS);
            DWORD nSize = GetModuleFileNameA(hModule, const_cast<std::string::pointer>(output.data()), dwBufferSize);
            DWORD dwErrorCode = GetLastError();

            if (nSize == 0)
            {
                return std::string();
            }

            if (nSize < dwBufferSize)
            {
                return output.substr(0, nSize);
            }

            if (dwErrorCode == ERROR_SUCCESS || dwErrorCode == ERROR_INSUFFICIENT_BUFFER || nSize == dwBufferSize)
            {
                dwBufferSize *= 2;
                continue;
            }

            return std::string();
        }

        return std::string();
    }

    /**
     * @brief 获取指定模块的完整路径（Unicode版本）
     * 
     * 与 ANSI 版本逻辑相同，仅使用宽字符版本的 API。
     * 
     * @param hModule 模块句柄，NULL 表示当前进程的可执行文件
     * @return 模块完整路径，失败返回空字符串
     */
    std::wstring GetModulePathW(HMODULE hModule)
    {
        DWORD dwBufferSize = MAX_PATH;

        std::wstring output;

        while (dwBufferSize < USHRT_MAX)
        {
            output.resize(dwBufferSize);

            SetLastError(ERROR_SUCCESS);
            DWORD nSize = GetModuleFileNameW(hModule, const_cast<std::wstring::pointer>(output.data()), dwBufferSize);
            DWORD dwErrorCode = GetLastError();

            if (nSize == 0)
            {
                return std::wstring();
            }

            if (nSize < dwBufferSize)
            {
                return output.substr(0, nSize);
            }

            if (dwErrorCode == ERROR_SUCCESS || dwErrorCode == ERROR_INSUFFICIENT_BUFFER || nSize == dwBufferSize)
            {
                dwBufferSize *= 2;
                continue;
            }

            return std::wstring();
        }

        return std::wstring();
    }

    /**
     * @brief 获取当前应用程序的完整路径（ANSI版本）
     * 
     * @return 应用程序完整路径，失败返回空字符串
     */
    std::string GetAppPathA()
    {
        return GetModulePathA(GetModuleHandleW(NULL));
    }

    /**
     * @brief 获取当前应用程序的完整路径（Unicode版本）
     * 
     * @return 应用程序完整路径，失败返回空字符串
     */
    std::wstring GetAppPathW()
    {
        return GetModulePathW(GetModuleHandleW(NULL));
    }

    /**
     * @brief 获取当前应用程序所在目录（ANSI版本）
     * 
     * 查找路径中最后一个反斜杠，返回其之前的部分。
     * 
     * @return 应用程序目录路径，失败返回空字符串
     */
    std::string GetAppDirectoryA()
    {
        std::string path = GetAppPathA();

        size_t pos = path.find_last_of('\\');

        if (pos != std::string::npos && pos > 0)
        {
            return path.substr(0, pos);
        }

        return path;
    }

    /**
     * @brief 获取当前应用程序所在目录（Unicode版本）
     * 
     * @return 应用程序目录路径，失败返回空字符串
     */
	std::wstring GetAppDirectoryW()
	{
		std::wstring path = GetAppPathW();

		size_t pos = path.find_last_of(L'\\');

		if (pos != std::wstring::npos && pos > 0)
		{
			return path.substr(0, pos);
		}

		return path;
	}

    /**
     * @brief 获取最后一个 Win32 错误的描述信息（ANSI版本）
     * 
     * 使用 FormatMessageA 获取错误码对应的描述字符串。
     * 注意：返回的字符串可能包含换行符和回车符。
     * 
     * @return 错误描述信息，失败返回空字符串
     */
    std::string GetLastErrorMessageA()
    {
        DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
        DWORD dwErrorCode = GetLastError();
        DWORD dwLanguageId = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        LPSTR pBuffer = NULL;

        if (FormatMessageA(dwFlags, NULL, dwErrorCode, dwLanguageId, (LPSTR)&pBuffer, 0, NULL) == 0)
        {
            return std::string();
        }

        std::string message(pBuffer);

        LocalFree(pBuffer);

        return message;
    }

    /**
     * @brief 获取最后一个 Win32 错误的描述信息（Unicode版本）
     * 
     * @return 错误描述信息，失败返回空字符串
     */
    std::wstring GetLastErrorMessageW()
    {
        DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
        DWORD dwErrorCode = GetLastError();
        DWORD dwLanguageId = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        PWSTR pBuffer = NULL;

        if (FormatMessageW(dwFlags, NULL, dwErrorCode, dwLanguageId, (PWSTR)&pBuffer, 0, NULL) == 0)
        {
            return std::wstring();
        }

        std::wstring message(pBuffer);

        LocalFree(pBuffer);

        return message;
    }

    /**
     * @brief 显示错误消息并终止应用程序（ANSI版本）
     * 
     * 格式化错误消息，显示消息框，然后终止进程。
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    __declspec(noreturn) void ThrowError(const char* format, ...)
    {
        va_list ap;

        va_start(ap, format);
        auto message = StringHelper::VFormat(format, ap);
        va_end(ap);

        MessageBoxA(NULL, message.c_str(), "Fatal Error", MB_ICONERROR | MB_OK);
        ExitProcess(1);
    }

    /**
     * @brief 显示错误消息并终止应用程序（Unicode版本）
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    __declspec(noreturn) void ThrowError(const wchar_t* format, ...)
    {
        va_list ap;

        va_start(ap, format);
        auto message = StringHelper::VFormat(format, ap);
        va_end(ap);

        MessageBoxW(NULL, message.c_str(), L"Fatal Error", MB_ICONERROR | MB_OK);
        ExitProcess(1);
    }

    /**
     * @brief 向调试器发送消息（ANSI版本）
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	void WriteDebugMessage(const char* format, ...)
	{
		va_list ap;

		va_start(ap, format);
		auto message = StringHelper::VFormat(format, ap);
		va_end(ap);

		OutputDebugStringA(message.c_str());
	}

    /**
     * @brief 向调试器发送消息（Unicode版本）
     * 
     * @param format 格式化字符串
     * @param ... 可变参数
     */
	void WriteDebugMessage(const wchar_t* format, ...)
	{
		va_list ap;

		va_start(ap, format);
		auto message = StringHelper::VFormat(format, ap);
		va_end(ap);

		OutputDebugStringW(message.c_str());
	}

    /**
     * @brief 显示文件夹选择对话框（ANSI版本）
     * 
     * 使用 SHBrowseForFolderA 显示标准的文件夹选择对话框。
     * 
     * @param title 对话框标题
     * @return 用户选择的文件夹路径，取消选择返回空字符串
     */
    std::string OpenFolderDialog(const std::string& title)
    {
        char buf[MAX_PATH]{};
        BROWSEINFOA bi{};

        bi.hwndOwner = GetActiveWindow();
        bi.pidlRoot = NULL;
        bi.pszDisplayName = buf;
        bi.lpszTitle = title.c_str();
        bi.ulFlags = BIF_NEWDIALOGSTYLE;
        bi.lpfn = NULL;
        bi.lParam = NULL;
        bi.iImage = 0;

        LPITEMIDLIST idl = SHBrowseForFolderA(&bi);

        if (idl == NULL)
        {
            return std::string();
        }

        if (SHGetPathFromIDListA(idl, buf) == FALSE)
        {
            return std::string();
        }

        return std::string(buf);
    }

    /**
     * @brief 显示文件夹选择对话框（Unicode版本）
     * 
     * @param title 对话框标题
     * @return 用户选择的文件夹路径，取消选择返回空字符串
     */
    std::wstring OpenFolderDialog(const std::wstring& title)
    {
        WCHAR buf[MAX_PATH]{};
        BROWSEINFOW bi{};

        bi.hwndOwner = GetActiveWindow();
        bi.pidlRoot = NULL;
        bi.pszDisplayName = buf;
        bi.lpszTitle = title.c_str();
        bi.ulFlags = BIF_NEWDIALOGSTYLE;
        bi.lpfn = NULL;
        bi.lParam = NULL;
        bi.iImage = 0;

        LPITEMIDLIST idl = SHBrowseForFolderW(&bi);

        if (idl == NULL)
        {
            return std::wstring();
        }

        if (SHGetPathFromIDListW(idl, buf) == FALSE)
        {
            return std::wstring();
        }

        return std::wstring(buf);
    }
}
