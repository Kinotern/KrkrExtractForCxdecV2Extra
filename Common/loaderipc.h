/**
 * @file loaderipc.h
 * @brief Loader 进程间通信接口
 * 
 * 提供 Loader 程序与插件之间的进程间通信机制，
 * 通过 Windows 消息机制传递进度和完成通知。
 */

#pragma once

#include <Windows.h>

namespace LoaderIpc
{
    /**
     * @brief Loader 窗口句柄环境变量名
     * 
     * Loader 程序通过此环境变量传递主窗口句柄，
     * 插件可以通过此句柄向 Loader 发送消息。
     */
    static constexpr const wchar_t LoaderWindowHandleEnvName[] = L"CXDEC_LOADER_HWND";

    /**
     * @brief 获取进度消息 ID
     * 
     * 使用 RegisterWindowMessageW 注册一个唯一的窗口消息，
     * 用于向 Loader 发送进度更新。
     * 
     * @return 消息 ID
     */
    inline UINT ProgressMessage()
    {
        static const UINT message = ::RegisterWindowMessageW(L"CXDEC_LOADER_PROGRESS");
        return message;
    }

    /**
     * @brief 获取完成消息 ID
     * 
     * 使用 RegisterWindowMessageW 注册一个唯一的窗口消息，
     * 用于通知 Loader 操作已完成。
     * 
     * @return 消息 ID
     */
    inline UINT CompletedMessage()
    {
        static const UINT message = ::RegisterWindowMessageW(L"CXDEC_LOADER_COMPLETED");
        return message;
    }
}
