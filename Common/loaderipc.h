#pragma once

#include <Windows.h>

namespace LoaderIpc
{
    static constexpr const wchar_t LoaderWindowHandleEnvName[] = L"CXDEC_LOADER_HWND";

    inline UINT ProgressMessage()
    {
        static const UINT message = ::RegisterWindowMessageW(L"CXDEC_LOADER_PROGRESS");
        return message;
    }

    inline UINT CompletedMessage()
    {
        static const UINT message = ::RegisterWindowMessageW(L"CXDEC_LOADER_COMPLETED");
        return message;
    }
}
