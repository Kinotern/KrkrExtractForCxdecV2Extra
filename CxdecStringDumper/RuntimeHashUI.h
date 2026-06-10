#pragma once

#include <windows.h>
#include <string>

namespace Engine
{
    class RuntimeHashUI
    {
    public:
        static void Start(HMODULE moduleHandle, const std::wstring& gameDirectory);
    };
}
