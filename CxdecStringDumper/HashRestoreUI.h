#pragma once

#include <Windows.h>
#include <string>

namespace Engine
{
    class HashRestoreUI
    {
    public:
        static void Start(HMODULE moduleHandle, const std::wstring& gameDirectory);
        static void Start(HMODULE moduleHandle, const std::wstring& gameDirectory, const std::wstring& initialSourceDirectory, bool showCrackTools);
    };
}
