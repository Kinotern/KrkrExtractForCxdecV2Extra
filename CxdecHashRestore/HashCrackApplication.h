#pragma once

#include <Windows.h>

namespace Engine
{
    class HashCrackApplication
    {
    public:
        static void Initialize(HMODULE module);
        static void Release();
    };
}
