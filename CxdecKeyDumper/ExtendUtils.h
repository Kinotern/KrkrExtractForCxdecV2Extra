#pragma once

#include <windows.h>
#include "detours.h"

namespace Engine
{
    namespace HookUtils
    {
        class InlineHook
        {
        public:
            InlineHook() = delete;
            InlineHook(const InlineHook&) = delete;
            InlineHook(InlineHook&&) = delete;
            InlineHook& operator=(const InlineHook&) = delete;
            InlineHook& operator=(InlineHook&&) = delete;
            ~InlineHook() = delete;

            template<class T>
            static void Hook(T& originalFunction, T detourFunction)
            {
                DetourUpdateThread(GetCurrentThread());
                DetourTransactionBegin();
                DetourAttach(&(PVOID&)originalFunction, (PVOID&)detourFunction);
                DetourTransactionCommit();
            }

            template<class T>
            static void UnHook(T& originalFunction, T detourFunction)
            {
                DetourUpdateThread(GetCurrentThread());
                DetourTransactionBegin();
                DetourDetach(&(PVOID&)originalFunction, (PVOID&)detourFunction);
                DetourTransactionCommit();
            }
        };
    }
}
