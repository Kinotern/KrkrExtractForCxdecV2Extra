#pragma once
#include <windows.h>
#include <cstdint>

// 在目标进程里造一块带 .detour 节的假 PE
// 返回分配到的远端地址，失败返回 NULL
void* CreateDetourSection(
    HANDLE hProcess,
    const void* injectData,
    SIZE_T injectDataSize
);
