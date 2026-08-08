#pragma once
#include <windows.h>
#include <cstdint>

// Allocate a fake PE image with a .detour section in the remote process.
// Returns a pointer to the allocated remote memory, or NULL on failure.
void* CreateDetourSection(
    HANDLE hProcess,
    const void* injectData,
    SIZE_T injectDataSize
);
