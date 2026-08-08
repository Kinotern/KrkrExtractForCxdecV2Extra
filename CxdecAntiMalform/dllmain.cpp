#include <windows.h>
#include "detour_finder.h"
#include "runtime_hook.h"

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        OutputDebugStringW(L"[AntiMalform] Init");

        // Phase 1: .detour patches
        const uint8_t* entry = FindDetourEntry();
        if (entry) {
            ApplyDetourPatches(entry);
        } else {
            // Retry in thread (Loader creates .detour section after injection)
            CreateThread(NULL, 0, [](LPVOID)->DWORD {
                for (int i = 0; i < 50; ++i) {
                    Sleep(200);
                    const uint8_t* e = FindDetourEntry();
                    if (e) { ApplyDetourPatches(e); return 0; }
                }
                return 0;
            }, NULL, 0, NULL);
        }

        // Phase 2: Install runtime hook
        if (InstallRuntimeHook()) {
            OutputDebugStringW(L"[AntiMalform] Hook installed");
        } else {
            OutputDebugStringW(L"[AntiMalform] Hook FAILED");
        }
    }
    return TRUE;
}
