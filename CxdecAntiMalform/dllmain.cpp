#include <windows.h>
#include "detour_finder.h"
#include "runtime_hook.h"

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        OutputDebugStringW(L"[AntiMalform] Init");

        // 阶段 1：应用 .detour 载荷
        const uint8_t* entry = FindDetourEntry();
        if (entry) {
            ApplyDetourPatches(entry);
        } else {
            // 放到线程里重试（注入后才会有 .detour 节）
            CreateThread(NULL, 0, [](LPVOID)->DWORD {
                for (int i = 0; i < 50; ++i) {
                    Sleep(200);
                    const uint8_t* e = FindDetourEntry();
                    if (e) { ApplyDetourPatches(e); return 0; }
                }
                return 0;
            }, NULL, 0, NULL);
        }

        // 阶段 2：装运行时挂钩
        if (InstallRuntimeHook()) {
            OutputDebugStringW(L"[AntiMalform] Hook installed");
        } else {
            OutputDebugStringW(L"[AntiMalform] Hook FAILED");
        }
    }
    return TRUE;
}
