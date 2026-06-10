#include <windows.h>

#include "HashCrackApplication.h"
#include "HashRestoreUI.h"
#include "path.h"
#include "util.h"

namespace
{
    bool IsRestoreUiSuppressed()
    {
        wchar_t value[16]{};
        DWORD length = ::GetEnvironmentVariableW(L"CXDEC_HASH_CRACK_SUPPRESS_RESTORE_UI", value, _countof(value));
        return length > 0 && value[0] == L'1';
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        ::DisableThreadLibraryCalls(module);
        ::SetEnvironmentVariableW(L"CXDEC_HASH_CRACK_MODE", L"1");
        Engine::HashCrackApplication::Initialize(module);
        if (!IsRestoreUiSuppressed())
        {
            std::wstring gameDirectory = Path::GetDirectoryName(Util::GetModulePathW(::GetModuleHandleW(nullptr)));
            Engine::HashRestoreUI::Start(module, gameDirectory);
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        Engine::HashCrackApplication::Release();
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void Dummy() {}
