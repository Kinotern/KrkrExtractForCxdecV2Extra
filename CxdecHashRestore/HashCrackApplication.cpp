#include "HashCrackApplication.h"

#include "HashCore.h"
#include "ExtendUtils.h"
#include "path.h"
#include "util.h"

namespace Engine
{
    using tTVPV2LinkProc = HRESULT(__stdcall*)(iTVPFunctionExporter*);

    namespace
    {
        constexpr wchar_t HashCrackOutputDirectoryEnvName[] = L"CXDEC_HASH_CRACK_OUTPUT_DIR";
        HashCore* g_HashCore = nullptr;
        bool g_TvpInitialized = false;
        tTVPV2LinkProc g_V2Link = nullptr;
        auto g_GetProcAddressFunction = ::GetProcAddress;

        HRESULT __stdcall HookV2Link(iTVPFunctionExporter* exporter)
        {
            HRESULT result = g_V2Link(exporter);
            HookUtils::InlineHook::UnHook(g_V2Link, HookV2Link);
            g_V2Link = nullptr;
            g_TvpInitialized = TVPInitImportStub(exporter);
            return result;
        }

        FARPROC WINAPI HookGetProcAddress(HMODULE module, LPCSTR procName)
        {
            FARPROC result = g_GetProcAddressFunction(module, procName);
            if (!result || HIWORD(procName) == 0 || strcmp(procName, "V2Link") != 0)
            {
                return result;
            }

            PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS((ULONG_PTR)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
            DWORD optionalHeaderSize = ntHeader->FileHeader.SizeOfOptionalHeader;
            PIMAGE_SECTION_HEADER codeSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)ntHeader + sizeof(ntHeader->Signature) + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize);
            ULONG_PTR codeStartVa = (ULONG_PTR)module + codeSectionHeader->VirtualAddress;
            DWORD codeSize = codeSectionHeader->SizeOfRawData;

            if (!g_TvpInitialized)
            {
                g_V2Link = (tTVPV2LinkProc)result;
                HookUtils::InlineHook::Hook(g_V2Link, HookV2Link);
            }

            if (g_HashCore && !g_HashCore->IsInitialized())
            {
                g_HashCore->Initialize((PVOID)codeStartVa, codeSize);
            }

            if (g_HashCore && g_HashCore->IsInitialized())
            {
                HookUtils::InlineHook::UnHook(g_GetProcAddressFunction, HookGetProcAddress);
            }
            return result;
        }

        std::wstring GetEnvironmentString(const wchar_t* name)
        {
            DWORD length = ::GetEnvironmentVariableW(name, nullptr, 0u);
            if (length == 0u)
            {
                return std::wstring();
            }

            std::wstring value(length, L'\0');
            DWORD copied = ::GetEnvironmentVariableW(name, value.data(), length);
            if (copied == 0u)
            {
                return std::wstring();
            }
            value.resize(copied);
            return value;
        }
    }

    void HashCrackApplication::Initialize(HMODULE module)
    {
        UNREFERENCED_PARAMETER(module);

        std::wstring gameDirectory = Path::GetDirectoryName(Util::GetModulePathW(::GetModuleHandleW(nullptr)));
        g_HashCore = HashCore::GetInstance();
        std::wstring hashOutputDirectory = GetEnvironmentString(HashCrackOutputDirectoryEnvName);
        if (hashOutputDirectory.empty())
        {
            g_HashCore->SetOutputDirectory(gameDirectory);
        }
        else
        {
            g_HashCore->SetHashOutputDirectory(hashOutputDirectory);
        }
        HookUtils::InlineHook::Hook(g_GetProcAddressFunction, HookGetProcAddress);
    }

    void HashCrackApplication::Release()
    {
        if (g_HashCore)
        {
            HashCore::Release();
            g_HashCore = nullptr;
        }
    }
}
