#include "Application.h"
#include "path.h"
#include "util.h"
#include "ExtendUtils.h"

namespace Engine
{
    static Application* g_Instance = nullptr;

    tTVPV2LinkProc g_V2Link = nullptr;
    HRESULT __stdcall HookV2Link(iTVPFunctionExporter* exporter)
    {
        HRESULT result = g_V2Link(exporter);
        HookUtils::InlineHook::UnHook(g_V2Link, HookV2Link);
        g_V2Link = nullptr;

        Application::GetInstance()->InitializeTVPEngine(exporter);
        return result;
    }

    auto g_GetProcAddressFunction = ::GetProcAddress;
    FARPROC WINAPI HookGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    {
        FARPROC result = g_GetProcAddressFunction(hModule, lpProcName);
        if (!result)
        {
            return result;
        }

        if (HIWORD(lpProcName) == 0)
        {
            return result;
        }

        if (strcmp(lpProcName, "V2Link") != 0)
        {
            return result;
        }

        PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
        DWORD optionalHeaderSize = ntHeader->FileHeader.SizeOfOptionalHeader;
        PIMAGE_SECTION_HEADER codeSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)ntHeader + sizeof(ntHeader->Signature) + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize);

        DWORD codeStartRva = codeSectionHeader->VirtualAddress;
        DWORD codeSize = codeSectionHeader->SizeOfRawData;
        ULONG_PTR codeStartVa = (ULONG_PTR)hModule + codeStartRva;

        Application* app = Application::GetInstance();
        if (!app->IsTVPEngineInitialize())
        {
            g_V2Link = (tTVPV2LinkProc)result;
            HookUtils::InlineHook::Hook(g_V2Link, HookV2Link);
        }

        KeyCore* dumper = app->GetKeyDumper();
        if (!dumper->IsInitialized())
        {
            dumper->Initialize(hModule, (PVOID)codeStartVa, codeSize);
        }

        if (dumper->IsInitialized())
        {
            HookUtils::InlineHook::UnHook(g_GetProcAddressFunction, HookGetProcAddress);
        }

        return result;
    }

    Application::Application()
    {
        this->mCurrentDirectoryPath = Path::GetDirectoryName(Util::GetModulePathW(::GetModuleHandleW(nullptr)));
        this->mTVPExporterInitialized = false;
        this->mKeyDumper = new KeyCore();
        this->mKeyDumper->SetOutputDirectory(this->mCurrentDirectoryPath);
    }

    Application::~Application()
    {
        if (this->mKeyDumper)
        {
            delete this->mKeyDumper;
            this->mKeyDumper = nullptr;
        }
    }

    void Application::InitializeModule(HMODULE hModule)
    {
        this->mModuleDirectoryPath = Path::GetDirectoryName(Util::GetModulePathW(hModule));
    }

    void Application::InitializeTVPEngine(iTVPFunctionExporter* exporter)
    {
        this->mTVPExporterInitialized = TVPInitImportStub(exporter);
        TVPSetCommandLine(L"-debugwin", L"yes");
    }

    bool Application::IsTVPEngineInitialize()
    {
        return this->mTVPExporterInitialized;
    }

    KeyCore* Application::GetKeyDumper()
    {
        return this->mKeyDumper;
    }

    Application* Application::GetInstance()
    {
        return g_Instance;
    }

    void Application::Initialize(HMODULE hModule)
    {
        g_Instance = new Application();
        g_Instance->InitializeModule(hModule);
        HookUtils::InlineHook::Hook(g_GetProcAddressFunction, HookGetProcAddress);
    }

    void Application::Release()
    {
        if (g_Instance)
        {
            delete g_Instance;
            g_Instance = nullptr;
        }
    }
}
