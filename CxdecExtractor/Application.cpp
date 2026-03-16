#include "Application.h"
#include "path.h"
#include "util.h"
#include "ExtendUtils.h"

namespace Engine
{
    /// <summary>
    /// DLL 生命周期内的唯一应用对象，统一持有解包器和 TVP 初始化状态。
    /// </summary>
    static Application* g_Instance = nullptr;

    // V2Link 是 Krkr/TVP 插件的初始化入口。这里先执行原函数，再补做我们的初始化，
    // 可以确保 tp_stub 依赖的导出表已经准备好。
    tTVPV2LinkProc g_V2Link = nullptr;
    HRESULT __stdcall HookV2Link(iTVPFunctionExporter* exporter)
    {
        HRESULT result = g_V2Link(exporter);
        HookUtils::InlineHook::UnHook(g_V2Link, HookV2Link);
        g_V2Link = nullptr;

        //初始化插件
        Application::GetInstance()->InitializeTVPEngine(exporter);

        return result;
    }

    // 注入后的 DLL 起点很早，此时还拿不到 TVP 导出表。
    // 先拦截 GetProcAddress，等宿主真正解析到 V2Link 时再完成初始化。
    auto g_GetProcAddressFunction = ::GetProcAddress;
    FARPROC WINAPI HookGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    {
        FARPROC result = g_GetProcAddressFunction(hModule, lpProcName);
        if (result)
        {
            // 忽略序号导出
            if (HIWORD(lpProcName) != 0)
            {
                if (strcmp(lpProcName, "V2Link") == 0)
                {
                    // V2Link 所在模块就是目标插件，后续特征码也只在其首个代码节里查找。
                    PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
                    DWORD optionalHeaderSize = ntHeader->FileHeader.SizeOfOptionalHeader;
                    PIMAGE_SECTION_HEADER codeSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)ntHeader + sizeof(ntHeader->Signature) + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize);

                    DWORD codeStartRva = codeSectionHeader->VirtualAddress;
                    DWORD codeSize = codeSectionHeader->SizeOfRawData;
                    ULONG_PTR codeStartVa = (ULONG_PTR)hModule + codeStartRva;

                    // 先补齐 TVP 导出绑定，再扫描解包所需的内部接口。
                    Application* app = Application::GetInstance();
                    if (!app->IsTVPEngineInitialize())
                    {
                        g_V2Link = (tTVPV2LinkProc)result;
                        HookUtils::InlineHook::Hook(g_V2Link, HookV2Link);
                    }

                    //解包接口
                    ExtractCore* extractor = app->GetExtractor();
                    if (!extractor->IsInitialized())
                    {
                        extractor->Initialize((PVOID)codeStartVa, codeSize);
                    }

                    // 两套入口都拿到后就不再拦截 GetProcAddress，避免继续影响宿主行为。
                    if (extractor->IsInitialized())
                    {
                        HookUtils::InlineHook::UnHook(g_GetProcAddressFunction, HookGetProcAddress);
                    }
                }
            }
        }
        return result;
    }


    //**********Application***********//
    Application::Application()
    {
        this->mCurrentDirectoryPath = Path::GetDirectoryName(Util::GetModulePathW(::GetModuleHandleW(NULL)));
        this->mTVPExporterInitialized = false;
        this->mExtractor = new ExtractCore();

        // 默认输出放到游戏目录，方便直接随游戏部署和查找结果。
        this->mExtractor->SetOutputDirectory(this->mCurrentDirectoryPath);
    }

    Application::~Application()
    {
        if (this->mExtractor)
        {
            delete this->mExtractor;
            this->mExtractor = nullptr;
        }
    }

    void Application::InitializeModule(HMODULE hModule)
    {
        this->mModuleDirectoryPath = Path::GetDirectoryName(Util::GetModulePathW(hModule));

        // 日志跟随注入 DLL 输出，避免游戏切换工作目录时找不到日志。
        this->mExtractor->SetLoggerDirectory(this->mModuleDirectoryPath);
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

    ExtractCore* Application::GetExtractor()
    {
        return this->mExtractor;
    }

    //**********====Static====**********//

    Application* Application::GetInstance()
    {
        return g_Instance;
    }

    void Application::Initialize(HMODULE hModule)
    {
        g_Instance = new Application();
        g_Instance->InitializeModule(hModule);

        // 初始化阶段唯一需要做的事情就是等待宿主解析 V2Link。
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

    //================================//
}
