#pragma once

#include <string>
#include "KeyCore.h"

namespace Engine
{
    using tTVPV2LinkProc = HRESULT(__stdcall*)(iTVPFunctionExporter*);
    using tTVPV2UnlinkProc = HRESULT(__stdcall*)();

    class Application
    {
    private:
        Application();
        Application(const Application&) = delete;
        Application(Application&&) = delete;
        Application& operator=(const Application&) = delete;
        Application& operator=(Application&&) = delete;
        ~Application();

    private:
        std::wstring mModuleDirectoryPath;
        std::wstring mCurrentDirectoryPath;
        KeyCore* mKeyDumper;
        bool mTVPExporterInitialized;

    public:
        void InitializeModule(HMODULE hModule);
        void InitializeTVPEngine(iTVPFunctionExporter* exporter);
        bool IsTVPEngineInitialize();
        KeyCore* GetKeyDumper();

        static Application* GetInstance();
        static void Initialize(HMODULE hModule);
        static void Release();
    };
}
