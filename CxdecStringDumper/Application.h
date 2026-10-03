#pragma once

#include <string>
#include "HashCore.h"

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

		std::wstring mModuleDirectoryPath;	//dll目录
		std::wstring mCurrentDirectoryPath;	//游戏当前目录
		HashCore* mStringDumper;			//Hash字符串dump
		bool mTVPExporterInitialized;		//插件初始化成功标志

	public:

		// 设置模块信息
		// hModule：模块信息
		void InitializeModule(HMODULE hModule);

		// 初始化插件
		// exporter：插件导出函数
		void InitializeTVPEngine(iTVPFunctionExporter* exporter);

		// 获取插件是否初始化完毕
		// 返回 True已初始化 False未初始化
		bool IsTVPEngineInitialize();

		// 获取解包器
		HashCore* GetStringDumper();

		// 获取对象实例
		static Application* GetInstance();
		// 初始化
		// hModule：模块信息
		static void Initialize(HMODULE hModule);
		// 释放
		static void Release();
	};
}

