#include "pch.h"
#include "CxdecPeUnpacker.h"
#include "PeParser.h"
#include "PackerDetect.h"
#include "UnpackCore.h"

#include "TryExport.h"

static std::wstring g_lastError;

namespace
{
	// 异常消息是 UTF-8，模块内统一用宽串，转一道
	void SetLastErrorFromUtf8(const std::string& message)
	{
		g_lastError = ExportGuard::WideFromUtf8(message);
	}
}

CXDECPEUNPACKER_API bool CxdecPeUnpacker_Detect(const wchar_t* filePath)
{
    g_lastError.clear();
    if (!filePath || !*filePath)
    {
        g_lastError = L"没给 PE 文件路径";
        return false;
    }

    return ExportGuard::Run(
        [](const std::string& m) { SetLastErrorFromUtf8(m); },
        [&]() -> bool
        {
            PeReader reader(filePath);
            if (!reader.Load())
            {
                g_lastError = L"读不了这个 PE 文件";
                return false;
            }

            PackerDetector detector(reader);
            // 返回 false 是常态（大多数 exe 就没壳），这种情况不算错误、不写 lastError
            return detector.Detect() != PackVariant::None;
        });
}

CXDECPEUNPACKER_API bool CxdecPeUnpacker_Process(const wchar_t* filePath, const wchar_t* outputPath)
{
    g_lastError.clear();
    if (!filePath || !*filePath || !outputPath || !*outputPath)
    {
        g_lastError = L"没给 PE 文件路径或输出路径";
        return false;
    }

    return ExportGuard::Run(
        [](const std::string& m) { SetLastErrorFromUtf8(m); },
        [&]() -> bool
        {
            PeReader reader(filePath);
            if (!reader.Load())
            {
                g_lastError = L"读不了这个 PE 文件";
                return false;
            }

            UnpackConfig config;
            config.verboseOutput   = true;
            config.keepBindSection = true;
            config.useExperimental = true;
            config.zeroDosStubData = true;

            UnpackEngine engine(reader, config);
            if (!engine.Process(outputPath))
            {
                g_lastError = engine.GetLastError();
                return false;
            }
            return true;
        });
}

CXDECPEUNPACKER_API const wchar_t* CxdecPeUnpacker_LastError()
{
    return g_lastError.c_str();
}
