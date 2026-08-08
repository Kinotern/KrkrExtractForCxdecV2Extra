#include "pch.h"
#include "CxdecPeUnpacker.h"
#include "PeParser.h"
#include "PackerDetect.h"
#include "UnpackCore.h"

static std::wstring g_lastError;

CXDECPEUNPACKER_API bool CxdecPeUnpacker_Detect(const wchar_t* filePath)
{
    g_lastError.clear();
    if (!filePath || !*filePath) return false;

    PeReader reader(filePath);
    if (!reader.Load()) return false;

    PackerDetector detector(reader);
    return detector.Detect() != PackVariant::None;
}

CXDECPEUNPACKER_API bool CxdecPeUnpacker_Process(const wchar_t* filePath, const wchar_t* outputPath)
{
    g_lastError.clear();
    if (!filePath || !*filePath || !outputPath || !*outputPath) return false;

    PeReader reader(filePath);
    if (!reader.Load()) return false;

    UnpackConfig config;
    config.verboseOutput   = true;
    config.keepBindSection = true;
    config.useExperimental = true;
    config.zeroDosStubData = true;

    UnpackEngine engine(reader, config);
    if (!engine.Process(outputPath)) {
        g_lastError = engine.GetLastError();
        return false;
    }
    return true;
}
