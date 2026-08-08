#pragma once

#include "PackerTypes.h"
class PeReader;

// 脱壳配置选项
struct UnpackConfig {
    bool verboseOutput    = true;
    bool keepBindSection  = true;
    bool useExperimental  = true;
    bool zeroDosStubData  = true;
    bool realignSections  = false;
    bool recalcChecksum   = false;
};

// 脱壳引擎：执行 7 步管线
class UnpackEngine {
public:
    UnpackEngine(PeReader& reader, const UnpackConfig& config);

    bool Process(const std::wstring& outputPath);
    const std::wstring& GetLastError() const;

private:
    void Log(const wchar_t* fmt, ...);

    bool Step1_ReadHeader();
    bool Step2_DecodePayload();
    bool Step3_DumpPlatformDriver();
    bool Step4_HandleBindSection();
    bool Step5_DecryptCodeSection();
    bool Step6_FixTlsCallbacks();
    bool Step7_RebuildAndSave(const std::wstring& outputPath);

    PeReader&          m_reader;
    UnpackConfig       m_config;
    PackShellHeader    m_header;
    std::wstring       m_lastError;

    std::vector<uint8_t> m_payloadData;
    std::vector<uint8_t> m_driverDllData;
    std::vector<uint8_t> m_decryptedCode;
    uint32_t             m_bindStartOffset;
    uint32_t             m_bindEndOffset;
};
