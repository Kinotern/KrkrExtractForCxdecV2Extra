#pragma once

#include "PackerTypes.h"
class PeReader;

// 保护壳检测器
class PackerDetector {
public:
    explicit PackerDetector(const PeReader& reader);

    PackVariant Detect();
    const std::wstring& GetLastError() const;

private:
    const PeReader& m_reader;
    std::wstring    m_lastError;
};
