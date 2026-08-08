#include "pch.h"
#include "PackerDetect.h"
#include "PeParser.h"
#include "CryptoUtil.h"

PackerDetector::PackerDetector(const PeReader& reader) : m_reader(reader) {}

PackVariant PackerDetector::Detect()
{
    auto* nt = m_reader.NtHeaders();
    if (!nt || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return PackVariant::None;

    auto* bindSection = m_reader.SectionHeader(".bind");
    if (!bindSection || memcmp(bindSection->Name, ".bind", 5) != 0) {
        m_lastError = L"PE 文件中未找到 .bind 节";
        return PackVariant::None;
    }

    uint32_t entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t aepFileOffset = m_reader.RvaToOffset(entryPoint);
    if (aepFileOffset == 0) {
        m_lastError = L"无法转换入口点 RVA";
        return PackVariant::None;
    }

    // 头部在入口点前 sizeof(PackShellHeader) 字节处
    uint32_t headerFileOffset = aepFileOffset - sizeof(PackShellHeader);
    if (headerFileOffset + sizeof(PackShellHeader) > m_reader.DataSize()) {
        m_lastError = L"头部偏移超出文件范围";
        return PackVariant::None;
    }

    uint8_t headerBuf[sizeof(PackShellHeader)];
    memcpy(headerBuf, m_reader.Data() + headerFileOffset, sizeof(headerBuf));
    PackUtil::XorDecodeChained(headerBuf, sizeof(headerBuf), 0);

    auto* header = reinterpret_cast<PackShellHeader*>(headerBuf);
    if (header->Signature != 0xC0DEC0DF) {
        m_lastError = L"头部魔数不匹配";
        return PackVariant::None;
    }
    if (header->XorKey == 0) {
        m_lastError = L"XorKey 为空";
        return PackVariant::None;
    }

    return PackVariant::V31x86;
}

const std::wstring& PackerDetector::GetLastError() const { return m_lastError; }
