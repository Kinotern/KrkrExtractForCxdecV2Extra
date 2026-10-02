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

    uint8_t headerBuf[sizeof(PackShellHeader)];
    bool headerFound = false;

    // 路径 1：壳头在入口点前 sizeof(PackShellHeader) 字节处。
    uint32_t entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t aepFileOffset = m_reader.RvaToOffset(entryPoint);
    if (aepFileOffset >= sizeof(PackShellHeader)) {
        uint32_t headerFileOffset = aepFileOffset - sizeof(PackShellHeader);
        if (headerFileOffset + sizeof(PackShellHeader) <= m_reader.DataSize()) {
            memcpy(headerBuf, m_reader.Data() + headerFileOffset, sizeof(headerBuf));
            PackUtil::XorDecodeChained(headerBuf, sizeof(headerBuf), 0);
            headerFound = reinterpret_cast<const PackShellHeader*>(headerBuf)->Signature == 0xC0DEC0DF;
        }
    }

    // 路径 2：壳头在 TLS 回调前 sizeof(PackShellHeader) 字节处（与脱壳引擎 Step1 保持一致）。
    if (!headerFound) {
        auto tlsDir = m_reader.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            uint32_t toff = m_reader.RvaToOffset(tlsDir.VirtualAddress);
            if (toff) {
                const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32*>(m_reader.Data() + toff);
                if (tls->AddressOfCallBacks) {
                    uint32_t cboff = m_reader.RvaToOffset(tls->AddressOfCallBacks);
                    if (cboff) {
                        uint32_t cbRva = *reinterpret_cast<const uint32_t*>(m_reader.Data() + cboff);
                        if (cbRva) {
                            uint32_t cbOff = m_reader.RvaToOffset(cbRva);
                            if (cbOff >= sizeof(PackShellHeader) && cbOff <= m_reader.DataSize()) {
                                memcpy(headerBuf, m_reader.Data() + cbOff - sizeof(PackShellHeader), sizeof(headerBuf));
                                PackUtil::XorDecodeChained(headerBuf, sizeof(headerBuf), 0);
                                headerFound = reinterpret_cast<const PackShellHeader*>(headerBuf)->Signature == 0xC0DEC0DF;
                            }
                        }
                    }
                }
            }
        }
    }

    if (!headerFound) {
        m_lastError = L"头部魔数不匹配";
        return PackVariant::None;
    }

    auto* header = reinterpret_cast<PackShellHeader*>(headerBuf);
    if (header->XorKey == 0) {
        m_lastError = L"XorKey 为空";
        return PackVariant::None;
    }

    return PackVariant::V31x86;
}

const std::wstring& PackerDetector::GetLastError() const { return m_lastError; }
