#include "pch.h"
#include "UnpackCore.h"
#include "PeParser.h"
#include "CryptoUtil.h"
#include <cstdio>

static const uint32_t HEADER_SIZE = sizeof(PackShellHeader);

UnpackEngine::UnpackEngine(PeReader& reader, const UnpackConfig& config)
    : m_reader(reader), m_config(config), m_bindStartOffset(0), m_bindEndOffset(0) {
    memset(&m_header, 0, sizeof(m_header));
}
const std::wstring& UnpackEngine::GetLastError() const { return m_lastError; }
void UnpackEngine::Log(const wchar_t* fmt, ...) {
    if (!m_config.verboseOutput) return;
    wchar_t buf[512]; va_list args; va_start(args, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, args); va_end(args);
    OutputDebugStringW(buf); OutputDebugStringW(L"\n");
}

bool UnpackEngine::Process(const std::wstring& outputPath) {
    Log(L"[PeUnpacker] 开始脱壳...");
    if (!Step1_ReadHeader())           return false;
    if (!Step2_DecodePayload())        return false;
    if (!Step3_DumpPlatformDriver())   return false;
    if (!Step4_HandleBindSection())    return false;
    if (!Step5_DecryptCodeSection())   return false;
    if (!Step6_FixTlsCallbacks())      return false;
    if (!Step7_RebuildAndSave(outputPath)) return false;
    Log(L"[PeUnpacker] 脱壳完成: %s", outputPath.c_str());
    return true;
}

// Step 1: 读取并 XOR 解码保护壳头部（入口点前 HEADER_SIZE 字节处）
bool UnpackEngine::Step1_ReadHeader() {
    Log(L"  Step 1 - 读取保护壳头部...");
    auto* nt = m_reader.NtHeaders();
    if (!nt) { m_lastError = L"NT 头读取失败"; return false; }
    auto* bindSec = m_reader.SectionHeader(".bind");
    if (!bindSec) { m_lastError = L"未找到 .bind 节"; return false; }

    uint32_t epOff = m_reader.RvaToOffset(nt->OptionalHeader.AddressOfEntryPoint);
    if (!epOff) { m_lastError = L"入口点 RVA 转换失败"; return false; }

    uint32_t hdrOff = epOff - HEADER_SIZE;
    if (hdrOff + HEADER_SIZE > m_reader.DataSize()) {
        m_lastError = L"头部偏移越界"; return false;
    }

    uint8_t buf[HEADER_SIZE];
    memcpy(buf, m_reader.Data() + hdrOff, HEADER_SIZE);
    PackUtil::XorDecodeChained(buf, HEADER_SIZE, 0);
    memcpy(&m_header, buf, HEADER_SIZE);

    // TLS 回调路径回退
    if (m_header.Signature != 0xC0DEC0DF) {
        Log(L"  --> 尝试 TLS 回调路径...");
        auto tlsDir = m_reader.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            uint32_t toff = m_reader.RvaToOffset(tlsDir.VirtualAddress);
            if (toff) {
                auto* tls = (const IMAGE_TLS_DIRECTORY32*)(m_reader.Data() + toff);
                if (tls->AddressOfCallBacks) {
                    uint32_t cboff = m_reader.RvaToOffset(tls->AddressOfCallBacks);
                    if (cboff) {
                        uint32_t cbRva = *(const uint32_t*)(m_reader.Data() + cboff);
                        if (cbRva) {
                            uint32_t cbOff = m_reader.RvaToOffset(cbRva);
                            hdrOff = cbOff - HEADER_SIZE;
                            if (hdrOff + HEADER_SIZE <= m_reader.DataSize()) {
                                memcpy(buf, m_reader.Data() + hdrOff, HEADER_SIZE);
                                PackUtil::XorDecodeChained(buf, HEADER_SIZE, 0);
                                memcpy(&m_header, buf, HEADER_SIZE);
                            }
                        }
                    }
                }
            }
        }
        if (m_header.Signature != 0xC0DEC0DF) {
            m_lastError = L"头部魔数不匹配"; return false;
        }
    }

    if (!m_header.XorKey) { m_lastError = L"XorKey 为空"; return false; }
    m_bindStartOffset = bindSec->PointerToRawData;
    m_bindEndOffset   = bindSec->PointerToRawData + m_header.BindSectionVirtualSize;
    return true;
}

// Step 2: 解码载荷数据（.bind 节起始位置）
bool UnpackEngine::Step2_DecodePayload() {
    Log(L"  Step 2 - 解码载荷数据...");
    uint32_t ps = (m_header.PayloadSize + 0x0F) & 0xFFFFFFF0;
    if (!ps) { Log(L"  --> 无载荷"); return true; }

    uint32_t poff = m_bindStartOffset;
    if (poff + ps > m_reader.DataSize()) {
        m_lastError = L"载荷数据越界"; return false;
    }
    m_payloadData.resize(ps);
    memcpy(m_payloadData.data(), m_reader.Data() + poff, ps);
    PackUtil::XorDecodeChained(m_payloadData.data(), ps, m_header.XorKey);
    return true;
}

// Step 3: 提取并 XTEA 解密平台驱动 DLL
bool UnpackEngine::Step3_DumpPlatformDriver() {
    Log(L"  Step 3 - 提取平台驱动...");
    if (!m_header.DrvDllSize) { Log(L"  --> 驱动大小为 0"); return true; }

    uint32_t doff = m_bindStartOffset + m_header.DrvDllOffset;
    if (doff + m_header.DrvDllSize > m_reader.DataSize()) {
        m_lastError = L"驱动数据越界"; return false;
    }
    m_driverDllData.resize(m_header.DrvDllSize);
    memcpy(m_driverDllData.data(), m_reader.Data() + doff, m_header.DrvDllSize);
    PackUtil::XteaDecrypt(m_driverDllData.data(), m_driverDllData.size(), m_header.DrvDecryptKeys);
    return true;
}

// Step 4: 定位代码段
bool UnpackEngine::Step4_HandleBindSection() {
    Log(L"  Step 4 - 定位代码段...");
    auto* cs = m_reader.SectionHeader(".text");
    if (!cs) { m_lastError = L"未找到 .text 节"; return false; }
    return true;
}

// Step 5: AES-256-CBC 解密代码段（NoEncryption 标志置位时跳过）
bool UnpackEngine::Step5_DecryptCodeSection() {
    Log(L"  Step 5 - AES 解密代码段...");
    auto* cs = m_reader.SectionHeader(".text");
    if (!cs) { m_lastError = L"未找到 .text 节"; return false; }

    if (m_header.Flags & PackFlags::NoEncryption) {
        Log(L"  --> 代码段未加密，跳过解密");
        return true;
    }

    uint32_t coff = cs->PointerToRawData;
    size_t csz = (size_t)m_header.CodeSectionRawSize;
    if (coff + csz > m_reader.DataSize()) {
        m_lastError = L"代码段数据越界"; return false;
    }

    // 被偷数据(16 字节) + 加密代码段
    size_t total = sizeof(m_header.CodeSectionStolenData) + csz;
    std::vector<uint8_t> combined(total);
    memcpy(combined.data(), m_header.CodeSectionStolenData, sizeof(m_header.CodeSectionStolenData));
    memcpy(combined.data() + sizeof(m_header.CodeSectionStolenData), m_reader.Data() + coff, csz);

    if (!PackUtil::AesDecrypt(combined.data(), total,
        m_header.AesKey, sizeof(m_header.AesKey), m_header.AesIv, sizeof(m_header.AesIv), m_decryptedCode)) {
        m_lastError = L"AES 解密失败"; return false;
    }
    return true;
}

// Step 6: NOP TLS 回调防反脱壳
bool UnpackEngine::Step6_FixTlsCallbacks() {
    Log(L"  Step 6 - TLS 回调处理...");

    // NOP first 16 bytes of code section (stolen data area)
    if (m_decryptedCode.size() >= 16) {
        const uint8_t nop16[] = {
            0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
        };
        memcpy(m_decryptedCode.data(), nop16, 16);
    }

    auto td = m_reader.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
    if (!td.VirtualAddress || !td.Size) { Log(L"  --> 无 TLS 目录"); return true; }
    uint32_t toff = m_reader.RvaToOffset(td.VirtualAddress);
    if (!toff) return true;
    auto* tls = (const IMAGE_TLS_DIRECTORY32*)(m_reader.Data() + toff);
    if (!tls->AddressOfCallBacks) return true;
    uint32_t cboff = m_reader.RvaToOffset(tls->AddressOfCallBacks);
    if (!cboff) return true;
    const uint8_t nop[] = { 0x00,0x00,0x00,0x00,0xC3,0x90,0x90,0x90,0x90,0x90 };
    uint32_t cbRva = *(const uint32_t*)(m_reader.Data() + cboff);
    if (cbRva) {
        auto* cs = m_reader.SectionHeader(".text");
        if (cs && cbRva >= cs->VirtualAddress && cbRva < cs->VirtualAddress + m_decryptedCode.size()) {
            uint32_t o = cbRva - cs->VirtualAddress;
            if (o + sizeof(nop) <= m_decryptedCode.size())
                memcpy(m_decryptedCode.data() + o, nop, sizeof(nop));
        }
    }
    return true;
}

// Step 7: 重建 PE 并保存
bool UnpackEngine::Step7_RebuildAndSave(const std::wstring& outputPath) {
    Log(L"  Step 7 - 重建 PE...");
    PeRebuilder rebuilder(m_reader);
    rebuilder.SetEntryPoint((uint32_t)m_header.OriginalEntryPoint);

    if (!m_decryptedCode.empty()) {
        if (!rebuilder.ReplaceSectionData(".text", m_decryptedCode))
            { m_lastError = L".text 节替换失败"; return false; }
    }
    if (!m_config.keepBindSection) rebuilder.RemoveSection(".bind");

    if (m_config.zeroDosStubData) rebuilder.ZeroDosStub();
    if (!rebuilder.Save(outputPath)) { m_lastError = L"保存失败"; return false; }
    return true;
}
