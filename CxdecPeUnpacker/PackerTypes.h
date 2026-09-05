#pragma once

#pragma pack(push, 1)

// V3.1 保护壳头部结构体，从 .bind 节 XOR 解码后获得
struct PackShellHeader {
    uint32_t XorKey;                    // +0x00
    uint32_t Signature;                 // +0x04: 魔数 0xC0DEC0DF
    uint64_t ImageBase;                 // +0x08
    uint64_t AddressOfEntryPoint;       // +0x10
    uint32_t BindSectionOffset;         // +0x18
    uint32_t Unknown0000;               // +0x1C
    uint64_t OriginalEntryPoint;        // +0x20
    uint32_t Unknown0001;               // +0x28
    uint32_t PayloadSize;               // +0x2C
    uint32_t DrvDllOffset;              // +0x30
    uint32_t DrvDllSize;                // +0x34
    uint32_t AppId;                     // +0x38
    uint32_t Flags;                     // +0x3C
    uint32_t BindSectionVirtualSize;    // +0x40
    uint32_t Unknown0002;               // +0x44
    uint64_t CodeSectionVA;             // +0x48
    uint64_t CodeSectionRawSize;        // +0x50
    uint8_t  AesKey[0x20];              // +0x58
    uint8_t  AesIv[0x10];               // +0x78
    uint8_t  CodeSectionStolenData[0x10]; // +0x88
    uint32_t DrvDecryptKeys[4];         // +0x98
    uint32_t Unknown0003[8];            // +0xA8
    uint64_t GetModuleHandleA_Rva;      // +0xC8
    uint64_t GetModuleHandleW_Rva;      // +0xD0
    uint64_t LoadLibraryA_Rva;          // +0xD8
    uint64_t LoadLibraryW_Rva;          // +0xE0
    uint64_t GetProcAddress_Rva;        // +0xE8
};

#pragma pack(pop)

// DRM 标志位（SteamStub V3.1 的 Flags 字段）
namespace PackFlags {
    constexpr uint32_t NoEncryption = 0x04;  // 代码段未加密
}

// 检测结果
enum class PackVariant : int {
    None    = 0,
    V31x86  = 0x31,
};
