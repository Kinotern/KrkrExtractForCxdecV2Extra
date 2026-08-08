#include "detour_section.h"
#include <cstring>

// 16-byte detour key
static const uint8_t kDetourKey[16] = {
    0xFF, 0xA3, 0xD7, 0x2E, 0x39, 0x33, 0x8D, 0x4A,
    0x80, 0x5C, 0xD4, 0x98, 0x15, 0x3F, 0xC2, 0x8F
};

void* CreateDetourSection(
    HANDLE hProcess,
    const void* injectData,
    SIZE_T injectDataSize)
{
    // Allocate remote memory: payload + 440 bytes of PE headers
    const SIZE_T totalSize = injectDataSize + 440;
    void* remoteAddr = VirtualAllocEx(
        hProcess, nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr)
        return nullptr;

    SIZE_T written = 0;

    // --- 1. Write IMAGE_DOS_HEADER (64 bytes) at offset 0 ---
    {
        uint8_t dosHdr[64] = {};
        dosHdr[0] = 0x4D;  // 'M'
        dosHdr[1] = 0x5A;  // 'Z'  â?e_magic = 0x5A4D
        dosHdr[60] = 0x40; // e_lfanew = 0x40
        dosHdr[61] = 0x00;
        dosHdr[62] = 0x00;
        dosHdr[63] = 0x00;

        if (!WriteProcessMemory(hProcess, remoteAddr, dosHdr, 0x40, &written) || written != 0x40) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // --- 2. Write IMAGE_NT_HEADERS32 (248 bytes) at offset 0x40 ---
    {
        uint8_t ntHdr[0xF8] = {};
        // Signature = "PE\0\0"
        ntHdr[0] = 0x50; ntHdr[1] = 0x45; ntHdr[2] = 0x00; ntHdr[3] = 0x00;
        // FileHeader
        ntHdr[4] = 0x4C; ntHdr[5] = 0x01; // Machine = I386 (0x014C)
        ntHdr[6] = 0x01; ntHdr[7] = 0x00; // NumberOfSections = 1
        ntHdr[20] = 0xE0; ntHdr[21] = 0x00; // SizeOfOptionalHeader = 0xE0
        // OptionalHeader
        ntHdr[24] = 0x0B; ntHdr[25] = 0x01; // Magic = PE32 (0x010B)

        if (!WriteProcessMemory(hProcess, static_cast<char*>(remoteAddr) + 0x40,
                                ntHdr, 0xF8, &written) || written != 0xF8) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // --- 3. Write IMAGE_SECTION_HEADER at offset 0x40+0xF8=0x138 ---
    {
        uint8_t secHdr[40] = {};
        std::memcpy(secHdr, ".detour", 7);
        secHdr[8]  = 0x40; secHdr[9]  = 0x00; secHdr[10] = 0x00; secHdr[11] = 0x00; // VirtualSize=0x40
        secHdr[12] = 0x40; secHdr[13] = 0x00; secHdr[14] = 0x00; secHdr[15] = 0x00; // VirtualAddress=0x40
        // SizeOfRawData = injectDataSize + 88
        uint32_t rawSize = static_cast<uint32_t>(injectDataSize + 88);
        secHdr[16] = rawSize & 0xFF;
        secHdr[17] = (rawSize >> 8) & 0xFF;
        secHdr[18] = (rawSize >> 16) & 0xFF;
        secHdr[19] = (rawSize >> 24) & 0xFF;
        secHdr[20] = 0x40; secHdr[21] = 0x00; secHdr[22] = 0x00; secHdr[23] = 0x00; // PtrToRawData=0x40
        // Characteristics = 0x7272744 (readable/writable/executable, contains code)
        secHdr[36] = 0x44; secHdr[37] = 0x27; secHdr[38] = 0x72; secHdr[39] = 0x07;

        if (!WriteProcessMemory(hProcess, static_cast<char*>(remoteAddr) + 0x138,
                                secHdr, 0x28, &written) || written != 0x28) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // --- 4. Write section data header (64 bytes) at offset 0x160 ---
    {
        uint32_t extra[16] = {};
        extra[0] = 0x40;                           // size = 64
        extra[1] = 0x727444;                       // magic = 0x727444 (7500868)
        extra[2] = 0x40;                           // entry start offset
        extra[3] = static_cast<uint32_t>(injectDataSize + 88); // entry end offset

        if (!WriteProcessMemory(hProcess, static_cast<char*>(remoteAddr) + 0x160,
                                extra, 0x40, &written) || written != 0x40) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // --- 5. Write data directory (24 bytes) at offset 0x1A0 ---
    {
        uint8_t dir[24] = {};
        uint32_t dataSize = static_cast<uint32_t>(injectDataSize + 24);
        dir[0]  = dataSize & 0xFF;
        dir[1]  = (dataSize >> 8) & 0xFF;
        dir[2]  = (dataSize >> 16) & 0xFF;
        dir[3]  = (dataSize >> 24) & 0xFF;
        // dir[4..7] = 0 (reserved)
        // dir[8..23] = 16-byte key
        std::memcpy(dir + 8, kDetourKey, 16);

        if (!WriteProcessMemory(hProcess, static_cast<char*>(remoteAddr) + 0x1A0,
                                dir, 0x18, &written) || written != 0x18) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    // --- 6. Write payload data at offset 0x1B8 ---
    {
        if (!WriteProcessMemory(hProcess, static_cast<char*>(remoteAddr) + 0x1B8,
                                injectData, injectDataSize, &written) ||
            written != injectDataSize) {
            VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
            return nullptr;
        }
    }

    return remoteAddr;
}
