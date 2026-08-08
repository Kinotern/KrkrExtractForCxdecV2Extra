#include "detour_finder.h"
#include <cstring>
#include <cstdio>
#include <vector>

// 16-byte detour key
static const uint8_t kDetourKey[16] = {
    0xFF, 0xA3, 0xD7, 0x2E, 0x39, 0x33, 0x8D, 0x4A,
    0x80, 0x5C, 0xD4, 0x98, 0x15, 0x3F, 0xC2, 0x8F
};

// Find a PE section by name in a loaded module.
// Returns a pointer to the section data in memory, or nullptr.
static const uint8_t* FindSectionByName(
    const uint8_t* moduleBase,
    const char* name)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        // PE section names are 8 bytes, null-padded
        if (std::memcmp(sec->Name, name, std::strlen(name)) == 0 &&
            (std::strlen(name) >= 8 || sec->Name[std::strlen(name)] == 0)) {
            return moduleBase + sec->VirtualAddress;
        }
    }
    return nullptr;
}

// Scan loaded modules for a detour entry matching our key.
const uint8_t* FindDetourEntry()
{
    std::vector<const uint8_t*> coveredBases;

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {

            auto* base = static_cast<const uint8_t*>(mbi.AllocationBase);

            // Skip regions already covered by a previous module
            bool skip = false;
            for (auto* cb : coveredBases) {
                if (base == cb) { skip = true; break; }
            }
            if (skip) { addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize; continue; }

            // Check if this is a valid PE — "MZ" at base
            if (base[0] != 0x4D || base[1] != 0x5A) {
                addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            coveredBases.push_back(base);

            // Find .detour section in this module
            const uint8_t* secData = FindSectionByName(base, ".detour");
            if (!secData) {
                secData = FindSectionByName(base, ".detourc");
                if (!secData) {
                    addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                    continue;
                }
            }

            // Validate section header: [0]=size>=0x40, [1]==0x727444
            auto* hdr = reinterpret_cast<const uint32_t*>(secData);
            if (hdr[0] < 0x40 || hdr[1] != 0x727444) {
                addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            // Iterate entries from hdr[2] to hdr[3]
            const uint8_t* dataStart = secData + 0x40;
            const uint8_t* dataEnd   = secData + hdr[3];
            const uint8_t* cur = dataStart;

            while (cur + 0x18 <= dataEnd) {
                auto* dir = reinterpret_cast<const uint32_t*>(cur);
                uint32_t dataSize = dir[0];
                const uint8_t* keyPtr = reinterpret_cast<const uint8_t*>(dir + 2);

                if (dataSize < 0x18) break;

                if (std::memcmp(keyPtr, kDetourKey, 16) == 0) {
                    // Match! Return data after 24-byte header
                    return cur + 0x18;
                }

                cur += dataSize;
            }

            // Move past this allocation
            addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            continue;
        }
        addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return nullptr;
}

// Apply detour patches from a matching entry.
bool ApplyDetourPatches(const uint8_t* entry)
{
    auto* hdr = reinterpret_cast<const uint32_t*>(entry);

    uint32_t magic  = hdr[0];
    uint32_t size1  = hdr[4];
    uint32_t size2  = hdr[8];
    uint32_t size3  = hdr[12];
    uint32_t dest1  = hdr[16];
    uint32_t dest2  = hdr[20];
    uint32_t dest3  = hdr[24];

    // No patches to apply — empty entry
    if (magic == 0 && size1 == 0 && size2 == 0 && size3 == 0)
        return false;

    // Patch region 1
    if (size1 > 0 && dest1 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 28 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest1,
                           patchData, size1, nullptr);
    }

    // Patch region 2
    if (size2 > 0 && dest2 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 92 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest2,
                           patchData, size2, nullptr);
    }

    // Patch region 3
    if (size3 > 0 && dest3 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 1636 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest3,
                           patchData, size3, nullptr);
    }

    return true;
}

// Log injectData fields for debugging.
void DumpDetourEntry(const uint8_t* entry)
{
    auto* hdr = reinterpret_cast<const uint32_t*>(entry);

    // [0]=magic [1]=size1 [2]=size2 [3]=size3
    // [4]=dest1 [5]=dest2 [6]=dest3
    OutputDebugStringA("=== Detour Entry ===\n");
    char buf[256];
    sprintf_s(buf, "magic=0x%08X size1=0x%X size2=0x%X size3=0x%X\n",
              hdr[0], hdr[4], hdr[8], hdr[12]);
    OutputDebugStringA(buf);
    sprintf_s(buf, "dest1=0x%08X dest2=0x%08X dest3=0x%08X\n",
              hdr[16], hdr[20], hdr[24]);
    OutputDebugStringA(buf);

    // Write to a log file for easy access
    FILE* f = nullptr;
    fopen_s(&f, "detour_dump.bin", "wb");
    if (f) {
        // Dump raw entry bytes (first 256)
        fwrite(entry, 1, 256, f);
        fclose(f);
    }
}
