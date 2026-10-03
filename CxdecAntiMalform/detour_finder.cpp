#include "detour_finder.h"
#include <cstring>
#include <cstdio>
#include <vector>

// 16 字节 detour key
static const uint8_t kDetourKey[16] = {
    0xFF, 0xA3, 0xD7, 0x2E, 0x39, 0x33, 0x8D, 0x4A,
    0x80, 0x5C, 0xD4, 0x98, 0x15, 0x3F, 0xC2, 0x8F
};

// 在已加载模块里按名字找节
// 返回内存中该节数据的指针，找不到返回 nullptr
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
        // 节名固定 8 字节，不足补 0
        if (std::memcmp(sec->Name, name, std::strlen(name)) == 0 &&
            (std::strlen(name) >= 8 || sec->Name[std::strlen(name)] == 0)) {
            return moduleBase + sec->VirtualAddress;
        }
    }
    return nullptr;
}

// 遍历内存，找能匹配 key 的载荷条目
const uint8_t* FindDetourEntry()
{
    std::vector<const uint8_t*> coveredBases;

    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {

            auto* base = static_cast<const uint8_t*>(mbi.AllocationBase);

            // 跳过已被前面模块覆盖的区域
            bool skip = false;
            for (auto* cb : coveredBases) {
                if (base == cb) { skip = true; break; }
            }
            if (skip) { addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize; continue; }

            // 判断这块是不是 PE（头部为 "MZ"）
            if (base[0] != 0x4D || base[1] != 0x5A) {
                addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            coveredBases.push_back(base);

            // 在这个模块里找 .detour 节
            const uint8_t* secData = FindSectionByName(base, ".detour");
            if (!secData) {
                secData = FindSectionByName(base, ".detourc");
                if (!secData) {
                    addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                    continue;
                }
            }

            // 校验节数据头：[0]=size>=0x40，[1]==0x727444
            auto* hdr = reinterpret_cast<const uint32_t*>(secData);
            if (hdr[0] < 0x40 || hdr[1] != 0x727444) {
                addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            // 从 hdr[2] 到 hdr[3] 遍历条目
            const uint8_t* dataStart = secData + 0x40;
            const uint8_t* dataEnd   = secData + hdr[3];
            const uint8_t* cur = dataStart;

            while (cur + 0x18 <= dataEnd) {
                auto* dir = reinterpret_cast<const uint32_t*>(cur);
                uint32_t dataSize = dir[0];
                const uint8_t* keyPtr = reinterpret_cast<const uint8_t*>(dir + 2);

                if (dataSize < 0x18) break;

                if (std::memcmp(keyPtr, kDetourKey, 16) == 0) {
                    // 命中，返回跳过 24 字节头之后的数据
                    return cur + 0x18;
                }

                cur += dataSize;
            }

            // 移到下一块分配
            addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            continue;
        }
        addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return nullptr;
}

// 应用命中条目里的三处补丁
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

    // 空条目，没有要打的东西
    if (magic == 0 && size1 == 0 && size2 == 0 && size3 == 0)
        return false;

    // 区域 1
    if (size1 > 0 && dest1 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 28 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest1,
                           patchData, size1, nullptr);
    }

    // 区域 2
    if (size2 > 0 && dest2 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 92 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest2,
                           patchData, size2, nullptr);
    }

    // 区域 3
    if (size3 > 0 && dest3 != 0) {
        const uint8_t* patchData = reinterpret_cast<const uint8_t*>(hdr + 1636 / 4);
        WriteProcessMemory(GetCurrentProcess(), (void*)(uintptr_t)dest3,
                           patchData, size3, nullptr);
    }

    return true;
}

// 调试用：打印载荷字段
void DumpDetourEntry(const uint8_t* entry)
{
    auto* hdr = reinterpret_cast<const uint32_t*>(entry);

    // 载荷字段：[0]=magic [1]=size1 [2]=size2 [3]=size3
    // [4]=dest1 [5]=dest2 [6]=dest3
    OutputDebugStringA("=== Detour Entry ===\n");
    char buf[256];
    sprintf_s(buf, "magic=0x%08X size1=0x%X size2=0x%X size3=0x%X\n",
              hdr[0], hdr[4], hdr[8], hdr[12]);
    OutputDebugStringA(buf);
    sprintf_s(buf, "dest1=0x%08X dest2=0x%08X dest3=0x%08X\n",
              hdr[16], hdr[20], hdr[24]);
    OutputDebugStringA(buf);

    // 落盘一份，方便查看
    FILE* f = nullptr;
    fopen_s(&f, "detour_dump.bin", "wb");
    if (f) {
        // 转储条目原始字节（前 256 字节）
        fwrite(entry, 1, 256, f);
        fclose(f);
    }
}
