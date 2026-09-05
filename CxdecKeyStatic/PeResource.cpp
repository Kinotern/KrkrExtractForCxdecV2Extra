#include "PeResource.h"
#include <cstring>
#include <utility>

namespace PeResource {

// PE结构（资源解析的最小子集）
#pragma pack(push, 1)
struct DosHeader {
    uint8_t  magic[2];    // "MZ"
    uint8_t  _pad[58];
    uint32_t e_lfanew;
};
struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};
struct OptionalHeader {
    uint16_t Magic;
    uint8_t  _pad1[94];
    DataDirectory DataDir[16];
};
struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
struct ResDir {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};
struct ResDirEntry {
    uint32_t Name;
    uint32_t OffsetToData;
};
struct ResDataEntry {
    uint32_t OffsetToData;
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
};
#pragma pack(pop)

static const uint32_t RES_DIR_FLAG = 0x80000000;
static const uint32_t RES_NAME_FLAG = 0x80000000;

// PE 头解析结果。
struct PeHeaders {
    const FileHeader* file_header;
    const OptionalHeader* optional_header;
    const SectionHeader* sections;
    size_t section_count;
};

// 解析 PE 头与节表，任何越界都返回 false。
static bool parse_pe_headers(const uint8_t* pe, size_t pe_size, PeHeaders& out) {
    if (!pe || pe_size < sizeof(DosHeader)) return false;
    auto* dos = (const DosHeader*)pe;
    if (dos->magic[0] != 'M' || dos->magic[1] != 'Z') return false;

    size_t fh_off = (size_t)dos->e_lfanew + 4;
    if (fh_off + sizeof(FileHeader) > pe_size) return false;
    auto* fh = (const FileHeader*)(pe + fh_off);

    size_t oh_off = fh_off + sizeof(FileHeader);
    if (oh_off + fh->SizeOfOptionalHeader > pe_size) return false;
    auto* oh = (const OptionalHeader*)(pe + oh_off);

    size_t sec_off = oh_off + fh->SizeOfOptionalHeader;
    size_t sec_count = fh->NumberOfSections;
    if (sec_off + sec_count * sizeof(SectionHeader) > pe_size) return false;

    out.file_header = fh;
    out.optional_header = oh;
    out.sections = (const SectionHeader*)(pe + sec_off);
    out.section_count = sec_count;
    return true;
}

uint32_t rva_to_file_offset(const uint8_t* pe, size_t pe_size, uint32_t rva) {
    PeHeaders h{};
    if (!parse_pe_headers(pe, pe_size, h)) return UINT32_MAX;

    for (size_t i = 0; i < h.section_count; ++i) {
        uint32_t vsize = h.sections[i].VirtualSize;
        if (vsize == 0) vsize = h.sections[i].SizeOfRawData;
        if (rva >= h.sections[i].VirtualAddress && rva < h.sections[i].VirtualAddress + vsize) {
            return h.sections[i].PointerToRawData + (rva - h.sections[i].VirtualAddress);
        }
    }
    return UINT32_MAX;
}

uint32_t read_image_base(const uint8_t* pe, size_t pe_size) {
    PeHeaders h{};
    if (!parse_pe_headers(pe, pe_size, h)) return 0;
    // PE32 OptionalHeader 的 ImageBase 位于其偏移 28 处。
    if (h.file_header->SizeOfOptionalHeader < 32) return 0;
    return *(const uint32_t*)((const uint8_t*)h.optional_header + 28);
}

// Find a resource by walking the 3-level tree: Type 鈫?Name 鈫?Language.
// 返回(data_ptr, data_size)对，未找到则返回(nullptr, 0)。
static std::pair<const uint8_t*, uint32_t> find_resource(
    const uint8_t* pe, size_t pe_size, const ResDir* root,
    bool type_is_name, const wchar_t* type_name, uint16_t type_id,
    bool name_is_name, const wchar_t* res_name, uint16_t res_id) {
    auto entries = (const ResDirEntry*)(root + 1);

    // 第1层：Type
    const ResDir* lv2 = nullptr;
    for (int i = 0; i < (root->NumberOfNamedEntries + root->NumberOfIdEntries); ++i) {
        bool match = false;
        if (type_is_name) {
            if (entries[i].Name & RES_NAME_FLAG) {
                auto* str = (const uint16_t*)((const uint8_t*)root + (entries[i].Name & 0x7FFFFFFF));
                uint16_t slen = *str++;
                if (type_name && (size_t)slen == wcslen(type_name) &&
                    wcsncmp((const wchar_t*)str, type_name, slen) == 0)
                    match = true;
            }
        } else {
            if (!(entries[i].Name & RES_NAME_FLAG) && entries[i].Name == type_id)
                match = true;
        }
        if (match && (entries[i].OffsetToData & RES_DIR_FLAG)) {
            lv2 = (const ResDir*)((const uint8_t*)root + (entries[i].OffsetToData & 0x7FFFFFFF));
            break;
        }
    }
    if (!lv2) return {nullptr, 0};

    // 第2层：Name
    auto lv2_entries = (const ResDirEntry*)(lv2 + 1);
    const ResDir* lv3 = nullptr;
    for (int i = 0; i < (lv2->NumberOfNamedEntries + lv2->NumberOfIdEntries); ++i) {
        bool match = false;
        if (name_is_name) {
            if (lv2_entries[i].Name & RES_NAME_FLAG) {
                auto* str = (const uint16_t*)((const uint8_t*)lv2 + (lv2_entries[i].Name & 0x7FFFFFFF));
                uint16_t slen = *str++;
                if (res_name && (size_t)slen == wcslen(res_name) &&
                    wcsncmp((const wchar_t*)str, res_name, slen) == 0)
                    match = true;
            }
        } else {
            if (!(lv2_entries[i].Name & RES_NAME_FLAG) && lv2_entries[i].Name == res_id)
                match = true;
        }
        if (match && (lv2_entries[i].OffsetToData & RES_DIR_FLAG)) {
            lv3 = (const ResDir*)((const uint8_t*)lv2 + (lv2_entries[i].OffsetToData & 0x7FFFFFFF));
            break;
        }
    }
    if (!lv3) return {nullptr, 0};

    // 第3层：Language（取第一个条目）
    auto lv3_entries = (const ResDirEntry*)(lv3 + 1);
    int total = lv3->NumberOfNamedEntries + lv3->NumberOfIdEntries;
    if (total == 0) return {nullptr, 0};
    if (lv3_entries[0].OffsetToData & RES_DIR_FLAG) return {nullptr, 0};

    auto* data_entry = (const ResDataEntry*)((const uint8_t*)lv3 + lv3_entries[0].OffsetToData);
    uint32_t file_off = rva_to_file_offset(pe, pe_size, data_entry->OffsetToData);
    if (file_off == UINT32_MAX) return {nullptr, 0};
    return {pe + file_off, data_entry->Size};
}

static const ResDir* get_resource_root(const uint8_t* pe, size_t pe_size) {
    if (pe_size < sizeof(DosHeader)) return nullptr;
    auto* dos = (const DosHeader*)pe;
    if (dos->magic[0] != 'M' || dos->magic[1] != 'Z') return nullptr;
    if (pe_size < dos->e_lfanew + 4 + sizeof(FileHeader) + sizeof(OptionalHeader))
        return nullptr;

    auto* oh = (const OptionalHeader*)(pe + dos->e_lfanew + 4 + sizeof(FileHeader));

    uint32_t res_rva = oh->DataDir[2].VirtualAddress;
    uint32_t res_sz  = oh->DataDir[2].Size;
    if (res_rva == 0 || res_sz == 0) return nullptr;

    uint32_t res_off = rva_to_file_offset(pe, pe_size, res_rva);
    if (res_off == UINT32_MAX) return nullptr;

    return (const ResDir*)(pe + res_off);
}

std::vector<uint8_t> read_rcdata(const uint8_t* pe_data, size_t pe_size,
                                  const char* name) {
    auto* root = get_resource_root(pe_data, pe_size);
    if (!root) return {};

    // 将ASCII名称转换为wchar_t
    size_t nlen = std::strlen(name);
    std::vector<wchar_t> wname(nlen + 1);
    for (size_t i = 0; i < nlen; ++i) wname[i] = (wchar_t)(unsigned char)name[i];
    wname[nlen] = 0;

    auto [ptr, sz] = find_resource(pe_data, pe_size, root,
                                    false, nullptr, 10,
                                    true, wname.data(), 0);

    if (!ptr) return {};

    std::vector<uint8_t> out(sz);
    std::memcpy(out.data(), ptr, sz);
    return out;
}

std::vector<uint8_t> read_custom_resource(const uint8_t* pe_data, size_t pe_size,
                                           const char* type, uint16_t id) {
    auto* root = get_resource_root(pe_data, pe_size);
    if (!root) return {};

    // 将type名称转换为wchar_t
    size_t tlen = std::strlen(type);
    std::vector<wchar_t> wtype(tlen + 1);
    for (size_t i = 0; i < tlen; ++i) wtype[i] = (wchar_t)(unsigned char)type[i];
    wtype[tlen] = 0;

    auto [ptr, sz] = find_resource(pe_data, pe_size, root,
                                    true, wtype.data(), 0,
                                    false, nullptr, id);

    if (!ptr) return {};

    std::vector<uint8_t> out(sz);
    std::memcpy(out.data(), ptr, sz);
    return out;
}

} // namespace PeResource
#include <windows.h>
#include <fstream>

namespace PeResource {

std::vector<uint8_t> read_rcdata(const wchar_t* exe_path, const wchar_t* name) {
    std::vector<uint8_t> out;

    HMODULE h = LoadLibraryExW(exe_path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) return out;

    HRSRC hrsrc = FindResourceW(h, name, RT_RCDATA);
    if (!hrsrc) { FreeLibrary(h); return out; }

    HGLOBAL hglob = LoadResource(h, hrsrc);
    if (!hglob) { FreeLibrary(h); return out; }

    DWORD sz = SizeofResource(h, hrsrc);
    const void* ptr = LockResource(hglob);
    if (ptr && sz > 0) {
        out.resize(sz);
        memcpy(out.data(), ptr, sz);
    }

    FreeLibrary(h);
    return out;
}

std::vector<uint8_t> read_custom_resource(const wchar_t* exe_path,
                                           const wchar_t* type_name, uint16_t id) {
    std::vector<uint8_t> out;

    HMODULE h = LoadLibraryExW(exe_path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) return out;

    HRSRC hrsrc = FindResourceExW(h, type_name, MAKEINTRESOURCEW(id),
                                   MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
    if (!hrsrc) { FreeLibrary(h); return out; }

    HGLOBAL hglob = LoadResource(h, hrsrc);
    if (!hglob) { FreeLibrary(h); return out; }

    DWORD sz = SizeofResource(h, hrsrc);
    const void* ptr = LockResource(hglob);
    if (ptr && sz > 0) {
        out.resize(sz);
        memcpy(out.data(), ptr, sz);
    }

    FreeLibrary(h);
    return out;
}

std::vector<uint8_t> read_raw_offset(const wchar_t* exe_path, uint32_t offset, size_t size) {
    std::vector<uint8_t> out;
    std::ifstream f(exe_path, std::ios::binary);
    if (!f) return out;
    f.seekg(offset);
    out.resize(size);
    f.read((char*)out.data(), size);
    if (f.gcount() != (std::streamsize)size) out.clear();
    return out;
}

} // namespace PeResource
