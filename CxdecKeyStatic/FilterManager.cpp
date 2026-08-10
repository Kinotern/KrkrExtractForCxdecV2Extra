#include "FilterManager.h"
#include <windows.h>
#include <cstring>
#include <cstdio>

namespace FilterManager {

static constexpr size_t MANAGER_SIZE = 0x30B0;

using ManagerCtor     = void (__thiscall*)(void* manager);
using BootstrapDerive = int  (__thiscall*)(void* manager_core,
                                            const wchar_t* bootstrap, size_t bootstrap_bytes,
                                            const uint8_t* params, size_t params_bytes);
using ArchiveDerive   = int  (__thiscall*)(void* manager_core,
                                            const wchar_t* unique, size_t unique_bytes,
                                            void* seed_bytes);
using HashKeyDerive   = void (__cdecl*)(void* out_bytes, size_t out_size,
                                         const void* data_bytes, size_t data_size,
                                         int seed);

static bool call_native_functions(
    void* manager,
    void* manager_core,
    const wchar_t* bootstrap, size_t bootstrap_len,
    const uint8_t* params_data, size_t params_len,
    const wchar_t* unique, size_t unique_len,
    uint64_t archive_seed,
    uint8_t* hash_key_out,
    ManagerCtor pMgrCtor,
    BootstrapDerive pBootstrap,
    ArchiveDerive pArchive,
    HashKeyDerive pHashKey)
{
    __try {
        pMgrCtor(manager);

        int ok = pBootstrap(manager_core,
                            bootstrap, bootstrap_len * sizeof(wchar_t),
                            params_data, params_len);
        if (ok == 0) return false;

        uint8_t local_hk[32] = {};
        uint32_t flag = *(uint32_t*)((uint8_t*)manager + 0x30A0);
        if ((flag & 3) == 3) {
            pHashKey(local_hk, sizeof(local_hk),
                     (uint8_t*)manager + 0x3040, 0x40, -1);
        }
        memcpy(hash_key_out, local_hk, 32);

        uint8_t seed_bytes[8];
        seed_bytes[0] = (uint8_t)(archive_seed);
        seed_bytes[1] = (uint8_t)(archive_seed >> 8);
        seed_bytes[2] = (uint8_t)(archive_seed >> 16);
        seed_bytes[3] = (uint8_t)(archive_seed >> 24);
        seed_bytes[4] = (uint8_t)(archive_seed >> 32);
        seed_bytes[5] = (uint8_t)(archive_seed >> 40);
        seed_bytes[6] = (uint8_t)(archive_seed >> 48);
        seed_bytes[7] = (uint8_t)(archive_seed >> 56);
        pArchive(manager_core, unique, unique_len * sizeof(wchar_t), seed_bytes);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

DripProgram derive_drip_program(
    const uint8_t* dll_data, size_t dll_size,
    const std::wstring& final_bootstrap,
    const std::wstring& unique,
    const uint8_t* params_data, size_t params_len,
    uint64_t archive_seed,
    uint32_t rva_manager_ctor,
    uint32_t rva_bootstrap_derive,
    uint32_t rva_archive_derive,
    uint32_t rva_hashkey_derive) {

    DripProgram prog{};
    prog.ok = false;

    if (!dll_data || dll_size == 0 || dll_size < 64) return prog;
    if (dll_data[0] != 'M' || dll_data[1] != 'Z') return prog;

    auto rva_valid = [&](uint32_t rva) { return rva > 0 && rva + 16 < dll_size; };
    if (!rva_valid(rva_manager_ctor) || !rva_valid(rva_bootstrap_derive) ||
        !rva_valid(rva_archive_derive) || !rva_valid(rva_hashkey_derive))
        return prog;

    wchar_t temp_path[MAX_PATH];
    wchar_t temp_file[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp_path)) return prog;
    if (!GetTempFileNameW(temp_path, L"bsd", 0, temp_file)) return prog;

    std::wstring dll_path = temp_file;
    dll_path += L".dll";
    DeleteFileW(temp_file);

    {
        FILE* f = _wfopen(dll_path.c_str(), L"wb");
        if (!f) return prog;
        fwrite(dll_data, 1, dll_size, f);
        fclose(f);
    }

    HMODULE hDll = LoadLibraryW(dll_path.c_str());
    if (!hDll) {
        DeleteFileW(dll_path.c_str());
        return prog;
    }

    {
        uint8_t* seed_ptr = (uint8_t*)hDll + 0x81758;
        uint64_t loaded_seed = 0;
        if (!IsBadReadPtr(seed_ptr, 8))
            loaded_seed = *(uint64_t*)seed_ptr;
        if (loaded_seed != 0) archive_seed = loaded_seed;
    }

    prog.source_module = dll_path;
    prog.source_module_base = (uintptr_t)hDll;

    uint8_t* base = (uint8_t*)hDll;
    auto pMgrCtor   = (ManagerCtor)(base + rva_manager_ctor);
    auto pBootstrap = (BootstrapDerive)(base + rva_bootstrap_derive);
    auto pArchive   = (ArchiveDerive)(base + rva_archive_derive);
    auto pHashKey   = (HashKeyDerive)(base + rva_hashkey_derive);

    void* manager = VirtualAlloc(nullptr, MANAGER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!manager) {
        FreeLibrary(hDll);
        DeleteFileW(dll_path.c_str());
        return prog;
    }
    std::memset(manager, 0, MANAGER_SIZE);

    uint8_t* mgr = (uint8_t*)manager;
    uint8_t* core = mgr + 8;
    prog.manager_va = (uintptr_t)manager;

    uint8_t hash_key_buf[32] = {};
    bool native_ok = call_native_functions(
        manager, core,
        final_bootstrap.c_str(), final_bootstrap.size(),
        params_data, params_len,
        unique.c_str(), unique.size(),
        archive_seed,
        hash_key_buf,
        pMgrCtor, pBootstrap, pArchive, pHashKey);

    if (!native_ok) {
        VirtualFree(manager, 0, MEM_RELEASE);
        FreeLibrary(hDll);
        DeleteFileW(dll_path.c_str());
        return prog;
    }

    for (int i = 0; i < 6; ++i)
        prog.holder_words[i] = *(uint32_t*)(core + 4 + i * 4);
    std::memcpy(prog.hxv4_key.data(), core + 0x3038, 32);
    std::memcpy(prog.hxv4_nonce1.data(), core + 0x3058, 24);
    std::memcpy(prog.hxv4_nonce0.data(), core + 0x3078, 24);

    uint32_t drip_impl_rva = *(uint32_t*)(core);
    uint8_t* drip_impl = (uint8_t*)(uintptr_t)drip_impl_rva;
    prog.drip_impl_va = (uintptr_t)drip_impl;

    if (drip_impl && !IsBadReadPtr(drip_impl, 0x810)) {
        uint32_t context_ptr = *(uint32_t*)(drip_impl + 0x04 + 0x0C);
        prog.context_va = (uintptr_t)context_ptr;
        if (context_ptr >= (uint32_t)(uintptr_t)manager &&
            context_ptr < (uint32_t)(uintptr_t)manager + MANAGER_SIZE) {
            uint8_t* ctx_start = (uint8_t*)(uintptr_t)context_ptr;
            uint8_t* ctx_end   = mgr + MANAGER_SIZE;
            size_t ctx_bytes   = ctx_end - ctx_start;
            size_t ctx_count   = ctx_bytes / 4;
            prog.context_u32.resize(ctx_count);
            for (size_t i = 0; i < ctx_count; ++i)
                prog.context_u32[i] = *(uint32_t*)(ctx_start + i * 4);

            // 提取lanes（128条lane，每条0x10字节，起始于drip_impl + 0x04）
            static constexpr int LANE_COUNT = 128;
            static constexpr int LANE_SIZE = 0x10;
            uint8_t* lane_base = drip_impl + 0x04;
            for (int li = 0; li < LANE_COUNT; ++li) {
                uint8_t* lane = lane_base + li * LANE_SIZE;
                if ((uint8_t*)lane + LANE_SIZE > mgr + MANAGER_SIZE) break;
                uint32_t begin   = *(uint32_t*)(lane);
                uint32_t end     = *(uint32_t*)(lane + 4);
                // 跳过current和ctx
                if (end < begin || ((end - begin) % 8) != 0) continue;
                std::vector<std::pair<uint32_t, uint32_t>> records;
                for (uint32_t rec = begin; rec < end; rec += 8) {
                    uint8_t* rp = (uint8_t*)(uintptr_t)rec;
                    if (IsBadReadPtr(rp, 8)) break;
                    uint32_t param = *(uint32_t*)(rp);
                    uint32_t callback = *(uint32_t*)(rp + 4);
                    records.push_back({param, callback});
                }
                prog.lanes.push_back(std::move(records));
            }
        }
    }

    std::memcpy(prog.hash_key.data(), hash_key_buf, 32);
    prog.ok = true;

    VirtualFree(manager, 0, MEM_RELEASE);
    FreeLibrary(hDll);
    DeleteFileW(dll_path.c_str());

    return prog;
}

} // namespace FilterManager
