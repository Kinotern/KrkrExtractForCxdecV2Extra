#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>

namespace FilterManager {

struct DripProgram {
    std::array<uint8_t, 32> hxv4_key;
    std::array<uint8_t, 24> hxv4_nonce0;
    std::array<uint8_t, 24> hxv4_nonce1;
    std::array<uint32_t, 6> holder_words;
    std::array<uint8_t, 32> hash_key;
    std::vector<uint32_t>    context_u32;
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> lanes;

    uintptr_t manager_va;
    uintptr_t drip_impl_va;
    uintptr_t context_va;
    std::wstring source_module;
    uintptr_t source_module_base;

    bool ok;
};

DripProgram derive_drip_program(
    const uint8_t* dll_data, size_t dll_size,
    const std::wstring& final_bootstrap,
    const std::wstring& unique,
    const uint8_t* params_data, size_t params_len,
    uint64_t archive_seed,
    uint32_t rva_manager_ctor,
    uint32_t rva_bootstrap_derive,
    uint32_t rva_archive_derive,
    uint32_t rva_hashkey_derive);

} // namespace FilterManager
