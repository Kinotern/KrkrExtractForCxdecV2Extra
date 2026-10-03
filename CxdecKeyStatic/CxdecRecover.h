#pragma once

#include <string>
#include <cstdint>

namespace Engine {

// 静态密钥提取的per-game常量。
// 所有可自动检测的字段默认为零/空；仅在需要覆盖时设置。
struct GameParams {
    // Salt自动检测。HXV4的salt_size始终为0x2000。
    uint32_t salt_offset = 0;   // 0 = auto-detect via V2Link marker
    uint32_t salt_size   = 0x2000;

    // filter path 覆盖；留空则从 EXE 资源自动检测（startup / bootstrap 两个来源）
    std::wstring startup_filter_path;    // empty = auto
    std::wstring bootstrap_filter_path;  // empty = auto

    // BOOTSTRAP DLL RVA常量。
    uint32_t rva_manager_ctor     = 0x0E2D0;
    uint32_t rva_bootstrap_derive = 0x15630;
    uint32_t rva_archive_derive   = 0x157D0;
    uint32_t rva_hashkey_derive   = 0x10410;
    uint32_t rva_archive_seed     = 0x81758;
};

// 主入口点。
bool recover_drip_program(const std::wstring& exe_path,
                          const std::wstring& output_dir,
                          const GameParams& params = GameParams{},
                          std::string* error_out = nullptr);

} // namespace Engine
