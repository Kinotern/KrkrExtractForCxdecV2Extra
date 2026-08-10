#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Bootstrap {

/// 提取的BOOTSTRAP DLL元数据，供FilterManager派生使用。
struct BootstrapConfig {
    std::wstring unique;      // UNIQUE string from DLL
    std::wstring warning;     // WARNING string from DLL (appended to prefix)
    std::vector<uint8_t> params; // PARAMS raw bytes from DLL (NOT text!)
    uint64_t    archive_seed; // archive seed (8 bytes) from DLL RVA 0x81758

    std::vector<uint8_t> dll_data; // raw decompressed BOOTSTRAP DLL bytes
    bool ok;
};

/// 解密（bres）、解压（zlib）、解析BOOTSTRAP DLL。
/// @param archive_seed_rva 可选的RVA（0=跳过，使用默认值0）
BootstrapConfig extract_bootstrap(
    const uint8_t* bootstrap_ct, size_t ct_len,
    const std::wstring& bootstrap_path,
    const uint8_t* salt, size_t salt_len,
    uint32_t archive_seed_rva = 0);

} // namespace Bootstrap
