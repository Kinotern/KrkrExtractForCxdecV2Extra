#pragma once

#include "core/mapping.h"
#include "core/xp3.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hxv4 {

// 映射表的 XChaCha20-Poly1305 根材料：一个 32 字节 key + 两个 24 字节 nonce。
// 用哪个 nonce 由 Hxv4 描述符的 open_flag 决定。
struct Hxv4Keys {
    std::array<uint8_t, 32> root_key{};
    std::array<uint8_t, 24> nonce0{};
    std::array<uint8_t, 24> nonce1{};
};

struct Hxv4MappingBlob {
    Xp3Header header;
    Hxv4Descriptor descriptor;
    std::vector<uint8_t> tjs_bytes;  // 解压后的 TJS Variant 原始字节
    MappingTable table;
};

// 读一个 XP3：解析索引 → 找 Hxv4 → 按 open_flag 选 nonce 解负载 → zlib 解压 → 解析映射表。
bool read_hxv4_mapping(const uint8_t* xp3, size_t len, const Hxv4Keys& keys,
                       Hxv4MappingBlob& out);

}  // namespace hxv4
