#pragma once

#include <cstddef>
#include <cstdint>

namespace hxv4::crypto {

// SipHash-2-4（c = 2 轮/块，d = 4 轮收尾）。key 必须是 16 字节，小端读入。
uint64_t siphash24(const uint8_t* data, size_t len, const uint8_t key[16]);

}  // namespace hxv4::crypto
