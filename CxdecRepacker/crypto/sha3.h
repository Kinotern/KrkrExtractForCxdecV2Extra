#pragma once

#include <cstddef>
#include <cstdint>

namespace hxv4::crypto {

// Keccak-f[1600] 置换（24 轮）。
void keccak_f1600(uint64_t state[25]);

// SHA3-384，输出 48 字节。bres 资源的 path_key 派生用它。
void sha3_384(const uint8_t* data, size_t len, uint8_t out[48]);

}  // namespace hxv4::crypto
