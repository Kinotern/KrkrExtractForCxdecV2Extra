#pragma once

#include <cstdint>
#include <cstddef>

namespace Crypto {

/// @brief ChaCha8流密码（8轮 = 4个双轮）。
/// 32字节密钥，8字节nonce，8字节计数器（64位）。
/// 计数器推进使用XOR（匹配Kirikiri引擎实现）。

/// @brief 生成一个64字节的密钥流块。
/// @param key 8个uint32组成的密钥
void chacha8_block(const uint32_t key[8], const uint32_t nonce[2],
                   uint32_t counter_lo, uint32_t counter_hi, uint8_t output[64]);

/// @brief 用ChaCha8密钥流XOR数据。每64字节块计数器XOR推进。
void chacha8_xor(const uint8_t key[32], const uint8_t nonce[8],
                 uint32_t counter_lo, uint32_t counter_hi,
                 uint8_t* data, size_t len);

} // namespace Crypto
