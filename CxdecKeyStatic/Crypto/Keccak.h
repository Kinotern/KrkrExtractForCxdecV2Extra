#pragma once

#include <cstdint>
#include <cstddef>

namespace Crypto {

/// @brief SHA3-384（Keccak-1600, c=768, r=832, domain 0x06）
/// 与标准SHA3-384输出完全一致。
class SHA3_384 {
public:
    static constexpr size_t DIGEST_SIZE = 48;
    static constexpr size_t RATE = 104;  // 832 bits

    SHA3_384();
    void update(const uint8_t* data, size_t len);
    void finalize(uint8_t digest[DIGEST_SIZE]);

    /// 一次性便捷函数
    static void hash(const uint8_t* data, size_t len, uint8_t digest[DIGEST_SIZE]);

private:
    void absorb_block();
    void keccak_f();

    uint64_t state[25];
    uint8_t  buf[RATE];
    size_t   buf_idx;
    bool     finalized;
};

} // namespace Crypto
