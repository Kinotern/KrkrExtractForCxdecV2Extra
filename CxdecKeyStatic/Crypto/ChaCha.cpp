#include "chacha.h"
#include <cstring>

namespace Crypto {

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7); \
} while(0)

void chacha8_block(const uint32_t key[8], const uint32_t nonce[2],
                   uint32_t counter_lo, uint32_t counter_hi, uint8_t output[64]) {
    uint32_t x[16];

    // 初始状态：32字节密钥、64位计数器、64位nonce（Kirikiri布局）
    x[0]  = 0x61707865;   // "expa"
    x[1]  = 0x3320646e;   // "nd 3"
    x[2]  = 0x79622d32;   // "2-by"
    x[3]  = 0x6b206574;   // "te k"
    x[4]  = key[0];  x[5]  = key[1];
    x[6]  = key[2];  x[7]  = key[3];
    x[8]  = key[4];  x[9]  = key[5];
    x[10] = key[6];  x[11] = key[7];
    x[12] = counter_lo;
    x[13] = counter_hi;
    x[14] = nonce[0];
    x[15] = nonce[1];

    uint32_t z[16];
    std::memcpy(z, x, sizeof(z));

    // 8轮 = 4个双轮
    for (int i = 0; i < 4; ++i) {
        // 列轮
        QR(z[0], z[4], z[ 8], z[12]);
        QR(z[1], z[5], z[ 9], z[13]);
        QR(z[2], z[6], z[10], z[14]);
        QR(z[3], z[7], z[11], z[15]);
        // 对角轮
        QR(z[0], z[5], z[10], z[15]);
        QR(z[1], z[6], z[11], z[12]);
        QR(z[2], z[7], z[ 8], z[13]);
        QR(z[3], z[4], z[ 9], z[14]);
    }

    for (int i = 0; i < 16; ++i)
        store32_le(output + i * 4, x[i] + z[i]);
}

void chacha8_xor(const uint8_t key[32], const uint8_t nonce[8],
                 uint32_t counter_lo, uint32_t counter_hi,
                 uint8_t* data, size_t len) {
    uint32_t k[8], n[2];
    for (int i = 0; i < 8; ++i)
        k[i] = load32_le(key + i * 4);
    n[0] = load32_le(nonce);
    n[1] = load32_le(nonce + 4);

    uint8_t block[64];
    size_t pos = 0;
    uint32_t block_idx = 0;
    while (pos < len) {
        // 计数器推进使用XOR（匹配Kirikiri引擎）
        chacha8_block(k, n, counter_lo ^ block_idx, counter_hi, block);
        size_t chunk = (len - pos < 64) ? (len - pos) : 64;
        for (size_t i = 0; i < chunk; ++i)
            data[pos + i] ^= block[i];
        pos += chunk;
        block_idx++;
    }
}

#undef QR

} // namespace Crypto
