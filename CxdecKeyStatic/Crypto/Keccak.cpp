#include "keccak.h"
#include <cstring>

namespace Crypto {

// Keccak-f[1600]的轮常量
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// rho步骤的旋转偏移量
static const int ROT[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

// Pi permutation lookup: pi[i] = j means state[j] 鈫?old_state[i]
static const int PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

SHA3_384::SHA3_384() : buf_idx(0), finalized(false) {
    std::memset(state, 0, sizeof(state));
}

void SHA3_384::keccak_f() {
    for (int round = 0; round < 24; ++round) {
        // Theta步骤
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y)
                state[x + 5 * y] ^= D[x];
        }

        // Rho + Pi组合步骤
        uint64_t B[25];
        for (int i = 0; i < 25; ++i)
            B[PI[i]] = rotl64(state[i], ROT[i]);

        // Chi步骤
        for (int y = 0; y < 5; ++y) {
            uint64_t T[5];
            for (int x = 0; x < 5; ++x)
                T[x] = B[x + 5 * y];
            for (int x = 0; x < 5; ++x)
                state[x + 5 * y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
        }

        // Iota步骤
        state[0] ^= RC[round];
    }
}

void SHA3_384::absorb_block() {
    // 将缓冲区字节以小端uint64格式XOR到state的前RATE字节
    for (size_t i = 0; i < RATE / 8; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j)
            v |= (uint64_t)buf[i * 8 + j] << (j * 8);
        state[i] ^= v;
    }
    // Any remaining bytes (RATE is 104 = 13*8, so RATE % 8 == 0 鈥?no remainder)
    keccak_f();
}

void SHA3_384::update(const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t space = RATE - buf_idx;
        size_t chunk = (len < space) ? len : space;
        std::memcpy(buf + buf_idx, data, chunk);
        buf_idx += chunk;
        data += chunk;
        len -= chunk;
        if (buf_idx == RATE) {
            absorb_block();
            buf_idx = 0;
        }
    }
}

void SHA3_384::finalize(uint8_t digest[DIGEST_SIZE]) {
    // 在填充前吸收完整块以避免溢出
    if (buf_idx == RATE) {
        absorb_block();
        buf_idx = 0;
    }
    // SHA3域分隔符：消息后的第一个字节为0x06
    buf[buf_idx++] = 0x06;
    // 用零填充到RATE-1，然后设置最后一个字节为0x80
    std::memset(buf + buf_idx, 0, RATE - buf_idx);
    buf[RATE - 1] |= 0x80;
    absorb_block();

    // 挤压：从state读取前DIGEST_SIZE字节
    // RATE=104>=DIGEST_SIZE=48，一次挤压足够
    for (size_t i = 0; i < DIGEST_SIZE; ++i) {
        int word_idx = (int)(i / 8);
        int byte_idx = (int)(i % 8);
        digest[i] = (uint8_t)(state[word_idx] >> (byte_idx * 8));
    }
    finalized = true;
}

void SHA3_384::hash(const uint8_t* data, size_t len, uint8_t digest[DIGEST_SIZE]) {
    SHA3_384 hasher;
    hasher.update(data, len);
    hasher.finalize(digest);
}

} // namespace Crypto
