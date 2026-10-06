#include "crypto/sha3.h"

#include <cstring>

namespace hxv4::crypto {
namespace {

constexpr uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

constexpr int kRho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                          27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
constexpr int kPi[24] = {10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
                         15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1};

inline uint64_t rotl64(uint64_t v, int c) { return (v << c) | (v >> (64 - c)); }

inline uint64_t load64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

// SHA3-384 的 rate：1600 - 2*384 = 832 bit = 104 B
constexpr size_t kRate = 104;

}  // namespace

void keccak_f1600(uint64_t s[25]) {
    for (int round = 0; round < 24; ++round) {
        // theta
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i) {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            const uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) s[j + i] ^= t;
        }
        // rho + pi
        uint64_t t = s[1];
        for (int i = 0; i < 24; ++i) {
            const int j = kPi[i];
            const uint64_t tmp = s[j];
            s[j] = rotl64(t, kRho[i]);
            t = tmp;
        }
        // chi
        for (int j = 0; j < 25; j += 5) {
            uint64_t b[5];
            for (int i = 0; i < 5; ++i) b[i] = s[j + i];
            for (int i = 0; i < 5; ++i) {
                s[j + i] = b[i] ^ ((~b[(i + 1) % 5]) & b[(i + 2) % 5]);
            }
        }
        // iota
        s[0] ^= kRoundConstants[round];
    }
}

void sha3_384(const uint8_t* data, size_t len, uint8_t out[48]) {
    uint64_t st[25] = {};
    auto absorb = [&st](const uint8_t* block) {
        for (size_t i = 0; i < kRate / 8; ++i) st[i] ^= load64(block + 8 * i);
        keccak_f1600(st);
    };

    while (len >= kRate) {
        absorb(data);
        data += kRate;
        len -= kRate;
    }

    uint8_t block[kRate] = {};
    std::memcpy(block, data, len);
    block[len] = 0x06;              // SHA-3 域分隔 + 起始位
    block[kRate - 1] |= 0x80;       // 结束位
    absorb(block);

    for (size_t i = 0; i < 48; ++i) {
        out[i] = static_cast<uint8_t>(st[i / 8] >> (8 * (i % 8)));
    }
}

}  // namespace hxv4::crypto
