#include "crypto/siphash.h"

namespace hxv4::crypto {
namespace {

inline uint64_t rotl(uint64_t v, int c) { return (v << c) | (v >> (64 - c)); }

inline uint64_t load64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

inline void sipround(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3) {
    v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
    v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
}

}  // namespace

uint64_t siphash24(const uint8_t* data, size_t len, const uint8_t key[16]) {
    const uint64_t k0 = load64(key);
    const uint64_t k1 = load64(key + 8);

    uint64_t v0 = 0x736F6D6570736575ULL ^ k0;
    uint64_t v1 = 0x646F72616E646F6DULL ^ k1;
    uint64_t v2 = 0x6C7967656E657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const size_t full = len & ~static_cast<size_t>(7);
    const uint8_t* p = data;
    for (; p != data + full; p += 8) {
        const uint64_t m = load64(p);
        v3 ^= m;
        sipround(v0, v1, v2, v3);
        sipround(v0, v1, v2, v3);
        v0 ^= m;
    }

    uint64_t b = static_cast<uint64_t>(len) << 56;
    switch (len & 7) {
        case 7: b |= static_cast<uint64_t>(p[6]) << 48; [[fallthrough]];
        case 6: b |= static_cast<uint64_t>(p[5]) << 40; [[fallthrough]];
        case 5: b |= static_cast<uint64_t>(p[4]) << 32; [[fallthrough]];
        case 4: b |= static_cast<uint64_t>(p[3]) << 24; [[fallthrough]];
        case 3: b |= static_cast<uint64_t>(p[2]) << 16; [[fallthrough]];
        case 2: b |= static_cast<uint64_t>(p[1]) << 8; [[fallthrough]];
        case 1: b |= static_cast<uint64_t>(p[0]); break;
        default: break;
    }

    v3 ^= b;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xFF;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

}  // namespace hxv4::crypto
