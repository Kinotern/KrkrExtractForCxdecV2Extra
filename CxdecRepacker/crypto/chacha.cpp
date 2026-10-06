#include "crypto/chacha.h"

namespace hxv4::crypto {
namespace {

// "expand 32-byte k" 的四个小端 word
constexpr uint32_t kSigma0 = 0x61707865;  // "expa"
constexpr uint32_t kSigma1 = 0x3320646e;  // "nd 3"
constexpr uint32_t kSigma2 = 0x79622d32;  // "2-by"
constexpr uint32_t kSigma3 = 0x6b206574;  // "te k"

inline uint32_t rotl(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

inline uint32_t load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline void store32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d = rotl(d ^ a, 16);
    c += d; b = rotl(b ^ c, 12);
    a += b; d = rotl(d ^ a, 8);
    c += d; b = rotl(b ^ c, 7);
}

// 10 次双轮 = 20 轮
void permute(uint32_t x[16]) {
    for (int i = 0; i < kChaChaRounds / 2; ++i) {
        quarter_round(x[0], x[4], x[8], x[12]);
        quarter_round(x[1], x[5], x[9], x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8], x[13]);
        quarter_round(x[3], x[4], x[9], x[14]);
    }
}

void load_key(uint32_t s[16], const Key32& key) {
    for (int i = 0; i < 8; ++i) s[4 + i] = load32(key.data() + 4 * i);
}

}  // namespace

Block64 chacha20_block(const Key32& key, uint64_t counter, const Nonce8& nonce) {
    uint32_t s[16] = {kSigma0, kSigma1, kSigma2, kSigma3};
    load_key(s, key);
    s[12] = static_cast<uint32_t>(counter);
    s[13] = static_cast<uint32_t>(counter >> 32);
    s[14] = load32(nonce.data());
    s[15] = load32(nonce.data() + 4);

    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = s[i];
    permute(x);

    Block64 out{};
    for (int i = 0; i < 16; ++i) store32(out.data() + 4 * i, x[i] + s[i]);
    return out;
}

void chacha20_xor(const Key32& key, uint64_t counter, const Nonce8& nonce, uint8_t* data,
                  size_t len) {
    size_t off = 0;
    while (off < len) {
        const Block64 ks = chacha20_block(key, counter, nonce);
        const size_t n = (len - off < 64) ? (len - off) : 64;
        for (size_t i = 0; i < n; ++i) data[off + i] ^= ks[i];
        off += n;
        ++counter;
    }
}

Key32 hchacha20(const Key32& key, const Nonce16& nonce) {
    uint32_t s[16] = {kSigma0, kSigma1, kSigma2, kSigma3};
    load_key(s, key);
    for (int i = 0; i < 4; ++i) s[12 + i] = load32(nonce.data() + 4 * i);
    permute(s);

    Key32 out{};
    for (int i = 0; i < 4; ++i) store32(out.data() + 4 * i, s[i]);
    for (int i = 0; i < 4; ++i) store32(out.data() + 16 + 4 * i, s[12 + i]);
    return out;
}

}  // namespace hxv4::crypto
