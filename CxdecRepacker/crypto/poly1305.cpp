#include "crypto/poly1305.h"

namespace hxv4::crypto {
namespace {

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

}  // namespace

Poly1305::Poly1305(const Key32& key) {
    // r 的钳位直接由掩码完成：r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    r_[0] = load32(key.data() + 0) & 0x3ffffff;
    r_[1] = (load32(key.data() + 3) >> 2) & 0x3ffff03;
    r_[2] = (load32(key.data() + 6) >> 4) & 0x3ffc0ff;
    r_[3] = (load32(key.data() + 9) >> 6) & 0x3f03fff;
    r_[4] = (load32(key.data() + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; ++i) h_[i] = 0;
    for (int i = 0; i < 4; ++i) pad_[i] = load32(key.data() + 16 + 4 * i);
}

void Poly1305::block(const uint8_t* m, uint32_t hibit) {
    const uint32_t r0 = r_[0], r1 = r_[1], r2 = r_[2], r3 = r_[3], r4 = r_[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint32_t h0 = h_[0] + (load32(m + 0) & 0x3ffffff);
    uint32_t h1 = h_[1] + ((load32(m + 3) >> 2) & 0x3ffffff);
    uint32_t h2 = h_[2] + ((load32(m + 6) >> 4) & 0x3ffffff);
    uint32_t h3 = h_[3] + ((load32(m + 9) >> 6) & 0x3ffffff);
    uint32_t h4 = h_[4] + ((load32(m + 12) >> 8) | hibit);

    const uint64_t d0 =
        static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4 +
        static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 +
        static_cast<uint64_t>(h4) * s1;
    uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0 +
                  static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 +
                  static_cast<uint64_t>(h4) * s2;
    uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1 +
                  static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 +
                  static_cast<uint64_t>(h4) * s3;
    uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2 +
                  static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 +
                  static_cast<uint64_t>(h4) * s4;
    uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3 +
                  static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 +
                  static_cast<uint64_t>(h4) * r0;

    uint32_t c = static_cast<uint32_t>(d0 >> 26);
    h0 = static_cast<uint32_t>(d0) & 0x3ffffff;
    d1 += c; c = static_cast<uint32_t>(d1 >> 26); h1 = static_cast<uint32_t>(d1) & 0x3ffffff;
    d2 += c; c = static_cast<uint32_t>(d2 >> 26); h2 = static_cast<uint32_t>(d2) & 0x3ffffff;
    d3 += c; c = static_cast<uint32_t>(d3 >> 26); h3 = static_cast<uint32_t>(d3) & 0x3ffffff;
    d4 += c; c = static_cast<uint32_t>(d4 >> 26); h4 = static_cast<uint32_t>(d4) & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    h_[0] = h0;
    h_[1] = h1;
    h_[2] = h2;
    h_[3] = h3;
    h_[4] = h4;
}

void Poly1305::update(const uint8_t* data, size_t len) {
    if (left_ != 0) {
        const size_t want = 16 - left_;
        const size_t take = (len < want) ? len : want;
        for (size_t i = 0; i < take; ++i) buf_[left_ + i] = data[i];
        left_ += take;
        data += take;
        len -= take;
        if (left_ < 16) return;
        block(buf_, 1u << 24);
        left_ = 0;
    }
    while (len >= 16) {
        block(data, 1u << 24);
        data += 16;
        len -= 16;
    }
    for (size_t i = 0; i < len; ++i) buf_[i] = data[i];
    left_ = len;
}

Tag16 Poly1305::finalize() {
    uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];

    if (left_ != 0) {
        buf_[left_++] = 1;
        while (left_ < 16) buf_[left_++] = 0;
        block(buf_, 0);
        h0 = h_[0]; h1 = h_[1]; h2 = h_[2]; h3 = h_[3]; h4 = h_[4];
    }

    // 完全进位
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    // h + (-p)，若 h >= p 则取它
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;  // g4 的符号位：>=0 则 mask = 0xffffffff
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // 把 5×26 位打包成 4 个 32 位字（丢 h4 的高 2 位，因为取模 2^128）
    const uint64_t w0 = static_cast<uint64_t>(h0) | (static_cast<uint64_t>(h1) << 26);
    const uint64_t w1 = static_cast<uint64_t>(h1 >> 6) | (static_cast<uint64_t>(h2) << 20);
    const uint64_t w2 = static_cast<uint64_t>(h2 >> 12) | (static_cast<uint64_t>(h3) << 14);
    const uint64_t w3 = static_cast<uint64_t>(h3 >> 18) | (static_cast<uint64_t>(h4) << 8);

    // h += s（模 2^128）
    uint64_t f = (w0 & 0xffffffffu) + pad_[0];
    const uint32_t o0 = static_cast<uint32_t>(f);
    f = (w1 & 0xffffffffu) + pad_[1] + (f >> 32);
    const uint32_t o1 = static_cast<uint32_t>(f);
    f = (w2 & 0xffffffffu) + pad_[2] + (f >> 32);
    const uint32_t o2 = static_cast<uint32_t>(f);
    f = (w3 & 0xffffffffu) + pad_[3] + (f >> 32);
    const uint32_t o3 = static_cast<uint32_t>(f);

    Tag16 tag{};
    store32(tag.data() + 0, o0);
    store32(tag.data() + 4, o1);
    store32(tag.data() + 8, o2);
    store32(tag.data() + 12, o3);

    h_[0] = h0; h_[1] = h1; h_[2] = h2; h_[3] = h3; h_[4] = h4;
    left_ = 0;
    return tag;
}

Tag16 poly1305(const Key32& key, const uint8_t* msg, size_t len) {
    Poly1305 p(key);
    p.update(msg, len);
    return p.finalize();
}

}  // namespace hxv4::crypto
