#include "crypto/blake2s.h"

#include <cstring>

namespace hxv4::crypto {
namespace {

// BLAKE2s 复用 SHA-256 的 IV
constexpr uint32_t kIV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                             0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};

constexpr uint8_t kSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline uint32_t rotr(uint32_t v, int c) { return (v >> c) | (v << (32 - c)); }

inline uint32_t load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline void g(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y) {
    v[a] += v[b] + x;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = rotr(v[b] ^ v[c], 12);
    v[a] += v[b] + y;
    v[d] = rotr(v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b] = rotr(v[b] ^ v[c], 7);
}

}  // namespace

Blake2s::Blake2s(size_t out_len, const uint8_t* key, size_t key_len)
    : buf_len_(0), out_len_(out_len) {
    for (int i = 0; i < 8; ++i) h_[i] = kIV[i];
    // 参数块 word0 = digest_len | key_len<<8 | fanout<<16 | depth<<24
    h_[0] ^= 0x01010000u ^ (static_cast<uint32_t>(key_len) << 8) ^
             static_cast<uint32_t>(out_len);
    t_[0] = 0;
    t_[1] = 0;
    if (key_len != 0) {
        std::memset(buf_, 0, sizeof(buf_));
        std::memcpy(buf_, key, key_len);
        buf_len_ = sizeof(buf_);
    }
}

void Blake2s::compress(const uint8_t block[64], bool last) {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = load32(block + 4 * i);

    uint32_t v[16];
    for (int i = 0; i < 8; ++i) v[i] = h_[i];
    for (int i = 0; i < 8; ++i) v[8 + i] = kIV[i];
    v[12] ^= t_[0];
    v[13] ^= t_[1];
    if (last) v[14] = ~v[14];

    for (int r = 0; r < 10; ++r) {
        g(v, 0, 4, 8, 12, m[kSigma[r][0]], m[kSigma[r][1]]);
        g(v, 1, 5, 9, 13, m[kSigma[r][2]], m[kSigma[r][3]]);
        g(v, 2, 6, 10, 14, m[kSigma[r][4]], m[kSigma[r][5]]);
        g(v, 3, 7, 11, 15, m[kSigma[r][6]], m[kSigma[r][7]]);
        g(v, 0, 5, 10, 15, m[kSigma[r][8]], m[kSigma[r][9]]);
        g(v, 1, 6, 11, 12, m[kSigma[r][10]], m[kSigma[r][11]]);
        g(v, 2, 7, 8, 13, m[kSigma[r][12]], m[kSigma[r][13]]);
        g(v, 3, 4, 9, 14, m[kSigma[r][14]], m[kSigma[r][15]]);
    }

    for (int i = 0; i < 8; ++i) h_[i] ^= v[i] ^ v[i + 8];
}

void Blake2s::update(const uint8_t* data, size_t len) {
    while (len > 0) {
        if (buf_len_ == sizeof(buf_)) {
            t_[0] += 64;
            if (t_[0] < 64) ++t_[1];
            compress(buf_, false);
            buf_len_ = 0;
        }
        size_t take = sizeof(buf_) - buf_len_;
        if (take > len) take = len;
        std::memcpy(buf_ + buf_len_, data, take);
        buf_len_ += take;
        data += take;
        len -= take;
    }
}

void Blake2s::finalize(uint8_t* out) {
    t_[0] += static_cast<uint32_t>(buf_len_);
    if (t_[0] < buf_len_) ++t_[1];
    std::memset(buf_ + buf_len_, 0, sizeof(buf_) - buf_len_);
    compress(buf_, true);
    for (size_t i = 0; i < out_len_; ++i) {
        out[i] = static_cast<uint8_t>(h_[i / 4] >> (8 * (i % 4)));
    }
}

void blake2s256(const uint8_t* data, size_t len, uint8_t out[32]) {
    Blake2s b(32);
    b.update(data, len);
    b.finalize(out);
}

}  // namespace hxv4::crypto
