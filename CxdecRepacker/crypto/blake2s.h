#pragma once

#include <cstddef>
#include <cstdint>

namespace hxv4::crypto {

// BLAKE2s（RFC 7693），默认 32 字节输出、无密钥。
//
// 支持可选密钥是为了 hxv4 的 keyed 变体：运行时若 `hash_key.key_len != 0`，
// `file_hash` 会变成用 `hash_key[0:32]` 作密钥的 keyed BLAKE2s。
// 当前样本是 `key_len == 0`（unkeyed），但接口留好。
class Blake2s {
public:
    explicit Blake2s(size_t out_len = 32, const uint8_t* key = nullptr, size_t key_len = 0);

    void update(const uint8_t* data, size_t len);
    void finalize(uint8_t* out);  // out 至少 out_len 字节

private:
    void compress(const uint8_t block[64], bool last);

    uint32_t h_[8];
    uint32_t t_[2];
    uint8_t buf_[64];
    size_t buf_len_;
    size_t out_len_;
};

// 一次性接口：无密钥 BLAKE2s-256。
void blake2s256(const uint8_t* data, size_t len, uint8_t out[32]);

}  // namespace hxv4::crypto
