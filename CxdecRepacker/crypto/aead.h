#pragma once

#include "crypto/types.h"

#include <cstddef>
#include <vector>

namespace hxv4::crypto {

// XChaCha20-Poly1305，内层用 DJB 布局（64 位计数器 + 64 位 nonce）。
// 密文从计数器 1 起，Poly1305 密钥取计数器 0 —— 与 hxv4 的 Hxv4 映射表负载一致。
//
// seal 返回 [16 字节 tag][密文]；open 接受同样格式，tag 不过返回 false。
std::vector<uint8_t> xchacha20poly1305_seal(const Key32& key, const Nonce24& nonce,
                                            const uint8_t* plaintext, size_t len);

bool xchacha20poly1305_open(const Key32& key, const Nonce24& nonce, const uint8_t* sealed,
                            size_t len, std::vector<uint8_t>& out);

// HxCryptTool 参数映射用：把 XChaCha20 的子密钥与 Poly1305 密钥单独取出来。
//   --index-key    = subkey
//   --index-verify = poly_key
void xchacha_subkeys(const Key32& key, const Nonce24& nonce, Key32& subkey, Key32& poly_key);

}  // namespace hxv4::crypto
