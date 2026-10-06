#pragma once

#include "crypto/types.h"

namespace hxv4::crypto {

// 生成 64 字节密钥流块。
//
// 状态布局是 **DJB 原版**：word0..3 = sigma、word4..11 = key、
// word12..13 = 64 位计数器、word14..15 = 64 位 nonce。
// 不是 RFC 8439 的 IETF 布局（32 位计数器 + 96 位 nonce）。
//
// hxv4 的索引层用的就是这个布局——它就是 XChaCha20 做完 HChaCha20 之后的内层。
Block64 chacha20_block(const Key32& key, uint64_t counter, const Nonce8& nonce);

// 从 counter 开始，就地 XOR（加解密同一操作）。
void chacha20_xor(const Key32& key, uint64_t counter, const Nonce8& nonce, uint8_t* data,
                  size_t len);

// HChaCha20：吃 16 字节 nonce，吐 32 字节子密钥（无 feed-forward）。
Key32 hchacha20(const Key32& key, const Nonce16& nonce);

}  // namespace hxv4::crypto
