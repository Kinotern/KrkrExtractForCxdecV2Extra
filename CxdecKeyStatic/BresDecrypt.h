#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Crypto {

// bres:// 解密：key/nonce/counter 由 SHA3-384(path + salt) 派生，ChaCha8 异或

struct BresKeyMaterial {
    uint8_t key[32];
    uint8_t nonce[8];
    uint32_t counter_low;   // starting block counter
    uint32_t counter_high;  // high word (always 0 for bres, stored for reference)
};

// 从bres路径和salt派生密钥材料。
// salt: 从游戏EXE中恢复的变长salt字节
BresKeyMaterial bres_derive_key(const uint8_t* path_utf16le, size_t path_len,
                                const uint8_t* salt, size_t salt_len);

// 解密bres加密的资源。密文和明文不能重叠。
// 错误时返回false（例如无效大小）。
bool bres_decrypt(const uint8_t* path_utf16le, size_t path_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext);

// 便捷函数：path为wstring（Windows上UTF-16LE）
BresKeyMaterial bres_derive_key(const std::wstring& path, const uint8_t* salt, size_t salt_len);
bool bres_decrypt(const std::wstring& path, const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext);

} // namespace Crypto
