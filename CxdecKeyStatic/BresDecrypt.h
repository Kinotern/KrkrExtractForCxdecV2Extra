#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Crypto {

/// @brief bres:// 资源解密（Kirikiri引擎）。
//
/// 加密链：
//   1. SHA3-384(path_utf16le + 32_byte_salt) 鈫?48-byte digest
///   2. key=digest[0:32], nonce=digest[32:40], counter=digest[40:48]
//   3. ChaCha8(key, nonce, counter) 鈯?ciphertext 鈫?plaintext

struct BresKeyMaterial {
    uint8_t key[32];
    uint8_t nonce[8];
    uint32_t counter_low;   // starting block counter
    uint32_t counter_high;  // high word (always 0 for bres, stored for reference)
};

/// 从bres路径和salt派生密钥材料。
/// @param salt 从游戏EXE中恢复的变长salt字节
BresKeyMaterial bres_derive_key(const uint8_t* path_utf16le, size_t path_len,
                                const uint8_t* salt, size_t salt_len);

/// 解密bres加密的资源。密文和明文不能重叠。
/// 错误时返回false（例如无效大小）。
bool bres_decrypt(const uint8_t* path_utf16le, size_t path_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext);

/// 便捷函数：path为wstring（Windows上UTF-16LE）
BresKeyMaterial bres_derive_key(const std::wstring& path, const uint8_t* salt, size_t salt_len);
bool bres_decrypt(const std::wstring& path, const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext);

} // namespace Crypto
