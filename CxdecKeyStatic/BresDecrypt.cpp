#include "BresDecrypt.h"
#include "Crypto/Keccak.h"
#include "Crypto/ChaCha.h"
#include <cstring>
#include <algorithm>

namespace Crypto {

BresKeyMaterial bres_derive_key(const uint8_t* path_utf16le, size_t path_len,
                                const uint8_t* salt, size_t salt_len) {
    BresKeyMaterial mat{};

    // SHA3-384(path_utf16le + salt)
    uint8_t digest[SHA3_384::DIGEST_SIZE];
    SHA3_384 hasher;
    hasher.update(path_utf16le, path_len);
    hasher.update(salt, salt_len);
    hasher.finalize(digest);

    std::memcpy(mat.key, digest, 32);
    std::memcpy(mat.nonce, digest + 32, 8);

    // counter以两个小端uint32格式存储
    mat.counter_low  = (uint32_t)digest[40]
                    | ((uint32_t)digest[41] << 8)
                    | ((uint32_t)digest[42] << 16)
                    | ((uint32_t)digest[43] << 24);
    mat.counter_high = (uint32_t)digest[44]
                    | ((uint32_t)digest[45] << 8)
                    | ((uint32_t)digest[46] << 16)
                    | ((uint32_t)digest[47] << 24);

    return mat;
}

BresKeyMaterial bres_derive_key(const std::wstring& path, const uint8_t* salt, size_t salt_len) {
    return bres_derive_key(
        reinterpret_cast<const uint8_t*>(path.data()),
        path.size() * sizeof(wchar_t),
        salt, salt_len);
}

bool bres_decrypt(const uint8_t* path_utf16le, size_t path_len,
                  const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext) {
    if (!ciphertext || ct_len == 0) return false;

    auto mat = bres_derive_key(path_utf16le, path_len, salt, salt_len);

    plaintext.resize(ct_len);
    std::memcpy(plaintext.data(), ciphertext, ct_len);

    chacha8_xor(mat.key, mat.nonce, mat.counter_low, mat.counter_high,
                plaintext.data(), ct_len);
    return true;
}

bool bres_decrypt(const std::wstring& path, const uint8_t* salt, size_t salt_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  std::vector<uint8_t>& plaintext) {
    return bres_decrypt(
        reinterpret_cast<const uint8_t*>(path.data()),
        path.size() * sizeof(wchar_t),
        salt, salt_len, ciphertext, ct_len, plaintext);
}

} // namespace Crypto
