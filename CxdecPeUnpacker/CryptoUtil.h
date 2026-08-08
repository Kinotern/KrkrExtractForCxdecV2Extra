#pragma once

namespace PackUtil {
    // XorDecodeChained 返回链式 XOR 解码后的最终密钥值
    uint32_t XorDecodeChained(uint8_t* data, size_t size, uint32_t xorKey);

    // AES-256-CBC 解密
    bool AesDecrypt(const uint8_t* cipherData, size_t cipherSize,
                    const uint8_t* key, size_t keySize,
                    const uint8_t* iv, size_t ivSize,
                    std::vector<uint8_t>& outPlainData);

    // XTEA 解密，用于平台驱动载荷
    void XteaDecrypt(uint8_t* data, size_t size, const uint32_t* key);
}
