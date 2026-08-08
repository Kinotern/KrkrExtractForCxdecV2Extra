#include "pch.h"
#include "CryptoUtil.h"

namespace PackUtil {

static uint32_t XorDecodeImpl(uint8_t* data, size_t size, uint32_t key)
{
    size_t x = 0;
    if (key == 0) {
        if (size < 4) return 0;
        key = *reinterpret_cast<uint32_t*>(data);
        x = 4;
    }
    for (; x + 4 <= size; x += 4) {
        uint32_t val = *reinterpret_cast<uint32_t*>(data + x);
        uint32_t tmp = val;
        val ^= key;
        key = tmp;
        *reinterpret_cast<uint32_t*>(data + x) = val;
    }
    return key;
}

uint32_t XorDecodeChained(uint8_t* data, size_t size, uint32_t xorKey)
{
    return XorDecodeImpl(data, size, xorKey);
}

bool AesDecrypt(const uint8_t* cipherData, size_t cipherSize,
                const uint8_t* key, size_t keySize,
                const uint8_t* iv, size_t ivSize,
                std::vector<uint8_t>& outPlainData)
{
    if (!cipherData || !key || !iv || cipherSize == 0)
        return false;
    if (cipherSize % 16 != 0)
        return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG resultSize = 0;
    bool success = false;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) goto cleanup;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CBC) - sizeof(wchar_t)), 0);
    if (status < 0) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                        const_cast<PUCHAR>(key), static_cast<ULONG>(keySize), 0);
    if (status < 0) goto cleanup;

    outPlainData.resize(cipherSize);
    status = BCryptDecrypt(hKey,
                           const_cast<PUCHAR>(cipherData), static_cast<ULONG>(cipherSize),
                           nullptr,
                           const_cast<PUCHAR>(iv), static_cast<ULONG>(ivSize),
                           outPlainData.data(), static_cast<ULONG>(outPlainData.size()),
                           &resultSize, 0);

    if (status >= 0) {
        outPlainData.resize(resultSize);
        success = true;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

static void XteaDecryptBlock(uint32_t v[2], const uint32_t k[4])
{
    const uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

void XteaDecrypt(uint8_t* data, size_t size, const uint32_t* key)
{
    if (!data || !key || size < 8) return;
    for (size_t x = 0; x + 8 <= size; x += 8) {
        uint32_t block[2];
        block[0] = *reinterpret_cast<uint32_t*>(data + x);
        block[1] = *reinterpret_cast<uint32_t*>(data + x + 4);
        XteaDecryptBlock(block, key);
        *reinterpret_cast<uint32_t*>(data + x)     = block[0];
        *reinterpret_cast<uint32_t*>(data + x + 4) = block[1];
    }
}

} // namespace PackUtil
