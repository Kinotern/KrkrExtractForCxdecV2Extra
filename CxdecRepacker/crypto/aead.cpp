#include "crypto/aead.h"

#include "crypto/chacha.h"
#include "crypto/poly1305.h"

#include <cstring>

namespace hxv4::crypto {
namespace {

Nonce16 hchacha_nonce(const Nonce24& n) {
    Nonce16 r{};
    std::memcpy(r.data(), n.data(), 16);
    return r;
}

Nonce8 inner_nonce(const Nonce24& n) {
    Nonce8 r{};
    std::memcpy(r.data(), n.data() + 16, 8);
    return r;
}

// mac = Poly1305(poly_key, 密文 ‖ 补零到 16 字节 ‖ LE64(0) ‖ LE64(密文长度))
Tag16 mac_of(const Key32& poly_key, const uint8_t* ct, size_t len) {
    Poly1305 p(poly_key);
    p.update(ct, len);
    static const uint8_t kZeros[16] = {};
    const size_t pad = (16 - (len % 16)) % 16;
    if (pad != 0) p.update(kZeros, pad);
    uint8_t len_block[16] = {};
    for (int i = 0; i < 8; ++i) {
        len_block[8 + i] = static_cast<uint8_t>(static_cast<uint64_t>(len) >> (8 * i));
    }
    p.update(len_block, sizeof(len_block));
    return p.finalize();
}

}  // namespace

void xchacha_subkeys(const Key32& key, const Nonce24& nonce, Key32& subkey, Key32& poly_key) {
    subkey = hchacha20(key, hchacha_nonce(nonce));
    const Block64 b = chacha20_block(subkey, 0, inner_nonce(nonce));
    std::memcpy(poly_key.data(), b.data(), poly_key.size());
}

std::vector<uint8_t> xchacha20poly1305_seal(const Key32& key, const Nonce24& nonce,
                                            const uint8_t* plaintext, size_t len) {
    Key32 subkey{}, poly_key{};
    xchacha_subkeys(key, nonce, subkey, poly_key);

    std::vector<uint8_t> out(16 + len);
    std::memcpy(out.data() + 16, plaintext, len);
    chacha20_xor(subkey, 1, inner_nonce(nonce), out.data() + 16, len);

    const Tag16 tag = mac_of(poly_key, out.data() + 16, len);
    std::memcpy(out.data(), tag.data(), tag.size());
    return out;
}

bool xchacha20poly1305_open(const Key32& key, const Nonce24& nonce, const uint8_t* sealed,
                            size_t len, std::vector<uint8_t>& out) {
    if (len < 16) return false;

    Key32 subkey{}, poly_key{};
    xchacha_subkeys(key, nonce, subkey, poly_key);

    const uint8_t* ct = sealed + 16;
    const size_t ct_len = len - 16;

    const Tag16 expect = mac_of(poly_key, ct, ct_len);
    uint8_t diff = 0;
    for (size_t i = 0; i < expect.size(); ++i) diff |= static_cast<uint8_t>(expect[i] ^ sealed[i]);
    if (diff != 0) return false;

    out.resize(ct_len);
    std::memcpy(out.data(), ct, ct_len);
    chacha20_xor(subkey, 1, inner_nonce(nonce), out.data(), ct_len);
    return true;
}

}  // namespace hxv4::crypto
