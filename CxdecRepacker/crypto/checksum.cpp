#include "crypto/checksum.h"

namespace hxv4::crypto {
namespace {

constexpr uint32_t kAdlerMod = 65521;

uint32_t* crc_table() {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        ready = true;
    }
    return table;
}

}  // namespace

uint32_t adler32(const uint8_t* data, size_t len, uint32_t init) {
    uint32_t a = init & 0xFFFF;
    uint32_t b = (init >> 16) & 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        a = (a + data[i]) % kAdlerMod;
        b = (b + a) % kAdlerMod;
    }
    return (b << 16) | a;
}

uint32_t crc32(const uint8_t* data, size_t len, uint32_t init) {
    const uint32_t* table = crc_table();
    uint32_t c = init ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

}  // namespace hxv4::crypto
