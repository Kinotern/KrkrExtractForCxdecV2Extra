#include "core/resource_hash.h"

#include "crypto/blake2s.h"
#include "crypto/siphash.h"

#include <string>
#include <vector>

namespace hxv4 {
namespace {

std::u16string with_media(std::u16string_view base) {
    std::u16string out(base);
    for (const char c : kMediaName) out.push_back(static_cast<char16_t>(c));
    return out;
}

std::vector<uint8_t> to_utf16le_bytes(std::u16string_view s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() * 2);
    for (const char16_t c : s) {
        out.push_back(static_cast<uint8_t>(c & 0xFF));
        out.push_back(static_cast<uint8_t>(c >> 8));
    }
    return out;
}

uint64_t bswap64(uint64_t v) {
    return ((v & 0x00000000000000FFULL) << 56) | ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x0000000000FF0000ULL) << 24) | ((v & 0x00000000FF000000ULL) << 8) |
           ((v & 0x000000FF00000000ULL) >> 8) | ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x00FF000000000000ULL) >> 40) | ((v & 0xFF00000000000000ULL) >> 56);
}

}  // namespace

Hash32 file_hash(std::u16string_view name) {
    const std::u16string msg = with_media(name);
    const std::vector<uint8_t> bytes = to_utf16le_bytes(msg);
    Hash32 out{};
    crypto::blake2s256(bytes.data(), bytes.size(), out.data());
    return out;
}

Hash32 file_hash_keyed(std::u16string_view name, const uint8_t key[32]) {
    const std::u16string msg = with_media(name);
    const std::vector<uint8_t> bytes = to_utf16le_bytes(msg);
    crypto::Blake2s b(32, key, 32);
    b.update(bytes.data(), bytes.size());
    Hash32 out{};
    b.finalize(out.data());
    return out;
}

uint64_t domain_hash(std::u16string_view path) {
    const bool is_root = path.empty() || path == u"/";
    const std::u16string msg = with_media(is_root ? std::u16string_view() : path);
    const std::vector<uint8_t> bytes = to_utf16le_bytes(msg);
    const uint8_t zero_key[16] = {};
    return bswap64(crypto::siphash24(bytes.data(), bytes.size(), zero_key));
}

}  // namespace hxv4
