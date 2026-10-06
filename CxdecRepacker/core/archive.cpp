#include "core/archive.h"

#include "crypto/aead.h"

#include <zlib.h>

namespace hxv4 {
namespace {

inline uint32_t load32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

bool read_hxv4_mapping(const uint8_t* xp3, size_t len, const Hxv4Keys& keys,
                       Hxv4MappingBlob& out) {
    std::vector<uint8_t> index_tree;
    if (!read_xp3(xp3, len, out.header, index_tree)) return false;
    if (!find_hxv4(index_tree, out.descriptor)) return false;

    const uint64_t payload_off = out.descriptor.payload_offset;
    const uint64_t payload_len = out.descriptor.payload_size;
    if (payload_len <= 16 || payload_off + payload_len > len) return false;

    const crypto::Nonce24 nonce =
        out.descriptor.open_flag() == 0 ? keys.nonce0 : keys.nonce1;

    std::vector<uint8_t> plain;
    if (!crypto::xchacha20poly1305_open(keys.root_key, nonce, xp3 + payload_off,
                                        static_cast<size_t>(payload_len), plain)) {
        return false;
    }
    if (plain.size() < 4) return false;

    const uint32_t declared = load32le(plain.data());
    if (declared == 0 || declared > (1u << 28)) return false;

    out.tjs_bytes.assign(declared, 0);
    uLongf dest_len = static_cast<uLongf>(declared);
    const int rc = uncompress(out.tjs_bytes.data(), &dest_len, plain.data() + 4,
                              static_cast<uLong>(plain.size() - 4));
    if (rc != Z_OK || dest_len != declared) return false;

    return mapping_parse(out.tjs_bytes.data(), out.tjs_bytes.size(), out.table);
}

}  // namespace hxv4
