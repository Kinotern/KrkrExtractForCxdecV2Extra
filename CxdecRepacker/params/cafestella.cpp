#include "params/cafestella.h"

#include "crypto/aead.h"
#include "crypto/chacha.h"

#include <cstring>

namespace hxv4::params::cafestella {
namespace {

void parse_hex(std::string_view hex, uint8_t* out, size_t out_len) {
    size_t n = 0;
    int hi = -1;
    for (const char c : hex) {
        int v;
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        } else {
            continue;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n < out_len) out[n++] = static_cast<uint8_t>((hi << 4) | v);
            hi = -1;
        }
    }
}

hxv4::crypto::Key32 key32(std::string_view hex) {
    hxv4::crypto::Key32 k{};
    parse_hex(hex, k.data(), k.size());
    return k;
}

hxv4::crypto::Nonce24 nonce24(std::string_view hex) {
    hxv4::crypto::Nonce24 n{};
    parse_hex(hex, n.data(), n.size());
    return n;
}

}  // namespace

IndexKey index_key(uint16_t open_flag) {
    const auto root = key32(kHxv4Key);
    const auto nonce = nonce24((open_flag & 1) != 0 ? kHxv4Nonce1 : kHxv4Nonce0);

    hxv4::crypto::Key32 subkey{}, poly_key{};
    hxv4::crypto::xchacha_subkeys(root, nonce, subkey, poly_key);

    IndexKey out;
    out.key = subkey;
    out.verify = poly_key;
    // 内层 nonce8 = nonce[16:24]；后 8 字节工具不读，填 0
    for (size_t i = 0; i < 8; ++i) out.nonce[i] = nonce[16 + i];
    return out;
}

uint64_t filder_key(uint16_t open_flag) {
    // 运行时只在 open_flag 的 bit0 为 0 时扰动 key
    if ((open_flag & 1) != 0) return 0;
    return static_cast<uint64_t>(kHolderWords[2]) |
           (static_cast<uint64_t>(kHolderWords[3]) << 32);
}

const hxv4::DripProgram& drip_program() {
    static const hxv4::DripProgram program = [] {
        std::vector<uint32_t> holder(std::begin(kHolderWords), std::end(kHolderWords));

        // 查表：4096 字节按小端还原成 1024 个 dword
        const uint8_t* table = cxdec_table();
        std::vector<uint32_t> context(kCxdecTableSize / 4);
        for (size_t i = 0; i < context.size(); ++i) {
            context[i] = static_cast<uint32_t>(table[4 * i]) |
                         (static_cast<uint32_t>(table[4 * i + 1]) << 8) |
                         (static_cast<uint32_t>(table[4 * i + 2]) << 16) |
                         (static_cast<uint32_t>(table[4 * i + 3]) << 24);
        }

        const uint32_t* counts = lane_record_counts();
        const uint32_t* flat = lane_records();
        std::vector<std::vector<hxv4::DripRecord>> lanes;
        lanes.reserve(kLaneCount);
        size_t at = 0;
        for (size_t i = 0; i < kLaneCount; ++i) {
            std::vector<hxv4::DripRecord> lane;
            lane.reserve(counts[i]);
            for (uint32_t k = 0; k < counts[i]; ++k) {
                lane.push_back(hxv4::DripRecord{flat[2 * at], flat[2 * at + 1]});
                ++at;
            }
            lanes.push_back(std::move(lane));
        }
        return hxv4::DripProgram(std::move(holder), std::move(context), std::move(lanes));
    }();
    return program;
}

}  // namespace hxv4::params::cafestella
