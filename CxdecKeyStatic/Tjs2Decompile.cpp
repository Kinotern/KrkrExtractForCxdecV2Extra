#include "Tjs2Decompile.h"
#include <cstring>
#include <algorithm>

namespace Tjs2 {

static uint32_t read_u32(const uint8_t* data, size_t& offset, size_t len) {
    if (offset + 4 > len) return 0;
    uint32_t v = (uint32_t)data[offset]
              | ((uint32_t)data[offset + 1] << 8)
              | ((uint32_t)data[offset + 2] << 16)
              | ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return v;
}

static inline size_t align4(size_t v) { return (v + 3) & ~3; }

static std::string utf16le_to_utf8(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint32_t cp = (uint32_t)data[i] | ((uint32_t)data[i + 1] << 8);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < len) {
            uint32_t lo = (uint32_t)data[i + 2] | ((uint32_t)data[i + 3] << 8);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        if (cp < 0x80)
            out += (char)cp;
        else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

static void parse_data_chunk(const uint8_t* data, size_t body_len,
                             std::vector<std::string>& strings) {
    // TJS2 DATA chunk解析（按TJS2语法规范）：
    // bytecode_literals（1字节单位）+ align4
    // shorts（2字节单位）+ align4
    // ints（4字节单位）+ align4
    // int64s（8字节单位）+ align4
    // reals_raw（8字节单位）+ align4
    // strings（每个：u32长度, len*2字节UTF-16LE, align4）
    // octets（每个：u32长度, len字节, align4）

    size_t off = 0;

    auto skip_pool = [&](int unit) {
        uint32_t count = read_u32(data, off, body_len);
        size_t raw = (size_t)count * unit;
        if (off + raw > body_len) { off = body_len; return; }
        off += align4(raw);
    };

    if (off + 4 > body_len) return;
    skip_pool(1);   // bytecode_literals
    skip_pool(2);   // shorts
    skip_pool(4);   // ints
    skip_pool(8);   // int64s
    skip_pool(8);   // reals_raw

    // 字符串池
    if (off + 4 > body_len) return;
    uint32_t str_cnt = read_u32(data, off, body_len);
    strings.reserve(str_cnt);
    for (uint32_t i = 0; i < str_cnt; ++i) {
        if (off + 4 > body_len) break;
        uint32_t slen = read_u32(data, off, body_len);
        size_t raw = (size_t)slen * 2;
        if (off + raw > body_len) break;
        strings.push_back(utf16le_to_utf8(data + off, raw));
        off += align4(raw);
    }
}

static bool find_chunk(const uint8_t* data, size_t len,
                       const char tag[4],
                       size_t& body_offset, size_t& body_size) {
    size_t offset = 12;  // skip "TJS2100\0" (8) + declared_size (4)
    while (offset + 8 <= len) {
        char current_tag[5] = {};
        std::memcpy(current_tag, data + offset, 4);
        offset += 4;
        uint32_t size = 0;
        size = (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8)
             | ((uint32_t)data[offset + 2] << 16) | ((uint32_t)data[offset + 3] << 24);
        if (size < 8) return false;
        if (offset + size > len + 4) return false;
        body_offset = offset - 4;
        body_size = size;
        if (std::memcmp(current_tag, tag, 4) == 0) return true;
        offset += size - 4;
    }
    return false;
}

StringsResult extract_strings(const uint8_t* data, size_t len) {
    StringsResult result;
    result.ok = false;

    if (len < 12) return result;
    if (std::memcmp(data, "TJS2100\x00", 8) != 0) return result;

    size_t body_off, body_sz;
    if (!find_chunk(data, len, "DATA", body_off, body_sz))
        return result;

    // body_off指向tag开始，body_sz为完整chunk大小（含tag+size头部）
    // body起始于body_off+8, body_len=body_sz-8
    if (body_sz < 8) return result;
    const uint8_t* body = data + body_off + 8;
    size_t body_len = body_sz - 8;

    parse_data_chunk(body, body_len, result.strings);
    result.ok = true;
    return result;
}

std::string find_bootstrap_url(const std::vector<std::string>& strings) {
    for (const auto& s : strings) {
        if (s.find("bootstrap") == std::string::npos) continue;
        if (s.size() > 4 && (s[0] == 'b' || s[0] == 'B'))
            return s;
    }
    for (const auto& s : strings) {
        if (s.find("bootstrap") != std::string::npos)
            return s;
    }
    return {};
}

std::string find_bootstrap_prefix(const std::vector<std::string>& strings) {
    std::vector<size_t> candidates;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (strings[i].find("all") != std::string::npos)
            candidates.push_back(i);
    }

    std::string best;
    for (auto idx : candidates) {
        const auto& s = strings[idx];
        if (s.find("right") != std::string::npos ||
            s.find("reserved") != std::string::npos ||
            s.find("left") != std::string::npos) {
            if (best.empty() || s.size() > best.size())
                best = s;
        }
    }

    if (best.empty()) {
        for (auto idx : candidates) {
            if (strings[idx].size() > best.size())
                best = strings[idx];
        }
    }

    return best;
}

} // namespace Tjs2
