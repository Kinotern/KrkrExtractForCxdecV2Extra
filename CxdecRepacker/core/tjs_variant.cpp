#include "core/tjs_variant.h"

#include <cstring>

namespace hxv4 {
namespace {

constexpr int kMaxDepth = 64;

// 标签常量
constexpr uint8_t kTagNull = 1;
constexpr uint8_t kTagString = 2;
constexpr uint8_t kTagOctet = 3;
constexpr uint8_t kTagInt = 4;
constexpr uint8_t kTagReal = 5;
constexpr int8_t kTagArray = -127;  // 0x81
constexpr int8_t kTagDict = -63;    // 0xC1

class Cursor {
public:
    Cursor(const uint8_t* data, size_t len) : data_(data), len_(len) {}

    bool take(size_t n, const uint8_t** out) {
        if (pos_ + n > len_) return false;
        *out = data_ + pos_;
        pos_ += n;
        return true;
    }

    bool byte(uint8_t& out) {
        const uint8_t* p;
        if (!take(1, &p)) return false;
        out = p[0];
        return true;
    }

    bool i32(int32_t& out) {
        const uint8_t* p;
        if (!take(4, &p)) return false;
        out = static_cast<int32_t>((static_cast<uint32_t>(p[0]) << 24) |
                                   (static_cast<uint32_t>(p[1]) << 16) |
                                   (static_cast<uint32_t>(p[2]) << 8) |
                                   static_cast<uint32_t>(p[3]));
        return true;
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
};

std::string utf16be_to_utf8(const uint8_t* p, size_t units) {
    std::string out;
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = static_cast<uint32_t>(p[2 * i] << 8) | p[2 * i + 1];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units) {
            const uint32_t lo = static_cast<uint32_t>(p[2 * i + 2] << 8) | p[2 * i + 3];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

bool parse_value(Cursor& c, TjsValue& v, int depth) {
    if (depth > kMaxDepth) return false;

    uint8_t tag;
    if (!c.byte(tag)) return false;
    const int8_t signed_tag = static_cast<int8_t>(tag);

    if (signed_tag == 0 || signed_tag == kTagNull) {
        v.type = TjsType::Null;
        return true;
    }
    if (signed_tag == kTagString) {
        int32_t units;
        if (!c.i32(units) || units < 0) return false;
        const uint8_t* p;
        if (!c.take(static_cast<size_t>(units) * 2, &p)) return false;
        v.type = TjsType::String;
        v.str = utf16be_to_utf8(p, static_cast<size_t>(units));
        return true;
    }
    if (signed_tag == kTagOctet) {
        int32_t size;
        if (!c.i32(size) || size < 0) return false;
        const uint8_t* p;
        if (!c.take(static_cast<size_t>(size), &p)) return false;
        v.type = TjsType::Octet;
        v.octet.assign(p, p + size);
        return true;
    }
    if (signed_tag == kTagInt) {
        const uint8_t* p;
        if (!c.take(8, &p)) return false;
        uint64_t raw = 0;
        for (int i = 0; i < 8; ++i) raw |= static_cast<uint64_t>(p[i]) << (8 * (7 - i));
        v.type = TjsType::Int;
        v.integer = static_cast<int64_t>(raw);
        return true;
    }
    if (signed_tag == kTagReal) {
        const uint8_t* p;
        if (!c.take(8, &p)) return false;
        uint64_t raw = 0;
        for (int i = 0; i < 8; ++i) raw |= static_cast<uint64_t>(p[i]) << (8 * (7 - i));
        double d;
        static_assert(sizeof(d) == sizeof(raw), "double 必须是 8 字节");
        std::memcpy(&d, &raw, sizeof(d));
        v.type = TjsType::Real;
        v.real = d;
        return true;
    }
    if (signed_tag == kTagArray) {
        int32_t count;
        if (!c.i32(count) || count < 0) return false;
        v.type = TjsType::Array;
        v.array.clear();
        v.array.reserve(static_cast<size_t>(count));
        for (int32_t i = 0; i < count; ++i) {
            TjsValue item;
            if (!parse_value(c, item, depth + 1)) return false;
            v.array.push_back(std::move(item));
        }
        return true;
    }
    if (signed_tag == kTagDict) {
        int32_t count;
        if (!c.i32(count) || count < 0) return false;
        v.type = TjsType::Dict;
        v.dict.clear();
        for (int32_t i = 0; i < count; ++i) {
            TjsValue k;
            if (!parse_value(c, k, depth + 1)) return false;
            if (k.type != TjsType::String) return false;
            TjsValue val;
            if (!parse_value(c, val, depth + 1)) return false;
            v.dict.emplace_back(std::move(k.str), std::move(val));
        }
        return true;
    }
    return false;
}

void put_i32(std::vector<uint8_t>& out, int32_t v) {
    const uint32_t u = static_cast<uint32_t>(v);
    out.push_back(static_cast<uint8_t>(u >> 24));
    out.push_back(static_cast<uint8_t>(u >> 16));
    out.push_back(static_cast<uint8_t>(u >> 8));
    out.push_back(static_cast<uint8_t>(u));
}

void put_i64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void utf8_to_utf16be(const std::string& s, std::vector<uint8_t>& out) {
    size_t i = 0;
    while (i < s.size()) {
        uint32_t cp = static_cast<uint8_t>(s[i]);
        size_t extra = 0;
        if (cp >= 0xF0) {
            cp &= 0x07;
            extra = 3;
        } else if (cp >= 0xE0) {
            cp &= 0x0F;
            extra = 2;
        } else if (cp >= 0xC0) {
            cp &= 0x1F;
            extra = 1;
        }
        ++i;
        for (size_t k = 0; k < extra && i < s.size(); ++k, ++i) {
            cp = (cp << 6) | (static_cast<uint8_t>(s[i]) & 0x3F);
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            const uint16_t hi = static_cast<uint16_t>(0xD800 + (cp >> 10));
            const uint16_t lo = static_cast<uint16_t>(0xDC00 + (cp & 0x3FF));
            out.push_back(static_cast<uint8_t>(hi >> 8));
            out.push_back(static_cast<uint8_t>(hi));
            out.push_back(static_cast<uint8_t>(lo >> 8));
            out.push_back(static_cast<uint8_t>(lo));
        } else {
            out.push_back(static_cast<uint8_t>(cp >> 8));
            out.push_back(static_cast<uint8_t>(cp));
        }
    }
}

void serialize_value(const TjsValue& v, std::vector<uint8_t>& out) {
    switch (v.type) {
        case TjsType::Null:
            out.push_back(kTagNull);
            break;
        case TjsType::String: {
            std::vector<uint8_t> units;
            utf8_to_utf16be(v.str, units);
            out.push_back(kTagString);
            put_i32(out, static_cast<int32_t>(units.size() / 2));
            out.insert(out.end(), units.begin(), units.end());
            break;
        }
        case TjsType::Octet:
            out.push_back(kTagOctet);
            put_i32(out, static_cast<int32_t>(v.octet.size()));
            out.insert(out.end(), v.octet.begin(), v.octet.end());
            break;
        case TjsType::Int:
            out.push_back(kTagInt);
            put_i64(out, static_cast<uint64_t>(v.integer));
            break;
        case TjsType::Real: {
            uint64_t raw;
            static_assert(sizeof(raw) == sizeof(v.real), "double 必须是 8 字节");
            std::memcpy(&raw, &v.real, sizeof(raw));
            out.push_back(kTagReal);
            put_i64(out, raw);
            break;
        }
        case TjsType::Array:
            out.push_back(static_cast<uint8_t>(kTagArray));
            put_i32(out, static_cast<int32_t>(v.array.size()));
            for (const TjsValue& item : v.array) serialize_value(item, out);
            break;
        case TjsType::Dict:
            out.push_back(static_cast<uint8_t>(kTagDict));
            put_i32(out, static_cast<int32_t>(v.dict.size()));
            for (const auto& kv : v.dict) {
                TjsValue k;
                k.type = TjsType::String;
                k.str = kv.first;
                serialize_value(k, out);
                serialize_value(kv.second, out);
            }
            break;
    }
}

}  // namespace

bool tjs_parse(const uint8_t* data, size_t len, TjsValue& out) {
    Cursor c(data, len);
    return parse_value(c, out, 0);
}

std::vector<uint8_t> tjs_serialize(const TjsValue& value) {
    std::vector<uint8_t> out;
    serialize_value(value, out);
    return out;
}

}  // namespace hxv4
