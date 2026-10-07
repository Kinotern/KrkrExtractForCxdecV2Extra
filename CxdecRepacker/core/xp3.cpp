#include "core/xp3.h"

#include <zlib.h>

#include <cstring>

namespace hxv4 {
namespace {

inline uint32_t load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t load64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

inline void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

inline void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void chunk(std::vector<uint8_t>& out, const char tag[4], const std::vector<uint8_t>& body) {
    out.insert(out.end(), tag, tag + 4);
    put64(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
}

bool parse_file_chunk(const uint8_t* body, size_t size, Xp3Entry& entry) {
    size_t q = 0;
    while (q + 12 <= size) {
        const uint8_t* p = body + q;
        const uint64_t sub_size = load64(p + 4);
        const size_t sub_body = q + 12;
        if (sub_body + sub_size > size) return false;

        if (std::memcmp(p, "adlr", 4) == 0) {
            if (sub_size < 4) return false;
            entry.adler = load32(body + sub_body);
        } else if (std::memcmp(p, "segm", 4) == 0) {
            if (sub_size % 28 != 0) return false;
            for (size_t k = 0; k < sub_size / 28; ++k) {
                const uint8_t* s = body + sub_body + k * 28;
                Xp3Segment seg;
                seg.flags = load32(s);
                seg.offset = load64(s + 4);
                seg.original_size = load64(s + 12);
                seg.archived_size = load64(s + 20);
                entry.segments.push_back(seg);
            }
        } else if (std::memcmp(p, "info", 4) == 0) {
            if (sub_size < 22) return false;
            const uint8_t* b = body + sub_body;
            entry.info_flags = load32(b);
            entry.original_size = load64(b + 4);
            entry.archived_size = load64(b + 12);
            const uint16_t name_len = static_cast<uint16_t>(b[20] | (b[21] << 8));
            if (22 + static_cast<size_t>(name_len) * 2 > sub_size) return false;
            entry.name.resize(name_len);
            for (uint16_t i = 0; i < name_len; ++i) {
                entry.name[i] = static_cast<char16_t>(b[22 + i * 2] | (b[23 + i * 2] << 8));
            }
        }
        q = sub_body + static_cast<size_t>(sub_size);
    }
    return true;
}

}  // namespace

bool read_xp3(const uint8_t* data, size_t len, Xp3Header& header,
              std::vector<uint8_t>& index_tree) {
    if (len < 40) return false;
    if (std::memcmp(data, kXp3Magic, sizeof(kXp3Magic)) != 0) return false;

    header.decoy_index_offset = load64(data + 11);
    header.index_offset = load64(data + 32);
    if (header.index_offset + 17 > len) return false;

    const uint8_t* p = data + header.index_offset;
    if (p[0] != 1) return false;  // 目前见到的样本索引都走 zlib 分支

    const uint64_t comp_size = load64(p + 1);
    const uint64_t orig_size = load64(p + 9);
    if (header.index_offset + 17 + comp_size > len) return false;

    // orig_size 是文件里的 64 位字段，直接拿去分配内存前必须先挡一道：
    // 下面的 size_t / uLongf 都是 32 位，装不下就会截断，畸形文件能让我们
    // 去申请几个 GB。实测索引树一条记录约 100 字节，64 MB 够几百万条了。
    constexpr uint64_t kMaxIndexTreeSize = 64ull * 1024 * 1024;
    if (orig_size > kMaxIndexTreeSize) return false;

    index_tree.assign(static_cast<size_t>(orig_size), 0);
    uLongf dest_len = static_cast<uLongf>(orig_size);
    const int rc =
        uncompress(index_tree.data(), &dest_len, p + 17, static_cast<uLong>(comp_size));
    if (rc != Z_OK || dest_len != orig_size) return false;

    header.file_chunk_count = 0;
    size_t q = 0;
    while (q + 12 <= index_tree.size()) {
        const uint64_t size = load64(index_tree.data() + q + 4);
        if (std::memcmp(index_tree.data() + q, "File", 4) == 0) ++header.file_chunk_count;
        // 和下面那两处遍历一样，先挡住上界再前进：size 是 64 位字段，窄化到
        // 32 位的 size_t 会回绕，q 就再也前进不了、循环出不去
        if (size > index_tree.size() - q - 12) break;
        q += 12 + static_cast<size_t>(size);
    }
    return true;
}

bool find_hxv4(const std::vector<uint8_t>& index_tree, Hxv4Descriptor& out) {
    size_t q = 0;
    while (q + 12 <= index_tree.size()) {
        const uint64_t size = load64(index_tree.data() + q + 4);
        const size_t body = q + 12;
        if (body + size > index_tree.size()) return false;

        if (std::memcmp(index_tree.data() + q, "Hxv4", 4) == 0) {
            if (size < 14) return false;
            const uint8_t* b = index_tree.data() + body;
            out.payload_offset = load64(b);
            out.payload_size = load32(b + 8);
            out.flags = static_cast<uint16_t>(b[12] | (b[13] << 8));
            return true;
        }
        q = body + static_cast<size_t>(size);
    }
    return false;
}

bool parse_xp3(const uint8_t* data, size_t len, Xp3Archive& out) {
    out = Xp3Archive{};
    if (!read_xp3(data, len, out.header, out.index_tree)) return false;

    out.has_hxv4 = find_hxv4(out.index_tree, out.hxv4);

    const uint8_t* p = data + out.header.index_offset;
    out.index_compressed_size = load64(p + 1);
    out.index_original_size = load64(p + 9);

    size_t q = 0;
    while (q + 12 <= out.index_tree.size()) {
        const uint64_t size = load64(out.index_tree.data() + q + 4);
        const size_t body = q + 12;
        if (body + size > out.index_tree.size()) return false;

        if (std::memcmp(out.index_tree.data() + q, "File", 4) == 0) {
            Xp3Entry entry;
            if (!parse_file_chunk(out.index_tree.data() + body, static_cast<size_t>(size), entry)) {
                return false;
            }
            out.entries.push_back(std::move(entry));
        }
        q = body + static_cast<size_t>(size);
    }
    return true;
}

std::vector<uint8_t> build_index_tree(const Hxv4Descriptor& hxv4,
                                      const std::vector<Xp3Entry>& entries) {
    std::vector<uint8_t> tree;

    // Hxv4 描述符（14 字节）
    std::vector<uint8_t> hx;
    put64(hx, hxv4.payload_offset);
    put32(hx, hxv4.payload_size);
    hx.push_back(static_cast<uint8_t>(hxv4.flags));
    hx.push_back(static_cast<uint8_t>(hxv4.flags >> 8));
    chunk(tree, "Hxv4", hx);

    for (const Xp3Entry& entry : entries) {
        std::vector<uint8_t> body;

        std::vector<uint8_t> adlr;
        put32(adlr, entry.adler);
        chunk(body, "adlr", adlr);

        std::vector<uint8_t> segm;
        for (const Xp3Segment& seg : entry.segments) {
            put32(segm, seg.flags);
            put64(segm, seg.offset);
            put64(segm, seg.original_size);
            put64(segm, seg.archived_size);
        }
        chunk(body, "segm", segm);

        std::vector<uint8_t> info;
        put32(info, entry.info_flags);
        put64(info, entry.original_size);
        put64(info, entry.archived_size);
        const uint16_t name_len = static_cast<uint16_t>(entry.name.size());
        info.push_back(static_cast<uint8_t>(name_len));
        info.push_back(static_cast<uint8_t>(name_len >> 8));
        for (const char16_t c : entry.name) {
            info.push_back(static_cast<uint8_t>(c));
            info.push_back(static_cast<uint8_t>(c >> 8));
        }
        info.push_back(0);
        info.push_back(0);
        chunk(body, "info", info);

        chunk(tree, "File", body);
    }
    return tree;
}

}  // namespace hxv4
