#include "core/pack.h"

#include "core/filter.h"
#include "core/tjs_variant.h"
#include "crypto/aead.h"
#include "crypto/checksum.h"

#include <zlib.h>

#include <cstring>

namespace hxv4 {
namespace {

void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

std::vector<uint8_t> deflate(const std::vector<uint8_t>& in) {
    if (in.empty()) return {};
    uLongf bound = compressBound(static_cast<uLong>(in.size()));
    std::vector<uint8_t> out(bound);
    if (compress2(out.data(), &bound, in.data(), static_cast<uLong>(in.size()), 9) != Z_OK) {
        return {};
    }
    out.resize(bound);
    return out;
}

// 把条目数据编码成磁盘形式：先过滤器，再（可选）zlib。
bool encode_entry(const PackEntry& entry, const DripProgram& drip, uint16_t open_flag,
                  std::vector<uint8_t>& out, Xp3Segment& seg) {
    seg.flags = 0;
    seg.original_size = entry.plaintext.size();

    if (entry.raw) {
        out = entry.plaintext;
        seg.archived_size = out.size();
        return true;
    }

    uint8_t seed_state[48];
    // 注意：build_filter_state 内部**自己**会按 open_flag 用 holder_words[2]/[3]
    // 扰动 key，所以这里必须传映射表里那个原始 key，不能再预先异或一次。
    if (!drip.build_filter_state(entry.key, open_flag, seed_state)) return false;

    std::vector<uint8_t> buf = entry.plaintext;
    FilterState(seed_state).apply(buf.data(), buf.size(), 0);

    if (entry.compress) {
        std::vector<uint8_t> comp = deflate(buf);
        if (comp.empty() && !buf.empty()) return false;
        seg.flags = 1;
        buf = std::move(comp);
    }
    seg.archived_size = buf.size();
    out = std::move(buf);
    return true;
}

}  // namespace

uint64_t hx_per_file_key(size_t index) {
    uint64_t state = 0x55555555ull + (index + 1) * 0x9E3779B97F4A7C15ull;
    uint64_t x = state;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

std::vector<uint8_t> pack_archive(const std::vector<PackEntry>& entries, const PackContext& ctx) {
    if (ctx.drip == nullptr || !ctx.drip->valid()) return {};

    const size_t total = entries.size();

    // ---- 1. 数据区 + 段表 ----
    std::vector<uint8_t> data;
    std::vector<Xp3Entry> index_entries;
    std::vector<MappingRecord> records;
    index_entries.reserve(total);
    records.reserve(total);

    // 40 字节头部之后就是条目数据；条目 0（若有）自然落在偏移 40
    uint64_t cursor = 40;
    for (size_t i = 0; i < entries.size(); ++i) {
        const PackEntry& in = entries[i];

        std::vector<uint8_t> encoded;
        Xp3Segment seg;
        if (!encode_entry(in, *ctx.drip, ctx.open_flag, encoded, seg)) return {};
        seg.offset = cursor;

        Xp3Entry e;
        e.info_flags = in.info_flags;
        e.original_size = in.plaintext.size();
        e.archived_size = encoded.size();
        e.name = in.index_name;
        e.adler = crypto::adler32(in.plaintext.data(), in.plaintext.size());
        e.segments = in.segments_override.empty()
                         ? std::vector<Xp3Segment>{seg}
                         : in.segments_override;
        index_entries.push_back(std::move(e));

        data.insert(data.end(), encoded.begin(), encoded.end());
        cursor += encoded.size();

        MappingRecord rec;
        rec.domain_hash_bytes = in.domain_hash;
        rec.file_hash = in.file_hash;
        // packed = 高 16 位 archive_slot(=0) | 低 16 位 filter_flag(=条目下标)
        rec.packed = static_cast<uint32_t>(index_entries.size() - 1);
        rec.key = in.key;
        records.push_back(rec);
    }

    // ---- 2. Hxv4 负载 ----
    MappingTable table;
    table.records = std::move(records);
    const std::vector<uint8_t> tjs = mapping_serialize(table);

    std::vector<uint8_t> mapping_plain;
    put32(mapping_plain, static_cast<uint32_t>(tjs.size()));
    const std::vector<uint8_t> tjs_z = deflate(tjs);
    if (tjs_z.empty() && !tjs.empty()) return {};
    mapping_plain.insert(mapping_plain.end(), tjs_z.begin(), tjs_z.end());

    const uint64_t payload_offset = cursor;
    const crypto::Nonce24 nonce =
        ctx.open_flag == 0 ? ctx.index_keys.nonce0 : ctx.index_keys.nonce1;
    const std::vector<uint8_t> payload = crypto::xchacha20poly1305_seal(
        ctx.index_keys.root_key, nonce, mapping_plain.data(), mapping_plain.size());
    if (payload.size() != mapping_plain.size() + 16) return {};

    // ---- 3. 索引 ----
    Hxv4Descriptor desc;
    desc.payload_offset = payload_offset;
    desc.payload_size = static_cast<uint32_t>(payload.size());
    desc.flags = ctx.open_flag;

    const std::vector<uint8_t> tree = build_index_tree(desc, index_entries);
    const std::vector<uint8_t> index_blob = deflate(tree);
    if (index_blob.empty() && !tree.empty()) return {};

    // ---- 4. 拼装 ----
    std::vector<uint8_t> out;
    out.reserve(40 + data.size() + payload.size() + 17 + index_blob.size());
    out.insert(out.end(), kXp3Magic, kXp3Magic + sizeof(kXp3Magic));
    put64(out, 0x17);  // 诱饵
    put32(out, 1);
    out.push_back(0x80);
    put64(out, 0);
    const uint64_t index_offset = payload_offset + payload.size();
    put64(out, index_offset);
    out.insert(out.end(), data.begin(), data.end());
    out.insert(out.end(), payload.begin(), payload.end());
    out.push_back(1);  // 索引压缩标志
    put64(out, index_blob.size());
    put64(out, tree.size());
    out.insert(out.end(), index_blob.begin(), index_blob.end());
    return out;
}

bool rebuild_archive(const uint8_t* data, size_t len, const Hxv4Keys& keys, const DripProgram& drip,
                     std::vector<uint8_t>& out) {
    Xp3Archive arch;
    Hxv4MappingBlob blob;
    if (!parse_xp3(data, len, arch) || !read_hxv4_mapping(data, len, keys, blob)) return false;
    if (arch.entries.size() != blob.table.records.size() || arch.entries.empty()) return false;

    std::vector<PackEntry> entries;
    entries.reserve(arch.entries.size());

    for (size_t i = 0; i < arch.entries.size(); ++i) {
        const Xp3Entry& e = arch.entries[i];
        const MappingRecord& rec = blob.table.records[i];

        PackEntry in;
        in.domain_hash = rec.domain_hash_bytes;
        in.file_hash = rec.file_hash;
        in.key = rec.key;
        in.index_name = e.name;
        in.info_flags = e.info_flags;
        // 段表**不**覆盖 i>0 的条目：让偏移由我们自己的布局逻辑算出来，
        // 这样 verify 才能真正检验布局对不对。条目 0 的怪癖那条
        // 走 ctx.placeholder_segments。

        if (i == 0) {
            // 占位图：数据紧跟在 40 字节头之后，**不过过滤器、不压缩**。
            // 它那条 segm 是原包的陈旧值（指向 PNG 中段），要原样写回去。
            const size_t size = static_cast<size_t>(e.original_size);
            if (40 + size > len) return false;
            in.plaintext.assign(data + 40, data + 40 + size);
            in.raw = true;
            in.compress = false;
            in.segments_override = e.segments;
        } else {
            // 逐段取出：解压 → 反过滤器 → 明文
            uint8_t seed_state[48];
            if (!drip.build_filter_state(rec.key, arch.hxv4.open_flag(), seed_state)) {
                return false;
            }
            const FilterState filter(seed_state);
            for (const Xp3Segment& seg : e.segments) {
                if (seg.offset + seg.archived_size > len) return false;
                std::vector<uint8_t> chunk;
                if (seg.is_compressed()) {
                    chunk.assign(static_cast<size_t>(seg.original_size), 0);
                    uLongf got = static_cast<uLongf>(seg.original_size);
                    if (uncompress(chunk.data(), &got, data + seg.offset,
                                   static_cast<uLong>(seg.archived_size)) != Z_OK ||
                        got != seg.original_size) {
                        return false;
                    }
                } else {
                    chunk.assign(data + seg.offset, data + seg.offset + seg.archived_size);
                }
                filter.apply(chunk.data(), chunk.size(), 0);
                in.plaintext.insert(in.plaintext.end(), chunk.begin(), chunk.end());
            }
            in.compress = !e.segments.empty() && e.segments[0].is_compressed();
        }
        entries.push_back(std::move(in));
    }

    PackContext ctx;
    ctx.drip = &drip;
    ctx.open_flag = arch.hxv4.open_flag();
    ctx.index_keys = keys;
    out = pack_archive(entries, ctx);
    return !out.empty();
}

}  // namespace hxv4
