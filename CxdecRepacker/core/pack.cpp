#include "core/pack.h"

#include "core/filter.h"
#include "core/text_scramble.h"
#include "core/tjs_variant.h"
#include "crypto/aead.h"
#include "crypto/checksum.h"

// 失败现场（错误码 + 路径）复用 Common 里的那套；$(SolutionDir)Common 已在包含路径里。
#include "win32error.h"

#include <zlib.h>

#include <windows.h>

#include <cstring>
#include <filesystem>
#include <fstream>

namespace hxv4 {
namespace {

namespace fs = std::filesystem;

// 错误信息统一用 UTF-8 的 std::string（本模块的 err 一直是这个形态）
std::string ToUtf8(const std::wstring& text) {
    if (text.empty()) return std::string();
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                           static_cast<int>(text.size()), nullptr, 0, nullptr,
                                           nullptr);
    if (need <= 0) return std::string();
    std::string out(static_cast<size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), &out[0], need,
                          nullptr, nullptr);
    return out;
}

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

// 数据按需读进来：留在磁盘上的就不必先占一份内存
bool load_plaintext(const PackEntry& entry, std::vector<uint8_t>& out, std::string& err) {
    if (entry.source_path.empty()) {
        out = entry.plaintext;
        return true;
    }
    std::ifstream f(fs::u8path(entry.source_path), std::ios::binary);
    if (!f) {
        err = "读不到 " + entry.source_path;
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    out.assign(static_cast<size_t>(n > 0 ? n : 0), 0);
    if (!out.empty()) f.read(reinterpret_cast<char*>(out.data()), n);
    if (!f && !f.eof()) {
        err = "读不到 " + entry.source_path;
        return false;
    }
    return true;
}

// 编码过程中才知道、但要写进索引的那几个值
struct EncodedInfo {
    uint64_t original_size = 0;
    uint32_t adler = 0;
    bool rescrambled = false;
};

// 把条目数据编码成磁盘形式：读盘 → （可选）加扰 → 过滤器 → （可选）zlib。
bool encode_entry(const PackEntry& entry, const DripProgram& drip, uint16_t open_flag,
                  std::vector<uint8_t>& out, Xp3Segment& seg, EncodedInfo& info,
                  std::string& err) {
    seg.flags = 0;

    std::vector<uint8_t> buf;
    if (!load_plaintext(entry, buf, err)) return false;

    // 加扰会把 2 字节 BOM 换成 5 字节头，所以必须在算 original_size 之前做
    if (entry.rescramble) {
        std::vector<uint8_t> scrambled;
        // 非文本返回 false、什么都不做，自带门控
        if (scramble_text(buf.data(), buf.size(), scrambled)) {
            buf = std::move(scrambled);
            info.rescrambled = true;
        }
    }

    info.original_size = buf.size();
    info.adler = crypto::adler32(buf.data(), buf.size());
    seg.original_size = buf.size();

    if (entry.raw) {
        out = std::move(buf);
        seg.archived_size = out.size();
        return true;
    }

    uint8_t seed_state[48];
    // 注意：build_filter_state 内部**自己**会按 open_flag 用 holder_words[2]/[3]
    // 扰动 key，所以这里必须传映射表里那个原始 key，不能再预先异或一次。
    if (!drip.build_filter_state(entry.key, open_flag, seed_state)) {
        err = "过滤器状态构造失败";
        return false;
    }
    FilterState(seed_state).apply(buf.data(), buf.size(), 0);

    if (entry.compress) {
        std::vector<uint8_t> comp = deflate(buf);
        if (comp.empty() && !buf.empty()) {
            err = "压缩失败";
            return false;
        }
        seg.flags = 1;
        buf = std::move(comp);
    }
    seg.archived_size = buf.size();
    out = std::move(buf);
    return true;
}

// 全在内存里的 sink，只服务于小规模的复刻验证
class MemorySink : public ArchiveSink {
public:
    bool Write(const uint8_t* data, size_t len) override {
        bytes_.insert(bytes_.end(), data, data + len);
        return true;
    }
    bool Patch(uint64_t offset, const uint8_t* data, size_t len) override {
        if (offset + len > bytes_.size()) return false;
        std::memcpy(bytes_.data() + offset, data, len);
        return true;
    }
    uint64_t Tell() const override { return bytes_.size(); }
    std::vector<uint8_t> TakeBytes() { return std::move(bytes_); }

private:
    std::vector<uint8_t> bytes_;
};

// 写的是 .part，Finish() 成功才改名过去。中途失败（含异常展开）由析构函数
// 把 .part 删掉——否则游戏目录里会留个半截的 patch@rN.xp3 被当成补丁包读。
class FileSink : public ArchiveSink {
public:
    FileSink(fs::path final_path, fs::path part_path)
        : final_(std::move(final_path)), part_(std::move(part_path)) {
        file_.open(part_, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!file_.is_open()) {
            Note(L"打开临时文件", part_);
        }
    }

    ~FileSink() override {
        if (file_.is_open()) file_.close();
        if (!committed_) {
            std::error_code ec;
            fs::remove(part_, ec);
        }
    }

    bool Ok() const { return file_.is_open(); }

    std::string Detail() const override { return detail_; }

    bool Write(const uint8_t* data, size_t len) override {
        if (!file_.is_open()) {
            if (detail_.empty()) Note(L"写入时文件已关闭", part_);
            return false;
        }
        file_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
        if (!file_) {
            Note(L"写数据", part_);
            return false;
        }
        cursor_ += len;
        return true;
    }

    bool Patch(uint64_t offset, const uint8_t* data, size_t len) override {
        if (!file_.is_open()) return false;
        const std::streampos here = file_.tellp();
        file_.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        file_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
        const bool ok = static_cast<bool>(file_);
        if (!ok) {
            Note(L"回填索引偏移", part_);
        }
        // 回填本来就在最后一步，但别赌调用顺序
        if (here != std::streampos(-1)) file_.seekp(here);
        return ok;
    }

    uint64_t Tell() const override { return cursor_; }

    bool Finish() override {
        if (!file_.is_open()) {
            if (detail_.empty()) Note(L"收尾时文件已关闭", part_);
            return false;
        }
        file_.flush();
        if (!file_) {
            Note(L"落盘 flush", part_);
            return false;
        }
        file_.close();
        // 目标可能已经存在（重封同名补丁包），要允许覆盖
        if (::MoveFileExW(part_.wstring().c_str(), final_.wstring().c_str(),
                          MOVEFILE_REPLACE_EXISTING) == FALSE) {
            // 最要命的一步：.part 已经写完，用户却拿不到成品。
            // 必须留下错误码（目标被占用？跨盘？权限？）
            Note(L"MoveFileEx 改名到最终文件", final_);
            return false;
        }
        committed_ = true;
        return true;
    }

private:
    // 只记第一次失败：后面的多半是同一个原因（磁盘满、盘掉线），重复记没意义。
    void Note(const wchar_t* what, const fs::path& path) {
        if (!detail_.empty()) return;
        detail_ = ToUtf8(Win32Error::FailureLine(what, path.wstring(), Win32Error::CaptureBoth()));
    }

    fs::path final_;
    fs::path part_;
    std::fstream file_;
    uint64_t cursor_ = 0;
    bool committed_ = false;
    std::string detail_;
};

}  // namespace

std::unique_ptr<ArchiveSink> MakeFileSink(const std::string& utf8_path, std::string& err) {
    const fs::path target = fs::u8path(utf8_path);
    fs::path part = target;
    part += L".part";

    auto sink = std::make_unique<FileSink>(target, part);
    if (!sink->Ok()) {
        err = "写不出文件：" + utf8_path;
        return nullptr;
    }
    return sink;
}

uint64_t hx_per_file_key(size_t index) {
    uint64_t state = 0x55555555ull + (index + 1) * 0x9E3779B97F4A7C15ull;
    uint64_t x = state;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

bool pack_archive_stream(const std::vector<PackEntry>& entries, const PackContext& ctx,
                         ArchiveSink& sink, PackStats& stats, std::string& err) {
    if (ctx.drip == nullptr || !ctx.drip->valid()) {
        err = "参数无效";
        return false;
    }

    const size_t total = entries.size();
    std::vector<Xp3Entry> index_entries;
    std::vector<MappingRecord> records;
    index_entries.reserve(total);
    records.reserve(total);

    // ---- 1. 数据区 + 段表（边编码边写，条目数据不在内存里累积）----
    //
    // 头部 40 字节先写占位：index_offset 要等负载写完才算得出来，最后回填。
    std::vector<uint8_t> header;
    header.reserve(40);
    header.insert(header.end(), kXp3Magic, kXp3Magic + sizeof(kXp3Magic));  // 0x00..0x0A
    put64(header, 0x17);                                                    // 0x0B 诱饵
    put32(header, 1);                                                       // 0x13
    header.push_back(0x80);                                                 // 0x17
    put64(header, 0);                                                       // 0x18
    put64(header, 0);                                                       // 0x20 占位
    if (!sink.Write(header.data(), header.size())) {
        err = "写入失败";
        return false;
    }

    // 40 字节头部之后就是条目数据；条目 0（若有）自然落在偏移 40
    uint64_t cursor = 40;
    uint32_t rescrambled = 0;

    for (size_t i = 0; i < entries.size(); ++i) {
        const PackEntry& in = entries[i];

        std::vector<uint8_t> encoded;
        Xp3Segment seg;
        EncodedInfo info;
        if (!encode_entry(in, *ctx.drip, ctx.open_flag, encoded, seg, info, err)) return false;
        seg.offset = cursor;

        Xp3Entry e;
        e.info_flags = in.info_flags;
        e.original_size = info.original_size;
        e.archived_size = encoded.size();
        e.name = in.index_name;
        e.adler = info.adler;
        e.segments = in.segments_override.empty()
                         ? std::vector<Xp3Segment>{seg}
                         : in.segments_override;
        index_entries.push_back(std::move(e));

        if (!sink.Write(encoded.data(), encoded.size())) {
            err = "写入失败";
            return false;
        }
        cursor += encoded.size();
        if (info.rescrambled) ++rescrambled;

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
    if (tjs_z.empty() && !tjs.empty()) {
        err = "映射表压缩失败";
        return false;
    }
    mapping_plain.insert(mapping_plain.end(), tjs_z.begin(), tjs_z.end());

    const uint64_t payload_offset = cursor;
    const crypto::Nonce24 nonce =
        ctx.open_flag == 0 ? ctx.index_keys.nonce0 : ctx.index_keys.nonce1;
    const std::vector<uint8_t> payload = crypto::xchacha20poly1305_seal(
        ctx.index_keys.root_key, nonce, mapping_plain.data(), mapping_plain.size());
    if (payload.size() != mapping_plain.size() + 16) {
        err = "索引负载加密失败";
        return false;
    }
    if (!sink.Write(payload.data(), payload.size())) {
        err = "写入失败";
        return false;
    }
    cursor += payload.size();

    // ---- 3. 索引 ----
    Hxv4Descriptor desc;
    desc.payload_offset = payload_offset;
    desc.payload_size = static_cast<uint32_t>(payload.size());
    desc.flags = ctx.open_flag;

    const std::vector<uint8_t> tree = build_index_tree(desc, index_entries);
    const std::vector<uint8_t> index_blob = deflate(tree);
    if (index_blob.empty() && !tree.empty()) {
        err = "索引压缩失败";
        return false;
    }

    std::vector<uint8_t> tail;
    tail.push_back(1);  // 索引压缩标志
    put64(tail, index_blob.size());
    put64(tail, tree.size());
    tail.insert(tail.end(), index_blob.begin(), index_blob.end());
    if (!sink.Write(tail.data(), tail.size())) {
        err = "写入失败";
        return false;
    }

    // ---- 4. 回填 index_offset（头部 0x20）----
    std::vector<uint8_t> patch;
    put64(patch, payload_offset + payload.size());
    if (!sink.Patch(0x20, patch.data(), patch.size())) {
        err = "写入失败";
        return false;
    }

    stats.rescrambled = rescrambled;
    stats.bytes = sink.Tell();
    return true;
}

std::vector<uint8_t> pack_archive(const std::vector<PackEntry>& entries, const PackContext& ctx) {
    MemorySink sink;
    PackStats stats;
    std::string err;
    if (!pack_archive_stream(entries, ctx, sink, stats, err)) return {};
    return sink.TakeBytes();
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
