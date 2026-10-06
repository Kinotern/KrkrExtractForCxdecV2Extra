#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hxv4 {

// hxv4 变体 XP3 的魔数。
inline constexpr uint8_t kXp3Magic[11] = {0x58, 0x50, 0x33, 0x0D, 0x0A, 0x20,
                                          0x0A, 0x1A, 0x8B, 0x67, 0x01};

// 头部。0x0B 处那个 u64 恒为 0x17，是**诱饵**；真实索引偏移在 0x20。
struct Xp3Header {
    uint64_t decoy_index_offset = 0;
    uint64_t index_offset = 0;
    uint32_t file_chunk_count = 0;
};

// `Hxv4` 块的 14 字节描述符。
struct Hxv4Descriptor {
    uint64_t payload_offset = 0;
    uint32_t payload_size = 0;
    uint16_t flags = 0;

    // flags 的 bit0。决定用 hxv4_nonce0 还是 hxv4_nonce1 解映射表负载。
    uint16_t open_flag() const { return static_cast<uint16_t>(flags & 1); }
};

// `File` 块里的一个段（segm 子块，28 字节）。
struct Xp3Segment {
    uint32_t flags = 0;
    uint64_t offset = 0;
    uint64_t original_size = 0;
    uint64_t archived_size = 0;

    bool is_compressed() const { return (flags & 1) != 0; }
};

// 一个条目（一个 `File` 块）。
//
// 注意：`name` 是**生成的假名**（第 i 条是 U+5000+i，即「倀倁倂倃…」），
// 不是真实文件名。真名只能通过映射表里的 file_hash 关联。
struct Xp3Entry {
    uint32_t info_flags = 0;
    uint64_t original_size = 0;
    uint64_t archived_size = 0;
    std::u16string name;
    std::vector<Xp3Segment> segments;
    uint32_t adler = 0;
};

struct Xp3Archive {
    Xp3Header header;
    Hxv4Descriptor hxv4;
    bool has_hxv4 = false;
    std::vector<Xp3Entry> entries;
    std::vector<uint8_t> index_tree;  // 解压后的 chunk 树原始字节
    uint64_t index_compressed_size = 0;
    uint64_t index_original_size = 0;
};

// 只解头部与索引 chunk 树。
bool read_xp3(const uint8_t* data, size_t len, Xp3Header& header,
              std::vector<uint8_t>& index_tree);

// 完整解析：头部 + 索引树 + Hxv4 描述符 + 全部 File 条目。
bool parse_xp3(const uint8_t* data, size_t len, Xp3Archive& out);

// 在索引 chunk 树里找 `Hxv4` 块。
bool find_hxv4(const std::vector<uint8_t>& index_tree, Hxv4Descriptor& out);

// 把索引 chunk 树序列化出来（**不含**最外层 zlib 压缩）。
// 顺序：先 `Hxv4`，再逐个 `File`。每个 `File` 内部按 `adlr` → `segm` → `info`。
std::vector<uint8_t> build_index_tree(const Hxv4Descriptor& hxv4,
                                      const std::vector<Xp3Entry>& entries);

}  // namespace hxv4
