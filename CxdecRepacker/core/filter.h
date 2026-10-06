#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hxv4 {

// 一个边界的派生参数（来自 48 字节种子状态里某个 u64）。
struct FilterBoundary {
    uint16_t pos0 = 0;
    uint16_t pos1 = 0;
    uint32_t key = 0;
    uint8_t byte0 = 0;
    uint8_t byte1 = 0;
};

// 数据层过滤器运行时状态。
//
// 数据在（可能的）zlib 解压之后还要过这一层：
//   1. 前 16 字节用 bulk_key 逐字节 XOR；
//   2. 按 split_offset 切成两段；
//   3. 每段用「按字节位置旋转的 dword key」XOR；
//   4. 每段在 pos0 / pos1 两个位置上各 XOR 一个字节。
//
// 全是 XOR，所以加密与解密是同一个函数。
// 语义与 cxdec 的 `FilterRuntimeState`、`垃圾站/src/hxv4-core/src/filter.rs` 对齐。
class FilterState {
public:
    explicit FilterState(const uint8_t seed_state[48]);

    // 就地施加变换。`offset` 是这段数据在条目内的逻辑偏移（整条一次处理时传 0）。
    void apply(uint8_t* data, size_t len, uint64_t offset = 0) const;

    uint64_t split_offset() const { return split_offset_; }
    bool has_bulk_key() const { return has_bulk_key_; }

private:
    static FilterBoundary parse_boundary(uint64_t value, bool null_mode);
    static void apply_boundary(uint8_t* data, const FilterBoundary& b, uint64_t chunk_start,
                               size_t buffer_start, size_t size);

    FilterBoundary boundary0_;
    FilterBoundary boundary1_;
    uint64_t split_offset_ = 0;
    bool has_bulk_key_ = false;
    uint8_t bulk_key_[16] = {};
};

}  // namespace hxv4
