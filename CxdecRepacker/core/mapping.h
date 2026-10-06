#pragma once

#include "core/tjs_variant.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hxv4 {

// 映射表里的一条记录。
//
// TJS 结构是：根数组里交错 `[域哈希(octet,8), 组数组]`，
// 组数组里交错 `[文件哈希(octet,32), [packed(int), key(int)]]`。
struct MappingRecord {
    std::array<uint8_t, 8> domain_hash_bytes{};  // 表里原样存的 8 字节
    std::array<uint8_t, 32> file_hash{};
    uint32_t packed = 0;  // 高 16 = archive_slot，低 16 = filter_flag
    uint64_t key = 0;

    // 那 8 字节按**大端**读出来的值，等于 domain_hash(path) 的返回值。
    // （存盘字节 = 该值的大端序；别按小端读。）
    uint64_t domain_hash_value() const;

    uint16_t archive_slot() const { return static_cast<uint16_t>(packed >> 16); }
    uint16_t filter_flag() const { return static_cast<uint16_t>(packed & 0xFFFF); }
};

struct MappingTable {
    std::vector<MappingRecord> records;
};

// 解析映射表（TJS 大端 Variant）。失败返回 false。
bool mapping_parse(const uint8_t* data, size_t len, MappingTable& out);

// 序列化映射表。同域的记录会被归到同一个组里（按出现顺序）。
std::vector<uint8_t> mapping_serialize(const MappingTable& table);

}  // namespace hxv4
