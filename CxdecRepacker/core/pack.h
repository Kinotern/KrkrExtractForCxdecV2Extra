#pragma once

#include "core/archive.h"
#include "core/drip.h"
#include "core/mapping.h"
#include "core/resource_hash.h"
#include "core/xp3.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hxv4 {

// 一条待写出的条目。
struct PackEntry {
    std::array<uint8_t, 8> domain_hash{};  // 域哈希（写进映射表的那 8 字节）
    Hash32 file_hash{};
    uint64_t key = 0;                 // 写进映射表的 per-file key（原样，不做 XOR）
    std::vector<uint8_t> plaintext;   // 明文（未过滤、未压缩）
    std::u16string index_name;        // 索引 info 里的名字（原包是生成的假名）
    uint32_t info_flags = 0x80000000u;
    bool compress = false;

    // raw = true：数据原样写出，**不过过滤器、不压缩**。
    // 条目 0 那张警告占位图就是这样（游戏也不读它）。
    bool raw = false;

    // 段表覆盖：非空时原样写入，跳过常规布局。
    // 用来复刻原包的怪癖（例如条目 0 那条指向 PNG 中段的陈旧 segm）。
    std::vector<Xp3Segment> segments_override;
};

struct PackContext {
    const DripProgram* drip = nullptr;  // 数据层 VM，必需
    uint16_t open_flag = 0;

    Hxv4Keys index_keys{};  // 索引层 XChaCha20-Poly1305 材料
};

// 按 hxv4 变体 XP3 写出。失败返回空 vector。
//
// 数据层的 seed 由 `entry.key` 经 `filter_seed()` 推出（与读侧同一套规则），
// 所以调用者只需要决定「往映射表里写什么 key」。
std::vector<uint8_t> pack_archive(const std::vector<PackEntry>& entries, const PackContext& ctx);

// 原工具用的 per-file key 生成器：splitmix64，种子 0x55555555，按枚举顺序。
// 这只是写侧的一种选择——映射表里的 key 本来就是写侧的自由度，
// 用它是为了让结果与原工具的行为一致，便于对照。
uint64_t hx_per_file_key(size_t index);

// 从一条 XP3 读出全部内容再原样重写一遍（T0 逐字节复刻验证用）。
// 依赖 `read_hxv4_mapping` 那套密钥材料。
bool rebuild_archive(const uint8_t* data, size_t len, const Hxv4Keys& keys,
                     const DripProgram& drip, std::vector<uint8_t>& out);

}  // namespace hxv4
