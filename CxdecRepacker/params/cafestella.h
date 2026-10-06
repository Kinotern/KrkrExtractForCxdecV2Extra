#pragma once

#include "core/drip.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

// CafeStella 的硬编码参数。
//
// **这是单游戏硬编码**，目的只有一个：先把整条链路跑通、方便 debug。
// 多游戏 / 参数管理以后再做（见 md/06-dev/02-架构与复用.md）。
//
// 来源：D:\Program\Steam\steamapps\common\CafeStella\CafeStella.exe.unpacked_crack.exe
// 派生：cxdec-hxv4-static-analysis 的 static_xp3_recover + FilterManagerDerive
// 产物：keys/cafestella/drip_program.json
// 完整记录：md/06-dev/03-密钥派生链.md §7
namespace hxv4::params::cafestella {

// ---------------------------------------------------------------------------
// 游戏路径
// ---------------------------------------------------------------------------
inline constexpr std::string_view kGameDir = "G:/SteamLibrary/steamapps/common/CafeStella";
inline constexpr std::string_view kExePath =
    "G:/SteamLibrary/steamapps/common/CafeStella/CafeStella.exe.unpacked_crack.exe";

// ---------------------------------------------------------------------------
// 映射表（索引层）的 XChaCha20-Poly1305 根材料
// ---------------------------------------------------------------------------
inline constexpr std::string_view kHxv4Key =
    "77987faf3a8bb3ec9c31ec618319360721ab314cb2198cf10d96fed40affcc24";
inline constexpr std::string_view kHxv4Nonce0 = "6e69de1b066aa4823bd31dcb789a384b1d726c36d1241ec3";
inline constexpr std::string_view kHxv4Nonce1 = "524ce3acd0bfd8a906654cc06fb462deaf978684e3ee7cd8";

// ---------------------------------------------------------------------------
// 索引层派生结果
//
// 等价于原 HxCryptTool 的 `--index-key` / `--index-nonce` / `--index-verify`。
// 注意工具把 HChaCha20 那一步外置了，所以 `key` 是**派生后的子密钥**，
// 不是 kHxv4Key 本身。这里在运行时用我们自己的 HChaCha20 算出来，
// 既省得抄一遍常量，也顺带自检密码学实现。
// ---------------------------------------------------------------------------
struct IndexKey {
    std::array<uint8_t, 32> key{};     // --index-key    = HChaCha20(hxv4_key, nonce[0:16])
    std::array<uint8_t, 16> nonce{};   // --index-nonce  = nonce[16:24] + 8 字节填充
    std::array<uint8_t, 32> verify{};  // --index-verify = ChaCha20(子密钥, 计数器0)[:32]
};

// open_flag 决定用 nonce0 还是 nonce1（来自 Hxv4 描述符 flags 的 bit0）。
IndexKey index_key(uint16_t open_flag);

// ---------------------------------------------------------------------------
// 数据层
// ---------------------------------------------------------------------------
inline constexpr uint32_t kHolderWords[6] = {49694536, 0, 467560814, 2191813126, 486, 101};

inline constexpr uint32_t filder_split() { return kHolderWords[5]; }  // 101
inline constexpr uint32_t filder_mask() { return kHolderWords[4]; }   // 486

// `--filder-key`。
//
// 运行时读侧在 **open_flag 的 bit0 == 0 时**才把 holder_words[2]/[3] 异或进 key，
// 写侧必须用同一个偏移量，所以这里是「open_flag=0 取 hw[2]|hw[3]<<32，=1 取 0」。
// 这条方向是靠 Adler-32 对真机数据实测出来的（4/4 命中，反过来的写法 0/4），
// 别按直觉写反。
uint64_t filder_key(uint16_t open_flag);

// 数据层查表：4096 字节 = context_u32[0..1023] 的小端拼接。
// 以下四项都由 cpp/tools/gen_cafestella_params.py 从 drip_program.json 生成。
inline constexpr size_t kCxdecTableSize = 4096;
const uint8_t* cxdec_table();

inline constexpr size_t kLaneCount = 128;
const uint32_t* lane_record_counts();  // 128 项，每条 lane 的记录条数
const uint32_t* lane_records();        // 扁平存放的 (param, op) 对
size_t lane_records_count();           // 记录条数（= len(lane_records())/2）

// 用上面这些硬编码参数构造好的 DripValue VM。
const hxv4::DripProgram& drip_program();

// 条目 0 的 910 字节警告占位图。严格说它是**原工具内嵌的固定常量**
// （每个包都一样），不是游戏参数；放在这里只是因为同属"需要写死"的那类数据。
inline constexpr size_t kPlaceholderSize = 910;
const uint8_t* placeholder();

// 占位图那条映射记录的 file_hash。同样是固定常量（各游戏一致），
// 不对应任何能猜到的文件名——是原工具自己的约定。
inline constexpr std::string_view kPlaceholderFileHash =
    "2ea4aaec6a09f9d17e2a5a7ac422fb64b6a42195c55cf6772fb30c0fa0120c8d";

// ---------------------------------------------------------------------------
// 归档标识
// ---------------------------------------------------------------------------
inline constexpr std::string_view kUnique = "{Kanna+Natsume+Nozomi+Mei+Suzune}";
inline constexpr uint64_t kArchiveSeed = 0x79D53D8B5F13AB6DULL;

// ---------------------------------------------------------------------------
// 常用包
// ---------------------------------------------------------------------------
inline constexpr std::string_view kMainXp3 =
    "G:/SteamLibrary/steamapps/common/CafeStella/main.xp3";

}  // namespace hxv4::params::cafestella
