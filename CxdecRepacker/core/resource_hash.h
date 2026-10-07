#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace hxv4 {

// hxv4 的媒体名（盐）。**这是运行时的默认值，不是唯一值。**
//
// 运行时用的是 CompoundStorageMedia 的 mediaName，来自 STARTUP.TJS：
//
//   mediaName = bootstrapPrefix 含冒号 ? 冒号前那段 : "xp3hnp"
//
// 所以它每游戏可变，不能写死在公式里。调用方一律传自己那套的盐，
// 只在确实拿不到真实值时才回落到这个默认值。
inline constexpr std::string_view kDefaultMediaName = "xp3hnp";

using Hash32 = std::array<uint8_t, 32>;

// 逻辑文件名 -> file_hash（32 字节）。
// 输入 = UTF-16LE(名字) ‖ UTF-16LE(盐)，unkeyed BLAKE2s-256。
// 必须传运行时实际用的规范化逻辑文件名（通常含扩展名，如 "bgm01.opus"），
// 裸逻辑名（"bgm01"）会算错。
Hash32 file_hash(std::u16string_view name, std::string_view media_name);

// keyed 变体：运行时 `hash_key.key_len != 0` 时启用，密钥为 hash_key[0:32]。
// 见过样本的 key_len 恒为 0（hash_key 被复制进 hasher 的 key buffer 但长度没写），
// 所以这条目前用不上，接口先留着。
Hash32 file_hash_keyed(std::u16string_view name, const uint8_t key[32],
                       std::string_view media_name);

// 逻辑目录路径 -> domain_hash（u64）。
// 输入 = UTF-16LE(路径 ‖ 盐)；空串或 "/" 代表根，等价于只哈希盐。
// 返回的是 SipHash-2-4(零密钥) 之后**字节反转**的值——
// 把它写成**大端** 8 字节，就是索引里存的 domain_hash。
// （CafeStella 实测：本函数得 0x94D4A97C61498621，索引里存的正是 94D4A97C61498621。）
uint64_t domain_hash(std::u16string_view path, std::string_view media_name);

}  // namespace hxv4
