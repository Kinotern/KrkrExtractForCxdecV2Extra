#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace hxv4 {

// hxv4 的媒体名（盐）。硬编码在打包器与运行时里，不随游戏变化。
inline constexpr std::string_view kMediaName = "xp3hnp";

using Hash32 = std::array<uint8_t, 32>;

// 逻辑文件名 -> file_hash（32 字节）。
// 输入 = UTF-16LE(名字) ‖ UTF-16LE(盐)，unkeyed BLAKE2s-256。
// 必须传运行时实际用的规范化逻辑文件名（通常含扩展名，如 "bgm01.opus"），
// 裸逻辑名（"bgm01"）会算错。
Hash32 file_hash(std::u16string_view name);

// keyed 变体：运行时 `hash_key.key_len != 0` 时启用，密钥为 hash_key[0:32]。
Hash32 file_hash_keyed(std::u16string_view name, const uint8_t key[32]);

// 逻辑目录路径 -> domain_hash（u64）。
// 输入 = UTF-16LE(路径 ‖ 盐)；空串或 "/" 代表根，等价于只哈希盐。
// 返回的是 SipHash-2-4(零密钥) 之后**字节反转**的值——
// 把它写成小端 8 字节，就是索引里存的 domain_hash。
uint64_t domain_hash(std::u16string_view path);

}  // namespace hxv4
