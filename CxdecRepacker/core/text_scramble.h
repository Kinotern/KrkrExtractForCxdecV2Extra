#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hxv4 {

// KiriKiri 文本加扰（文本资源的防呆措施，**不是加密**）。
//
// 磁盘格式：`FE FE <mode> FF FE <body>`
//   mode 0 = XOR 加扰、mode 1 = 相邻位交换、mode 2 = zlib
//
// 游戏读到 `FE FE` 魔数就自己解扰；玩家用记事本直接打开则是乱码。
// 本游戏（CafeStella）用的全是 **mode 1**，而位交换是**对称的**——
// 同一个操作既是加扰也是解扰。
//
// 所以：干净文本（`FF FE` 开头）加扰一次就变回原包里的形态，反之亦然。
inline constexpr size_t kScrambleHeaderSize = 5;
inline constexpr uint8_t kScrambleModeBitSwap = 1;

// 是不是加扰格式（`FE FE <mode> FF FE`）。
bool is_scrambled(const uint8_t* data, size_t len);

// 加扰 → 干净文本：5 字节头换成 2 字节 BOM（少 3 字节），体做一次位交换。
// 只支持 mode 1；其他 mode 或格式不符返回 false。
bool descramble_text(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

// 干净文本 → 加扰：输入必须 `FF FE` 开头，否则返回 false。
// 输出 = `FE FE 01 FF FE` + 位交换后的体。
bool scramble_text(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

}  // namespace hxv4
