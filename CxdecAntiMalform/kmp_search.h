#pragma once
#include <cstdint>

// Knuth-Morris-Pratt 字节查找

namespace Kmp {

// 建失败表，table 由调用方分配 patternLen 个元素
void BuildTable(const uint8_t* pattern, size_t patternLen, size_t* table);

// KMP 查找，返回首个匹配位置；mask 非空时 mask[i]==0 表示该字节通配
const uint8_t* Search(
    const uint8_t* data,    size_t dataLen,
    const uint8_t* pattern, size_t patternLen,
    const uint8_t* mask = nullptr);

} // namespace Kmp
