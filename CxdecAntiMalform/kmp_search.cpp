#include "kmp_search.h"
#include <cstring>
#include <vector>

namespace Kmp {

void BuildTable(const uint8_t* pattern, size_t patternLen, size_t* table) {
    table[0] = 0;
    size_t j = 0;
    for (size_t i = 1; i < patternLen; ++i) {
        while (j > 0 && pattern[i] != pattern[j])
            j = table[j - 1];
        if (pattern[i] == pattern[j])
            ++j;
        table[i] = j;
    }
}

// 带掩码时 KMP 失败表不可靠（建表时不知道通配），改用 O(n*m) 线性扫描
static const uint8_t* SearchWithMask(
    const uint8_t* data,    size_t dataLen,
    const uint8_t* pattern, size_t patternLen,
    const uint8_t* mask)
{
    if (dataLen < patternLen) return nullptr;

    for (size_t i = 0; i <= dataLen - patternLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < patternLen; ++j) {
            // mask[j] == 0 表示通配，必然匹配
            if (mask[j] != 0 && data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return data + i;
    }
    return nullptr;
}

const uint8_t* Search(
    const uint8_t* data,    size_t dataLen,
    const uint8_t* pattern, size_t patternLen,
    const uint8_t* mask)
{
    if (patternLen == 0) return data;
    if (dataLen < patternLen) return nullptr;

    // 给了掩码就走朴素通配扫描
    if (mask)
        return SearchWithMask(data, dataLen, pattern, patternLen, mask);

    // 没有掩码：走标准 KMP
    std::vector<size_t> table(patternLen);
    BuildTable(pattern, patternLen, table.data());

    size_t j = 0;
    for (size_t i = 0; i < dataLen; ++i) {
        while (j > 0 && data[i] != pattern[j])
            j = table[j - 1];
        if (data[i] == pattern[j])
            ++j;
        if (j == patternLen) {
                        return data + i + 1 - patternLen;
        }
    }

        return nullptr;
}

} // namespace Kmp
