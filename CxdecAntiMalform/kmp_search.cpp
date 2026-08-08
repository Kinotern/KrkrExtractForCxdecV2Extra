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

// ---------------------------------------------------------------------------
// When a mask is provided, KMP's failure-function table cannot be used safely:
// the table is built from raw byte values without wildcard awareness, so
// back-tracking at a wildcard position would jump to a wrong prefix offset.
// We therefore use a simple O(n*m) linear scan for the masked case.
// Pattern lengths in this codebase are short (< 32 bytes), so the cost is
// negligible.
// ---------------------------------------------------------------------------
static const uint8_t* SearchWithMask(
    const uint8_t* data,    size_t dataLen,
    const uint8_t* pattern, size_t patternLen,
    const uint8_t* mask)
{
    if (dataLen < patternLen) return nullptr;

    for (size_t i = 0; i <= dataLen - patternLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < patternLen; ++j) {
            // mask[j] == 0  => wildcard, always matches
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

    // If a mask is supplied, delegate to the simple wildcard scan.
    if (mask)
        return SearchWithMask(data, dataLen, pattern, patternLen, mask);

    // No mask: standard KMP.
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
