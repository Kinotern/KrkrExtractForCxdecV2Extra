#pragma once
#include <cstdint>

// Knuth-Morris-Pratt byte-level search.

namespace Kmp {

// Build the partial-match (failure) table.
// pattern: byte sequence to search for
// patternLen: length in bytes
// table: output array, caller allocates patternLen elements
void BuildTable(const uint8_t* pattern, size_t patternLen, size_t* table);

// Search for pattern in data using KMP.
// Returns pointer to first match, or nullptr if not found.
// mask: optional; if non-null, mask[i]==0 means byte at pattern[i] is wild.
const uint8_t* Search(
    const uint8_t* data,    size_t dataLen,
    const uint8_t* pattern, size_t patternLen,
    const uint8_t* mask = nullptr);

} // namespace Kmp
