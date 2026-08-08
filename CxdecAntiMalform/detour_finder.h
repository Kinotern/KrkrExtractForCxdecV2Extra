#pragma once
#include <windows.h>
#include <cstdint>

// Scan loaded PE modules for a .detour section matching the 16-byte key.
// Returns a pointer to the entry data, or nullptr if not found.
const uint8_t* FindDetourEntry();

// Apply the three memcpy patches from a detour entry.
// Returns true if patches were applied.
bool ApplyDetourPatches(const uint8_t* entry);

// Debug: dump the full injectData to a log file.
void DumpDetourEntry(const uint8_t* entry);
