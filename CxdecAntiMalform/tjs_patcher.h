#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "tjs2_parser.h"

namespace TjsPatcher {

struct PatchedData {
    std::vector<uint8_t> bytes;
    bool  modified;
    int   patchesApplied;
    std::vector<size_t> patchOffsets;
};

// Patch TJS2 bytecode to bypass System.checkSignature() calls.
// Uses the tjs2_parser to decode bytecode → walk VM opcodes →
// find System + checkSignature + VM_CALL/VM_CALLD → flip 99↔100.
PatchedData PatchBytecode(const uint8_t* data, size_t size);

bool IsTjs2Bytecode(const uint8_t* data, size_t size);

} // namespace TjsPatcher
