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

// 改 TJS2 字节码，绕过 System.checkSignature() 的校验
PatchedData PatchBytecode(const uint8_t* data, size_t size);

bool IsTjs2Bytecode(const uint8_t* data, size_t size);

} // namespace TjsPatcher
