#pragma once
// Minimal TJS2 bytecode parser.
// Parses TJS2100 bytecode and exposes the VM opcode stream for patching.

#include <cstdint>
#include <vector>
#include <string>

namespace Tjs2Parser {

struct ByteCode {
    bool valid;
    std::vector<std::string> strings; // global DATA string pool

    // Each InterCodeContext in the bytecode is one "object".
    struct Context {
        std::string     name;          // context name (e.g. "(top level script)")
        std::vector<int32_t> code;     // VM opcode stream (int16 expanded to int32)
        std::vector<std::string> strings; // string constants for this context
        size_t rawCodeOffset;          // byte offset of code array in the raw data
    };
    std::vector<Context> contexts;
};

// Parse raw TJS2 bytecode. Returns valid=false on any error.
ByteCode Parse(const uint8_t* data, size_t size);

// Check if data starts with TJS2100 header.
bool IsTjs2(const uint8_t* data, size_t size);

} // namespace Tjs2Parser
