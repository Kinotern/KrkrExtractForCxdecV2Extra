#pragma once
// 精简的 TJS2 字节码解析器
// 解析 TJS2100 字节码，暴露 VM 指令流供补丁使用

#include <cstdint>
#include <vector>
#include <string>

namespace Tjs2Parser {

struct ByteCode {
    bool valid;
    std::vector<std::string> strings; // global DATA string pool

    // 字节码里每个 InterCodeContext 就是一个对象
    struct Context {
        std::string     name;          // context name (e.g. "(top level script)")
        std::vector<int32_t> code;     // VM opcode stream (int16 expanded to int32)
        std::vector<std::string> strings; // string constants for this context
        size_t rawCodeOffset;          // byte offset of code array in the raw data
    };
    std::vector<Context> contexts;
};

// 解析 TJS2 字节码，出错时 valid=false
ByteCode Parse(const uint8_t* data, size_t size);

// 判断是不是 TJS2100 字节码
bool IsTjs2(const uint8_t* data, size_t size);

} // namespace Tjs2Parser
