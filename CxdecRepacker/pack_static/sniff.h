#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hxv4::pack_static {

// 输入目录的形态。
enum class InputMode : int32_t {
    Unknown = -1,
    SingleDomain = 1,  // 一个域目录
    MultiDomain = 2,   // 多个域目录
    Patch = 3,         // 平铺的真实文件名
};

struct SniffResult {
    InputMode mode = InputMode::Unknown;
    uint32_t domain_count = 0;
    uint32_t file_count = 0;
    uint32_t skipped = 0;               // 被忽略的（清单文件等）
    std::vector<std::string> problems;  // 非空即无法判定，不要猜
    std::string detail;                 // 给界面显示的一句话

    bool ok() const { return mode != InputMode::Unknown; }
};

// 只看「一层域目录 + 一层文件」，不递归。
//
// 判据：
//   一级目录名 16 位 hex  -> 域目录，其下必须是 64 位 hex 的文件
//   根下文件名 64 位 hex  -> 归到根域
//   其余普通文件          -> 平铺（补丁）
//
// 混合、出现子目录、空目录等一律判为 Unknown 并给出理由——
// 宁可报错，也不要打出一个只有占位条目的空包。
SniffResult sniff_directory(const std::string& utf8_dir);

const char* mode_name(InputMode mode);

}  // namespace hxv4::pack_static
