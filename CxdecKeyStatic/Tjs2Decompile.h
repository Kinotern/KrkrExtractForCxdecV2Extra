#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Tjs2 {

// 最小 TJS2 字节码解析器，只取字符串，用于找 _bootStrap 前缀与 bootstrap URL

struct StringsResult {
    std::vector<std::string> strings;  // string table (UTF-8 converted)
    bool ok;
};

// 解析TJS2字节码并提取字符串表。
StringsResult extract_strings(const uint8_t* data, size_t len);

// 从TJS2字符串中查找bootstrap bres:// URL。
// 未找到则返回空字符串。
std::string find_bootstrap_url(const std::vector<std::string>& strings);

// 找 _bootStrap 前缀：优先含 "all"，其次含 "right" 或 "reserved"
std::string find_bootstrap_prefix(const std::vector<std::string>& strings);

} // namespace Tjs2
