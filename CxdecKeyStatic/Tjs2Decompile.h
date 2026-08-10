#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace Tjs2 {

/// @brief 最小化的TJS2字节码解析器，专注于提取字符串
/// 并查找_bootStrap前缀和bootstrap URL。
//
/// TJS2字节码格式："TJS2100\x00" + declared_size(u32) + chunks[]
/// 每个chunk：tag(4字节ASCII) + size(u32) + body
// DATA chunk body contains: pools 鈫?string table 鈫?octets

struct StringsResult {
    std::vector<std::string> strings;  // string table (UTF-8 converted)
    bool ok;
};

/// 解析TJS2字节码并提取字符串表。
StringsResult extract_strings(const uint8_t* data, size_t len);

/// 从TJS2字符串中查找bootstrap bres:// URL。
/// 未找到则返回空字符串。
std::string find_bootstrap_url(const std::vector<std::string>& strings);

/// 从TJS2字符串中查找_bootStrap prefix字符串。
/// prefix是System.bootStrap()的第一个字符串参数。
/// 使用启发式：查找包含"all"的字符串，
/// 优先选择包含"right"或"reserved"的。
/// 未找到则返回空字符串。
std::string find_bootstrap_prefix(const std::vector<std::string>& strings);

} // namespace Tjs2
