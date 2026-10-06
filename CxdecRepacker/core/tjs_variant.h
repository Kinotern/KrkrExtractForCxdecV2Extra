#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace hxv4 {

enum class TjsType { Null, String, Octet, Int, Real, Array, Dict };

// TJS 二进制 Variant。
//
// 这是 hxv4 映射表用的**大端**形式（对应原工具 `sub_140013D20`），
// 不是 TJS 运行时的小端格式。标签：
//   0/1 = Null，2 = 字符串，3 = octet，4 = 整数(i64)，5 = 实数(f64)，
//   0x81 = 数组，0xC1 = 字典。长度与整数一律大端。
struct TjsValue {
    TjsType type = TjsType::Null;
    std::string str;  // String，已转成 UTF-8
    std::vector<uint8_t> octet;
    int64_t integer = 0;
    double real = 0.0;
    std::vector<TjsValue> array;
    std::vector<std::pair<std::string, TjsValue>> dict;

    bool is_octet() const { return type == TjsType::Octet; }
    bool is_int() const { return type == TjsType::Int; }
    bool is_array() const { return type == TjsType::Array; }
};

// 解析一个 Variant。失败返回 false（截断、标签未知、嵌套过深都会失败）。
bool tjs_parse(const uint8_t* data, size_t len, TjsValue& out);

// 序列化一个 Variant。
std::vector<uint8_t> tjs_serialize(const TjsValue& value);

}  // namespace hxv4
