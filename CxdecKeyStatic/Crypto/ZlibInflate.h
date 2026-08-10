#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace Crypto {

/// @brief zlib解压（自研deflate实现）。
/// 输入：标准zlib流（CMF+FLG头部+deflate+adler32）。
/// 失败返回空vector。
std::vector<uint8_t> zlib_decompress(const uint8_t* data, size_t len);

} // namespace Crypto
