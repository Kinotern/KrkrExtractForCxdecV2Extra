#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace Crypto {

// zlib 解压（自研 deflate）；失败返回空 vector
std::vector<uint8_t> zlib_decompress(const uint8_t* data, size_t len);

} // namespace Crypto
