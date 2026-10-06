#pragma once

#include <cstddef>
#include <cstdint>

namespace hxv4::crypto {

// Adler-32（模 65521）。XP3 索引里的 `adlr` 块用它，是运行时判定"提取成功"的依据。
uint32_t adler32(const uint8_t* data, size_t len, uint32_t init = 1);

// CRC-32（IEEE 802.3，反射多项式 0xEDB88320）。hxv4p 容器的 payload 校验用它。
uint32_t crc32(const uint8_t* data, size_t len, uint32_t init = 0);

}  // namespace hxv4::crypto
