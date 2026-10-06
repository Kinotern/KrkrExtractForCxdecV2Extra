#pragma once

#include <array>
#include <cstdint>

namespace hxv4::crypto {

inline constexpr int kChaChaRounds = 20;

using Key32 = std::array<uint8_t, 32>;
using Nonce8 = std::array<uint8_t, 8>;
using Nonce16 = std::array<uint8_t, 16>;
using Nonce24 = std::array<uint8_t, 24>;
using Tag16 = std::array<uint8_t, 16>;
using Block64 = std::array<uint8_t, 64>;

}  // namespace hxv4::crypto
