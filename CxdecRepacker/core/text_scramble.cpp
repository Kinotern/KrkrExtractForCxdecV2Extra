#include "core/text_scramble.h"

namespace hxv4 {
namespace {

// 相邻 bit 两两对调。对称，所以加扰/解扰共用。
void bit_swap(uint8_t* data, size_t len, size_t from) {
    for (size_t i = from; i + 1 < len; i += 2) {
        const uint16_t c = static_cast<uint16_t>(data[i] | (data[i + 1] << 8));
        const uint16_t s =
            static_cast<uint16_t>(((c & 0xAAAAu) >> 1) | ((c & 0x5555u) << 1));
        data[i] = static_cast<uint8_t>(s & 0xFF);
        data[i + 1] = static_cast<uint8_t>(s >> 8);
    }
}

}  // namespace

bool is_scrambled(const uint8_t* data, size_t len) {
    return len >= kScrambleHeaderSize && data[0] == 0xFE && data[1] == 0xFE &&
           data[3] == 0xFF && data[4] == 0xFE;
}

bool descramble_text(const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    if (!is_scrambled(data, len)) return false;
    if (data[2] != kScrambleModeBitSwap) return false;  // 只支持位交换

    out.clear();
    out.reserve(len - 3);
    out.push_back(0xFF);
    out.push_back(0xFE);
    out.insert(out.end(), data + kScrambleHeaderSize, data + len);
    bit_swap(out.data(), out.size(), 2);
    return true;
}

bool scramble_text(const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    if (len < 2 || data[0] != 0xFF || data[1] != 0xFE) return false;

    out.clear();
    out.reserve(len + 3);
    out.push_back(0xFE);
    out.push_back(0xFE);
    out.push_back(kScrambleModeBitSwap);
    out.push_back(0xFF);
    out.push_back(0xFE);
    out.insert(out.end(), data + 2, data + len);
    bit_swap(out.data(), out.size(), kScrambleHeaderSize);
    return true;
}

}  // namespace hxv4
