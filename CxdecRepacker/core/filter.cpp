#include "core/filter.h"

namespace hxv4 {
namespace {

uint64_t load_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

}  // namespace

FilterBoundary FilterState::parse_boundary(uint64_t value, bool null_mode) {
    FilterBoundary b;
    b.pos0 = static_cast<uint16_t>((value >> 48) & 0xFFFF);
    b.pos1 = static_cast<uint16_t>((value >> 32) & 0xFFFF);
    if (b.pos0 == b.pos1) b.pos1 = static_cast<uint16_t>(b.pos1 + 1);

    uint8_t key_byte = static_cast<uint8_t>(value & 0xFF);
    b.byte0 = static_cast<uint8_t>((value >> 8) & 0xFF);
    b.byte1 = static_cast<uint8_t>((value >> 16) & 0xFF);

    // key_byte 为 0 时的兜底；null_mode 下取 0，否则取 0xA5
    if (key_byte == 0) key_byte = null_mode ? uint8_t{0} : uint8_t{0xA5};
    b.key = static_cast<uint32_t>(key_byte) * 0x01010101u;

    if (null_mode) {
        b.byte0 = 0;
        b.byte1 = 0;
    }
    return b;
}

FilterState::FilterState(const uint8_t seed_state[48]) {
    const bool null_mode = seed_state[45] != 0;
    boundary0_ = parse_boundary(load_le64(seed_state + 0), null_mode);
    boundary1_ = parse_boundary(load_le64(seed_state + 8), null_mode);
    split_offset_ = load_le64(seed_state + 16);
    has_bulk_key_ = seed_state[44] != 0;
    for (int i = 0; i < 16; ++i) bulk_key_[i] = seed_state[24 + i];
}

void FilterState::apply_boundary(uint8_t* data, const FilterBoundary& b, uint64_t chunk_start,
                                 size_t buffer_start, size_t size) {
    if (size == 0) return;

    // 旋转 dword key：按逻辑位置的低 2 位选字节
    for (size_t i = 0; i < size; ++i) {
        const uint32_t shift = static_cast<uint32_t>((chunk_start + i) & 3) * 8;
        data[buffer_start + i] ^= static_cast<uint8_t>((b.key >> shift) & 0xFF);
    }

    // 两个边界单字节
    if (b.byte0 != 0 && b.pos0 >= chunk_start &&
        b.pos0 < chunk_start + static_cast<uint64_t>(size)) {
        data[buffer_start + (b.pos0 - chunk_start)] ^= b.byte0;
    }
    if (b.byte1 != 0 && b.pos1 >= chunk_start &&
        b.pos1 < chunk_start + static_cast<uint64_t>(size)) {
        data[buffer_start + (b.pos1 - chunk_start)] ^= b.byte1;
    }
}

void FilterState::apply(uint8_t* data, size_t len, uint64_t offset) const {
    if (len == 0) return;
    const uint64_t end = offset + len;

    if (has_bulk_key_ && offset < 16) {
        const uint64_t overlap_end = end < 16 ? end : 16;
        for (uint64_t logical = offset; logical < overlap_end; ++logical) {
            data[logical - offset] ^= bulk_key_[logical];
        }
    }

    const uint64_t split = split_offset_;
    if (split <= offset) {
        apply_boundary(data, boundary1_, offset, 0, len);
    } else if (split < end) {
        const size_t first = static_cast<size_t>(split - offset);
        apply_boundary(data, boundary0_, offset, 0, first);
        apply_boundary(data, boundary1_, split, first, len - first);
    } else {
        apply_boundary(data, boundary0_, offset, 0, len);
    }
}

}  // namespace hxv4
