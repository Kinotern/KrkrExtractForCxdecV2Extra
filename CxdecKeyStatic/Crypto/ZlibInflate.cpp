#include "ZlibInflate.h"
#include <cstring>
#include <cstdlib>

namespace Crypto {

static const int LEN_EXTRA[29] = {
    0,0,0,0,0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3, 4,4,4,4, 5,5,5,5, 0
};
static const int LEN_BASE[29] = {
    3,4,5,6,7,8,9,10, 11,13,15,17, 19,23,27,31,
    35,43,51,59, 67,83,99,115, 131,163,195,227, 258
};
static const int DIST_EXTRA[30] = {
    0,0,0,0, 1,1, 2,2, 3,3, 4,4, 5,5, 6,6,
    7,7, 8,8, 9,9, 10,10, 11,11, 12,12, 13,13
};
static const int DIST_BASE[30] = {
    1,2,3,4, 5,7, 9,13, 17,25, 33,49, 65,97, 129,193,
    257,385, 513,769, 1025,1537, 2049,3073, 4097,6145, 8193,12289, 16385,24577
};
static const int CLEN_ORDER[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

class BitStream {
    const uint8_t* p_;
    const uint8_t* end_;
    uint64_t buf_;
    int bits_;
public:
    BitStream(const uint8_t* data, size_t len)
        : p_(data), end_(data + len), buf_(0), bits_(0) {
        for (int i = 0; i < 8 && p_ < end_; ++i)
            buf_ |= (uint64_t)(*p_++) << (i * 8);
        bits_ = (int)((p_ - data) * 8);
        if (p_ == end_ && bits_ == 0 && len > 0) bits_ = (int)(len * 8);
    }

    uint32_t read_bits(int n) {
        if (n <= 0) return 0;
        while (bits_ < n && p_ < end_) {
            buf_ |= (uint64_t)(*p_++) << bits_;
            bits_ += 8;
        }
        if (bits_ < n) return 0;
        uint32_t v = (uint32_t)(buf_ & ((1ULL << n) - 1));
        buf_ >>= n;
        bits_ -= n;
        return v;
    }

    void align() {
        int skip = bits_ & 7;
        if (skip) { buf_ >>= skip; bits_ -= skip; }
    }

    int remaining_bits() const { return bits_ + (int)((end_ - p_) * 8); }
};

struct HuffDecoder {
    int counts[16];
    int symbols[320];
    int max_len;

    void build(const uint8_t* lengths, int n) {
        memset(counts, 0, sizeof(counts));
        max_len = 0;
        for (int i = 0; i < n; ++i) {
            int len = lengths[i];
            if (len > 0 && len <= 15) {
                counts[len]++;
                if (len > max_len) max_len = len;
            }
        }
        counts[0] = 0;

        int off[16];
        off[1] = 0;
        for (int b = 2; b <= 15; ++b)
            off[b] = off[b-1] + counts[b-1];

        int next_code[16];
        for (int b = 1; b <= 15; ++b)
            next_code[b] = off[b];

        for (int i = 0; i < n; ++i) {
            int len = lengths[i];
            if (len > 0 && len <= 15)
                symbols[next_code[len]++] = i;
        }
    }

    int decode(BitStream& bs) const {
        int code = 0;
        int first = 0;
        int off = 0;
        for (int bits = 1; bits <= max_len; ++bits) {
            code = (code << 1) | (int)bs.read_bits(1);
            int cnt = counts[bits];
            int diff = code - first;
            if (diff < cnt)
                return symbols[off + diff];
            off += cnt;
            first = (first + cnt) << 1;
        }
        return -1;
    }
};

static void build_fixed_ll(uint8_t* lens) {
    for (int i = 0; i <= 143; ++i) lens[i] = 8;
    for (int i = 144; i <= 255; ++i) lens[i] = 9;
    for (int i = 256; i <= 279; ++i) lens[i] = 7;
    for (int i = 280; i <= 287; ++i) lens[i] = 8;
}

std::vector<uint8_t> zlib_decompress(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out;
    if (len < 6) return out;

    uint8_t cmf = data[0];
    uint8_t flg = data[1];
    if ((cmf & 0x0F) != 8) return out;
    if ((((uint16_t)cmf << 8) | flg) % 31 != 0) return out;

    size_t stream_off = 2;
    if (flg & 0x20) stream_off += 4;

    size_t raw_len = len - stream_off - 4;
    BitStream bs(data + stream_off, raw_len);
    out.reserve(len * 4);

    for (;;) {
        int bfinal = (int)bs.read_bits(1);
        int btype  = (int)bs.read_bits(2);

        if (btype == 0) {
            bs.align();
            uint32_t block_len = bs.read_bits(16);
            uint32_t block_nlen = bs.read_bits(16);
            if (block_len != (uint32_t)(~block_nlen & 0xFFFF)) return {};

            // bs现在指向头部之后。读取block_len字节。
            int remaining = bs.remaining_bits();
            int bytes_buffered = (remaining + 7) / 8;
            int bits_to_drop = remaining - bytes_buffered * 8;
            if (bits_to_drop < 0) bits_to_drop += 8;
            if (bits_to_drop > 0) bs.read_bits(bits_to_drop);

            // 直接从输入读取字节
            size_t consumed = raw_len - (size_t)(bs.remaining_bits() / 8);
            if (consumed + block_len > raw_len) return {};

            size_t old_sz = out.size();
            out.resize(old_sz + block_len);
            memcpy(out.data() + old_sz, data + stream_off + consumed, block_len);

            bs = BitStream(data + stream_off + consumed + block_len,
                            raw_len - consumed - block_len);
        } else if (btype == 1 || btype == 2) {
            HuffDecoder ll_tree, dist_tree;

            if (btype == 1) {
                uint8_t ll_lens[288];
                build_fixed_ll(ll_lens);
                ll_tree.build(ll_lens, 288);

                uint8_t d_lens[32];
                memset(d_lens, 5, 32);
                dist_tree.build(d_lens, 32);
            } else {
                int hlit  = (int)bs.read_bits(5) + 257;
                int hdist = (int)bs.read_bits(5) + 1;
                int hclen = (int)bs.read_bits(4) + 4;

                if (hlit > 288 || hdist > 32) return {};

                uint8_t cl_lens[19] = {};
                for (int i = 0; i < hclen; ++i)
                    cl_lens[CLEN_ORDER[i]] = (uint8_t)bs.read_bits(3);

                HuffDecoder cl_tree;
                cl_tree.build(cl_lens, 19);

                uint8_t all_lens[320] = {};
                int total = hlit + hdist;
                for (int i = 0; i < total; ) {
                    int sym = cl_tree.decode(bs);
                    if (sym < 0) return {};
                    if (sym < 16) {
                        all_lens[i++] = (uint8_t)sym;
                    } else if (sym == 16) {
                        if (i == 0) return {};
                        int repeat = (int)bs.read_bits(2) + 3;
                        uint8_t prev = all_lens[i - 1];
                        for (int r = 0; r < repeat && i < total; ++r)
                            all_lens[i++] = prev;
                    } else if (sym == 17) {
                        int repeat = (int)bs.read_bits(3) + 3;
                        for (int r = 0; r < repeat && i < total; ++r)
                            all_lens[i++] = 0;
                    } else {
                        int repeat = (int)bs.read_bits(7) + 11;
                        for (int r = 0; r < repeat && i < total; ++r)
                            all_lens[i++] = 0;
                    }
                }

                ll_tree.build(all_lens, hlit);
                dist_tree.build(all_lens + hlit, hdist);
            }

            for (;;) {
                int sym = ll_tree.decode(bs);
                if (sym < 0) return {};
                if (sym < 256) {
                    out.push_back((uint8_t)sym);
                } else if (sym == 256) {
                    break;
                } else {
                    int len_idx = sym - 257;
                    if (len_idx < 0 || len_idx > 28) return {};
                    int length = LEN_BASE[len_idx] + (int)bs.read_bits(LEN_EXTRA[len_idx]);

                    int dsym = dist_tree.decode(bs);
                    if (dsym < 0 || dsym > 29) return {};
                    int distance = DIST_BASE[dsym] + (int)bs.read_bits(DIST_EXTRA[dsym]);

                    if (distance < 1 || distance > (int)out.size()) return {};

                    size_t old_sz = out.size();
                    out.resize(old_sz + length);
                    for (int j = 0; j < length; ++j)
                        out[old_sz + j] = out[old_sz - distance + j];
                }
            }
        } else {
            return {};
        }

        if (bfinal) break;
    }

    return out;
}

} // namespace Crypto
