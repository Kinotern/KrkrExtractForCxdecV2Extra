#include "core/drip.h"

namespace hxv4 {
namespace {

// RECURSE 的嵌套上限（防御性，与参考实现一致）
constexpr int kMaxDepth = 64;

}  // namespace

DripProgram::DripProgram(std::vector<uint32_t> holder_words, std::vector<uint32_t> context,
                         std::vector<std::vector<DripRecord>> lanes)
    : holder_words_(std::move(holder_words)),
      context_(std::move(context)),
      lanes_(std::move(lanes)) {}

DripProgram::EvalResult DripProgram::eval_records(const std::vector<DripRecord>& lane, size_t pc,
                                                  uint32_t result, uint32_t scratch,
                                                  uint32_t seed, int depth) const {
    if (depth > kMaxDepth) return {0, pc, false};

    while (pc < lane.size()) {
        const uint32_t param = lane[pc].param;
        const uint32_t op = lane[pc].op;
        ++pc;

        if (op == kOpStop) break;

        if (op == kOpRecurse) {
            const EvalResult r = eval_records(lane, pc, result, scratch, seed, depth + 1);
            if (!r.ok) return r;
            result = r.value;
            pc = r.pc;
            continue;
        }

        switch (op) {
            case kOpAddImm: result = result + param; break;
            case kOpAddScratch: result = result + scratch; break;
            case kOpMulScratch: result = result * scratch; break;
            case kOpScratchMinusResult: result = scratch - result; break;
            case kOpShlScratch: result = result << (scratch & 0xF); break;
            case kOpShrScratch: result = result >> (scratch & 0xF); break;
            case kOpSubScratch: result = result - scratch; break;
            case kOpBitShuffle:
                result = (2u * (result & ~param)) | ((param >> 1) & (result >> 1));
                break;
            case kOpSetImm: result = param; break;
            case kOpSetSeed: result = seed; break;
            case kOpDec: result = result - 1; break;
            case kOpInc: result = result + 1; break;
            case kOpNeg: result = 0u - result; break;
            case kOpNot: result = ~result; break;
            case kOpTableImm:
                if (param >= context_.size()) return {0, pc, false};
                result = context_[param];
                break;
            case kOpTableMasked: {
                const uint32_t idx = param & result;
                if (idx >= context_.size()) return {0, pc, false};
                result = context_[idx];
                break;
            }
            case kOpSubImm: result = result - param; break;
            case kOpStoreScratch: {
                scratch = result;
                result = scratch;
                break;
            }
            case kOpXorImm: result = result ^ param; break;
            default: return {0, pc, false};  // 未知操作码
        }
    }
    return {result, pc, true};
}

bool DripProgram::eval_lane(size_t lane_index, uint32_t seed, uint32_t& out) const {
    if (lane_index >= lanes_.size()) return false;
    const EvalResult r = eval_records(lanes_[lane_index], 0, 0, 0, seed, 0);
    if (!r.ok) return false;
    out = r.value;
    return true;
}

bool DripProgram::get64_from_u32(uint32_t value, uint64_t& out) const {
    const size_t lane_index = value & 0x7F;
    const uint32_t seed = value >> 7;
    uint32_t lo = 0;
    uint32_t hi = 0;
    if (!eval_lane(lane_index, seed, lo)) return false;
    if (!eval_lane(lane_index, ~seed, hi)) return false;
    out = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
    return true;
}

bool DripProgram::build_filter_state(uint64_t key, uint16_t open_flag, uint8_t out[48]) const {
    if (!valid()) return false;

    uint32_t key_lo = static_cast<uint32_t>(key);
    uint32_t key_hi = static_cast<uint32_t>(key >> 32);
    if ((open_flag & 1) == 0) {
        key_lo ^= holder_words_[2];
        key_hi ^= holder_words_[3];
    }
    const uint64_t key64 = static_cast<uint64_t>(key_lo) | (static_cast<uint64_t>(key_hi) << 32);

    for (int i = 0; i < 48; ++i) out[i] = 0;

    uint64_t v = 0;
    if (!get64_from_u32(key_lo, v)) return false;
    for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(v >> (8 * i));

    if (!get64_from_u32(key_hi, v)) return false;
    for (int i = 0; i < 8; ++i) out[8 + i] = static_cast<uint8_t>(v >> (8 * i));

    const uint32_t bulk_offset =
        holder_words_[5] + (holder_words_[4] & static_cast<uint32_t>(key64 >> 16));
    for (int i = 0; i < 4; ++i) out[16 + i] = static_cast<uint8_t>(bulk_offset >> (8 * i));
    // out[20..23] 保持 0

    // 用 ~get64(~key64) 反复填充 16 字节 bulk_key。
    // `bitpos -= 8` 必须在 if/else **之外**——放进 else 会让 bulk_key 整体错位一字节。
    uint64_t cur = ~key64;
    int bitpos = -1;
    size_t pos = 24;
    while (pos < 40) {
        if (bitpos < 0) {
            if (!get64_from_u32(static_cast<uint32_t>(cur & 0xFFFFFFFFu), v)) return false;
            cur = ~v;
            bitpos = 64;
        } else {
            out[pos] = static_cast<uint8_t>((cur >> bitpos) & 0xFF);
            ++pos;
        }
        bitpos -= 8;
    }

    out[44] = 1;  // has_drip
    out[45] = 0;  // null_mode
    return true;
}

}  // namespace hxv4
