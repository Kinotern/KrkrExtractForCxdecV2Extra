#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hxv4 {

// DripValue 操作码，用「模块内 RVA」标识（`drip_program.json` 里 records 的第二个字段）。
enum DripOp : uint32_t {
    kOpAddImm = 0x17C50,
    kOpRecurse = 0x17C60,
    kOpAddScratch = 0x17CB0,
    kOpMulScratch = 0x17CD0,
    kOpScratchMinusResult = 0x17CF0,
    kOpShlScratch = 0x17D10,
    kOpShrScratch = 0x17D30,
    kOpSubScratch = 0x17D50,
    kOpBitShuffle = 0x17D70,
    kOpSetImm = 0x17DA0,
    kOpSetSeed = 0x17DB0,
    kOpDec = 0x17DD0,
    kOpInc = 0x17DE0,
    kOpNeg = 0x17DF0,
    kOpNot = 0x17E00,
    kOpTableImm = 0x17E10,
    kOpTableMasked = 0x17E30,
    kOpSubImm = 0x17E50,
    kOpStoreScratch = 0x17E60,
    kOpXorImm = 0x17E80,
    kOpStop = 0x51D90,
};

struct DripRecord {
    uint32_t param = 0;
    uint32_t op = 0;
};

// DripValue VM。
//
// 数据层的核心：128 条 lane 程序 + 一张 1024 项 dword 查表，
// 用来把「每文件的 64 位 key」展开成 48 字节的过滤器种子状态。
//
// 语义与 cxdec 的 `xp3_inspect.py`（DripProgram）和 `垃圾站/src/hxv4-core/src/drip.rs`
// 逐条对齐；后者在 CafeStella 真机数据上验证过。
class DripProgram {
public:
    DripProgram() = default;
    DripProgram(std::vector<uint32_t> holder_words, std::vector<uint32_t> context,
                std::vector<std::vector<DripRecord>> lanes);

    bool valid() const {
        return lanes_.size() == 128 && holder_words_.size() >= 6 && context_.size() >= 1024;
    }

    // 以 seed 求值第 `lane_index` 条 lane。
    bool eval_lane(size_t lane_index, uint32_t seed, uint32_t& out) const;

    // `DripValueImpl_get64_from_u32`：低半来自 seed，高半来自 ~seed。
    bool get64_from_u32(uint32_t value, uint64_t& out) const;

    // 构造 48 字节过滤器种子状态。
    //
    // `open_flag` 的 bit0 **为 0 时**才用 `holder_words[2]/[3]` 扰动 key ——
    // 这条方向是实测出来的（见 params/cafestella.h 的 filder_key 注释），别写反。
    bool build_filter_state(uint64_t key, uint16_t open_flag, uint8_t out[48]) const;

    const std::vector<uint32_t>& holder_words() const { return holder_words_; }
    const std::vector<uint32_t>& context() const { return context_; }

private:
    struct EvalResult {
        uint32_t value = 0;
        size_t pc = 0;
        bool ok = false;
    };
    EvalResult eval_records(const std::vector<DripRecord>& lane, size_t pc, uint32_t result,
                            uint32_t scratch, uint32_t seed, int depth) const;

    std::vector<uint32_t> holder_words_;
    std::vector<uint32_t> context_;
    std::vector<std::vector<DripRecord>> lanes_;
};

}  // namespace hxv4
