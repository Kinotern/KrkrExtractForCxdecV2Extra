#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// hxv4p：Hxv4 解密参数的二进制容器

namespace Hxv4p {

constexpr uint32_t kMagic = 0x31505848;  // 'HXP1'
constexpr uint16_t kFormatVersion = 1;

constexpr uint32_t kFlagZlib        = 0x0001;
constexpr uint32_t kFlagOpcodeIndex = 0x0002;
constexpr uint32_t kFlagRva         = 0x0004;

constexpr uint16_t kChunkIdentity    = 0x0001;
constexpr uint16_t kChunkKeyMaterial = 0x0002;
constexpr uint16_t kChunkHolderWords = 0x0003;
constexpr uint16_t kChunkTable       = 0x0004;
constexpr uint16_t kChunkLanes       = 0x0005;
constexpr uint16_t kChunkParams      = 0x0006;
constexpr uint16_t kChunkBootstrap   = 0x0007;
constexpr uint16_t kChunkHashDomain  = 0x0008;

constexpr size_t kTableMin = 1024;
constexpr uint32_t kVaLowerBound = 0x1000000;

extern const uint32_t kOpcodes[21];
constexpr size_t kOpcodeCount = 21;

int OpcodeIndexOf(uint32_t callbackRva);

struct LaneRecord {
    uint32_t param;
    uint32_t opcode;  // 模块内 RVA
};

using Lane = std::vector<LaneRecord>;

struct Parameters {
    std::string source_module;
    uint32_t source_module_base = 0;
    uint32_t manager_va = 0;
    uint32_t context_va = 0;
    uint32_t drip_impl_va = 0;

    uint8_t hxv4_key[32] = {};
    uint8_t hxv4_nonce0[24] = {};
    uint8_t hxv4_nonce1[24] = {};
    uint8_t hash_key[32] = {};

    // pathHash / fileHash 的盐，也就是运行时 CompoundStorageMedia 的 mediaName
    //（STARTUP.TJS 里 bootstrapPrefix 含冒号时取冒号前那段，否则用默认值）。
    // UTF-8。空串是**合法值**（盐可以就是空串），所以另配一个 hash_domain_known
    // 区分「记了但是空」和「压根没记」——只有后者才该回落默认值。
    std::string hash_domain;
    bool hash_domain_known = false;

    std::vector<uint32_t> holder_words;
    std::vector<uint32_t> context_u32;
    std::vector<Lane> lanes;
};

// 把 lane 里的绝对 VA 归一化成模块内 RVA。返回是否做过归一。
bool NormalizeLanesToRva(std::vector<Lane>& lanes, uint32_t source_module_base);

std::vector<uint8_t> EncodePayload(const Parameters& params, std::string& error);

// compress=true 时包成合法 zlib 流（deflate stored block，不压缩）。
// 本仓库只有 inflate、没有 deflate；该文件每游戏只写一次，12 KB 与 8.5 KB 的差别不值得引依赖。
std::vector<uint8_t> Encode(const Parameters& params, bool compress, std::string& error);

// 按 flags.bit0 自动识别压缩，未知 chunk 跳过。
bool Decode(const std::vector<uint8_t>& blob, Parameters& out, std::string& error);

uint32_t Crc32(const uint8_t* data, size_t size);

}  // namespace Hxv4p
