#pragma once

#include "core/archive.h"
#include "core/drip.h"
#include "core/mapping.h"
#include "core/resource_hash.h"
#include "core/xp3.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hxv4 {

// 一条待写出的条目。
struct PackEntry {
    std::array<uint8_t, 8> domain_hash{};  // 域哈希（写进映射表的那 8 字节）
    Hash32 file_hash{};
    uint64_t key = 0;                 // 写进映射表的 per-file key（原样，不做 XOR）
    std::vector<uint8_t> plaintext;   // 明文（未过滤、未压缩）
    std::u16string index_name;        // 索引 info 里的名字（原包是生成的假名）
    uint32_t info_flags = 0x80000000u;
    bool compress = false;

    // 数据来源可以改成"按需从磁盘读"，这样整包不必先在内存里拼好。
    // 非空时优先读它；留空才用上面的 plaintext（条目 0 的占位图很小，还留在内存里）。
    std::string source_path;
    // 这个条目要不要重新加扰。原来在枚举阶段无条件做，现在下沉到编码阶段——
    // 那时数据才刚读进来，加扰完正好接着过滤，不用多留一份。
    bool rescramble = false;

    // raw = true：数据原样写出，**不过过滤器、不压缩**。
    // 条目 0 那张警告占位图就是这样（游戏也不读它）。
    bool raw = false;

    // 段表覆盖：非空时原样写入，跳过常规布局。
    // 用来复刻原包的怪癖（例如条目 0 那条指向 PNG 中段的陈旧 segm）。
    std::vector<Xp3Segment> segments_override;
};

struct PackContext {
    const DripProgram* drip = nullptr;  // 数据层 VM，必需
    uint16_t open_flag = 0;

    Hxv4Keys index_keys{};  // 索引层 XChaCha20-Poly1305 材料
};

// 打包的输出目标。布局逻辑只写一遍，内存版和落盘版共用，
// 免得两条路径将来产生不一样的字节。
struct ArchiveSink {
    virtual ~ArchiveSink() = default;
    virtual bool Write(const uint8_t* data, size_t len) = 0;
    // 回头补写某处：index_offset 要等负载写完才知道，只能先占位再回填。
    virtual bool Patch(uint64_t offset, const uint8_t* data, size_t len) = 0;
    virtual uint64_t Tell() const = 0;
    // 收尾。文件 sink 在这里才把 .part 改名成最终文件。
    virtual bool Finish() { return true; }
};

// 落盘用的 sink。写的是 <path>.part，Finish() 成功才改名过去——
// 中途失败只会留个 .part，不会让游戏读到半截的补丁包。
// 返回 nullptr 时 err 写明原因。
std::unique_ptr<ArchiveSink> MakeFileSink(const std::string& utf8_path, std::string& err);

struct PackStats {
    // 文件数由枚举阶段给（它才知道哪些是真实文件），这里只管打包过程中才知道的。
    uint32_t rescrambled = 0;
    uint64_t bytes = 0;
};

// 边编码边往 sink 里写。峰值内存只有一个文件的量级（明文 + 变换后的一份），
// 不再随整包大小增长。
bool pack_archive_stream(const std::vector<PackEntry>& entries, const PackContext& ctx,
                         ArchiveSink& sink, PackStats& stats, std::string& err);

// 按 hxv4 变体 XP3 写出。失败返回空 vector。
//
// 数据层的 seed 由 `entry.key` 经 `filter_seed()` 推出（与读侧同一套规则），
// 所以调用者只需要决定「往映射表里写什么 key」。
//
// 整包进内存的版本，只留给小规模的复刻验证用；正经打包走 pack_archive_stream。
std::vector<uint8_t> pack_archive(const std::vector<PackEntry>& entries, const PackContext& ctx);

// 原工具用的 per-file key 生成器：splitmix64，种子 0x55555555，按枚举顺序。
// 这只是写侧的一种选择——映射表里的 key 本来就是写侧的自由度，
// 用它是为了让结果与原工具的行为一致，便于对照。
uint64_t hx_per_file_key(size_t index);

// 从一条 XP3 读出全部内容再原样重写一遍（T0 逐字节复刻验证用）。
// 依赖 `read_hxv4_mapping` 那套密钥材料。
bool rebuild_archive(const uint8_t* data, size_t len, const Hxv4Keys& keys,
                     const DripProgram& drip, std::vector<uint8_t>& out);

}  // namespace hxv4
