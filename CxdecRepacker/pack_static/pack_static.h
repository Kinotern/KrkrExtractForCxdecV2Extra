#pragma once

#include "pack_static/profile.h"
#include "pack_static/sniff.h"

#include <cstdint>
#include <string>

namespace hxv4::pack_static {

// 默认 open_flag。真机包实测：基准包（main / uipsd）用 0，补丁包（patch*）用 1。
uint16_t default_open_flag(InputMode mode);

struct PackOptions {
    // 参数缓存目录，默认 "keys"。
    std::string profile_root = "keys";
    // 可选：游戏 EXE。给了就按它找派生参数，找不到回落内置并在报告里写明。
    std::string exe_path;
    // 可选：覆盖盐（pathHash/fileHash 的额外输入串）。
    // 留空就用参数里带的那个（派生产物会记下来，没有则默认 "xp3hnp"）。
    // 只有派生的那套不对时才需要手动指定。
    std::string media_name;
    // 1/2/3；-1 = 用嗅探结果。
    int32_t mode_override = -1;
    // 把干净文本搅回加扰形态。
    bool rescramble = false;
    // >= 0 时覆盖默认 open_flag。
    int32_t open_flag_override = -1;
    // 仓库里没有这个 EXE 的参数时，是否现场派生（调同目录的 CxdecKeyStatic）。默认开。
    bool auto_derive = true;
};

struct PackReport {
    InputMode mode = InputMode::Unknown;
    uint32_t domain_count = 0;
    uint32_t files = 0;
    uint32_t rescrambled = 0;
    uint64_t bytes = 0;
    uint16_t open_flag = 0;
    std::string profile_id;
    std::string profile_note;
    // 这次**实际用到**的盐。写进报告是因为盐错了完全看不出来（不报错、不崩，
    // 游戏只是当这个包不存在），至少让界面能把它显示出来。
    std::string media_name;
    // 条目顺序是否按解包器留下的 .alst 清单还原的。
    // false = 按 file_hash 排的，只是"能用"，结果不会与原件逐字节一致。
    bool ordered_by_manifest = false;
    bool derived = false;        // 这次是不是现场派生出来的
    std::string derive_note;     // 派生的结果或失败原因
    std::string detail;  // 嗅探给的一句话
    std::string error;   // 非空即失败

    bool ok() const { return error.empty() && mode != InputMode::Unknown; }
};

// 目录 → 包。顺序：嗅探 → 定模式 → 取参数 → 枚举 → 写出。
PackReport pack_static(const std::string& utf8_dir, const std::string& utf8_out,
                       const PackOptions& opts);

// 扫描目录里已有的 patch@r<N>.xp3，返回下一个可用修订号（至少 1）。
uint32_t next_patch_revision(const std::string& utf8_game_dir);

}  // namespace hxv4::pack_static
