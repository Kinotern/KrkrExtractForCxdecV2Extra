#pragma once

#include "core/pack.h"
#include "pack_static/profile.h"
#include "pack_static/sniff.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hxv4::pack_static {

struct EnumerateStats {
    uint32_t files = 0;  // 参与打包的资源文件数（不含占位条目）
};

// 按形态把目录枚举成 PackEntry（含条目 0 的占位图）。失败时 err 写明原因。
//
// **只填元数据，不读文件内容**：条目记下 source_path，等打包时再按需读进来。
// 整包因此在内存里待不住——大目录（几百 MB 到几 GB）也能封得出来。
//
// 模式 1/2：文件名已是 64 位 hex，直接当 file_hash，**不再哈希一次**。
// 模式 3  ：文件是真名，用 profile 的哈希方案算 file_hash。
bool enumerate_directory(const std::string& utf8_dir, InputMode mode, const GameProfile& profile,
                         bool rescramble, std::vector<PackEntry>& out, EnumerateStats& stats,
                         std::string& err);

}  // namespace hxv4::pack_static
