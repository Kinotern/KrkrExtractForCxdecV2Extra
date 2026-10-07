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

    // 是否按解包器留下的 .alst 清单还原了**原包的条目顺序**。
    //
    // 为什么这件事重要：原包每条记录的 filter_flag 低 16 位就是条目序号，而每个
    // 文件的过滤器密钥又是按序号发的——顺序变了，密钥跟着变，整包的密文就全不同。
    // 有清单时才能与原件对上；false 表示退回按 file_hash 排，那只是"能用"。
    bool ordered_by_manifest = false;
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
