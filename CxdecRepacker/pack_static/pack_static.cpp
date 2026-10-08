#include "pack_static/pack_static.h"

#include "pack_static/enumerate.h"
#include "pack_static/keystore.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>

namespace hxv4::pack_static {

namespace fs = std::filesystem;

uint16_t default_open_flag(InputMode mode) {
    // 一律 0，补丁包也 0。
    //
    // 这里曾经按"补丁用 1、基准用 0"分模式发标志，来源是一个参考包——那个包靠不住。
    // 实测（HF 国际版 CafeStella）：标志写 1 时，引擎确实用 nonce1 解开了映射表（能查到
    // 我们的 record），但**内容层 filter 的种子状态仍然按 open_flag=0 那套推**，于是我们
    // 按"1"搅出来的密文引擎解不回来 → 图片加载失败、tag 变 void。改回 0、密文按 0 搅，
    // 同一个包立刻在游戏里正常显示。
    //
    // 也就是说：`flags` 的 bit0 只该用来选 nonce，**不能**拿它去改 filter 的推导方向。
    (void)mode;
    return 0;
}

uint32_t next_patch_revision(const std::string& utf8_game_dir) {
    uint32_t best = 0;
    std::error_code ec;
    const fs::path dir = fs::u8path(utf8_game_dir);
    if (!fs::is_directory(dir, ec)) return 1;

    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (!e.is_regular_file()) continue;
        const std::string name = e.path().filename().string();
        if (name.rfind("patch@r", 0) != 0) continue;
        const size_t dot = name.rfind('.');
        if (dot == std::string::npos || dot <= 6) continue;

        const std::string num = name.substr(6, dot - 6);
        bool digits = !num.empty();
        for (const char c : num) {
            if (c < '0' || c > '9') digits = false;
        }
        if (!digits) continue;
        best = std::max(best, static_cast<uint32_t>(std::strtoul(num.c_str(), nullptr, 10)));
    }
    return best + 1;
}

PackReport pack_static(const std::string& utf8_dir, const std::string& utf8_out,
                       const PackOptions& opts) {
    PackReport r;

    // ---- 1. 嗅探 ----
    const SniffResult s = sniff_directory(utf8_dir);
    r.detail = s.detail;
    r.domain_count = s.domain_count;

    InputMode mode = s.mode;
    if (opts.mode_override >= 1 && opts.mode_override <= 3) {
        mode = static_cast<InputMode>(opts.mode_override);
    }
    if (mode == InputMode::Unknown) {
        r.error = "无法判定目录形态";
        if (!s.problems.empty()) {
            r.error += "：";
            for (size_t i = 0; i < s.problems.size(); ++i) {
                if (i != 0) r.error += "；";
                r.error += s.problems[i];
            }
        }
        return r;
    }
    r.mode = mode;

    // ---- 2. 取参数（仓库里没有这个 EXE 就现场派生）----
    const ProfileStore store(opts.profile_root);
    ResolvedProfile pr = store.resolve(opts.exe_path);
    if (pr.origin == ProfileOrigin::Builtin && opts.auto_derive && !opts.exe_path.empty()) {
        std::string note, why;
        if (DeriveProfile(opts.exe_path, opts.profile_root, &note, &why)) {
            const ResolvedProfile again = store.resolve(opts.exe_path);
            if (again.origin == ProfileOrigin::Loaded) {
                pr = again;
                r.derived = true;
                r.derive_note = note;
            }
        } else {
            r.derive_note = "现场派生失败：" + why + "；改用内置参数";
        }
    }
    if (!pr.ok()) {
        r.error = "取不到可用参数";
        return r;
    }
    r.profile_id = pr.profile->id;
    r.profile_note = pr.note;

    // 盐可以由调用方覆盖。派生的那套不对时（非默认 mediaName 的游戏）这是唯一入口；
    // 留空就一路用参数里带的。override 要活到第 4 步枚举，所以在这一层声明。
    GameProfile overridden;
    if (!opts.media_name.empty() && opts.media_name != pr.profile->media_name) {
        overridden = *pr.profile;
        overridden.media_name = opts.media_name;
        pr.profile = &overridden;
        r.profile_note += "；盐已覆盖为 \"" + opts.media_name + "\"";
    }
    r.media_name = pr.profile->media_name;

    // ---- 3. open_flag ----
    r.open_flag = (opts.open_flag_override >= 0)
                      ? static_cast<uint16_t>(opts.open_flag_override)
                      : default_open_flag(mode);

    // ---- 4. 枚举（只出元数据；文件内容留到打包时再按需读）----
    std::vector<PackEntry> entries;
    EnumerateStats stats;
    if (!enumerate_directory(utf8_dir, mode, *pr.profile, opts.rescramble, entries, stats,
                             r.error)) {
        return r;
    }

    // ---- 5. 边编码边落盘 ----
    //
    // 不再把整包拼在内存里：以前 351 MB 的输入要吃掉 1.1～1.4 GB 地址空间，
    // 32 位进程里分配失败就抛 bad_alloc。
    PackContext ctx;
    ctx.drip = &pr.profile->drip;
    ctx.open_flag = r.open_flag;
    ctx.index_keys = pr.profile->index;

    auto sink = MakeFileSink(utf8_out, r.error);
    if (!sink) return r;

    PackStats pack_stats;
    if (!pack_archive_stream(entries, ctx, *sink, pack_stats, r.error)) {
        // 把落盘层的失败现场（步骤 + 路径 + 错误码）拼进来：
        // 只写"写入失败"时，磁盘满、目标被占用、跨盘改名都会长得一模一样。
        const std::string detail = sink->Detail();
        if (!detail.empty()) r.error += " | " + detail;
        return r;  // sink 析构时会把 .part 删掉
    }

    // ---- 6. 收尾：到这一步才把 .part 改名成最终文件 ----
    if (!sink->Finish()) {
        r.error = "写不出文件：" + utf8_out;
        const std::string detail = sink->Detail();
        if (!detail.empty()) r.error += " | " + detail;
        return r;
    }

    r.files = stats.files;
    r.rescrambled = pack_stats.rescrambled;
    r.bytes = pack_stats.bytes;
    r.ordered_by_manifest = stats.ordered_by_manifest;
    return r;
}

}  // namespace hxv4::pack_static
