#include "pack_static/pack_static.h"

#include "pack_static/enumerate.h"
#include "pack_static/keystore.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace hxv4::pack_static {

namespace fs = std::filesystem;

uint16_t default_open_flag(InputMode mode) {
    // 补丁包用 1、基准包用 0，来自真机包实测
    return mode == InputMode::Patch ? 1 : 0;
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

    // ---- 3. open_flag ----
    r.open_flag = (opts.open_flag_override >= 0)
                      ? static_cast<uint16_t>(opts.open_flag_override)
                      : default_open_flag(mode);

    // ---- 4. 枚举 ----
    std::vector<PackEntry> entries;
    EnumerateStats stats;
    if (!enumerate_directory(utf8_dir, mode, *pr.profile, opts.rescramble, entries, stats,
                             r.error)) {
        return r;
    }

    // ---- 5. 打包 ----
    PackContext ctx;
    ctx.drip = &pr.profile->drip;
    ctx.open_flag = r.open_flag;
    ctx.index_keys = pr.profile->index;

    const std::vector<uint8_t> bytes = pack_archive(entries, ctx);
    if (bytes.empty()) {
        r.error = "打包失败（参数与数据不匹配？）";
        return r;
    }

    // ---- 6. 写出 ----
    std::ofstream f(fs::u8path(utf8_out), std::ios::binary);
    if (!f) {
        r.error = "写不出文件：" + utf8_out;
        return r;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!f) {
        r.error = "写入中断：" + utf8_out;
        return r;
    }

    r.files = stats.files;
    r.rescrambled = stats.rescrambled;
    r.bytes = bytes.size();
    return r;
}

}  // namespace hxv4::pack_static
