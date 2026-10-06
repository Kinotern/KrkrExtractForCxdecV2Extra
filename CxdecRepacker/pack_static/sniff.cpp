#include "pack_static/sniff.h"

#include <filesystem>
#include <system_error>

namespace hxv4::pack_static {
namespace {

namespace fs = std::filesystem;

bool is_hex_name(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (const char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

// 解包器留下的清单，不是资源
bool is_manifest(const fs::path& p) {
    std::string ext = p.extension().string();
    for (char& c : ext) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return ext == ".alst";
}

// 统一走 UTF-8：路径名要拼进给人看的消息里，用 .string() 会混进 ANSI 变成乱码
std::string name_of(const fs::path& p) { return p.filename().u8string(); }

}  // namespace

const char* mode_name(InputMode mode) {
    switch (mode) {
        case InputMode::SingleDomain: return "模式 1（单域）";
        case InputMode::MultiDomain: return "模式 2（多域）";
        case InputMode::Patch: return "模式 3（平铺补丁）";
        default: return "无法判定";
    }
}

SniffResult sniff_directory(const std::string& utf8_dir) {
    SniffResult r;

    const fs::path dir = fs::u8path(utf8_dir);
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        r.problems.push_back("不是目录：" + utf8_dir);
        r.detail = "不是目录";
        return r;
    }

    uint32_t domain_dirs = 0;
    uint32_t hashed_files = 0;  // 域目录下的 + 根下 64 位 hex 的
    uint32_t flat_files = 0;    // 真实文件名

    for (const auto& e : fs::directory_iterator(dir, ec)) {
        const std::string name = name_of(e.path());

        if (e.is_directory()) {
            if (!is_hex_name(name, 16)) {
                r.problems.push_back("目录名不是 16 位 hex：" + name + "（混合形态？）");
                continue;
            }
            ++domain_dirs;

            uint32_t in_this_domain = 0;
            for (const auto& f : fs::directory_iterator(e.path(), ec)) {
                if (f.is_directory()) {
                    r.problems.push_back("域目录 " + name + " 里还有子目录：" + name_of(f.path()));
                    continue;
                }
                if (!f.is_regular_file()) {
                    r.problems.push_back("域目录 " + name + " 里有非普通文件：" + name_of(f.path()));
                    continue;
                }
                if (is_manifest(f.path())) {
                    ++r.skipped;
                    continue;
                }
                if (!is_hex_name(name_of(f.path()), 64)) {
                    r.problems.push_back("域目录 " + name + " 下的文件名不是 64 位 hex：" +
                                         name_of(f.path()));
                    continue;
                }
                ++in_this_domain;
            }
            if (in_this_domain == 0) r.problems.push_back("域目录是空的：" + name);
            hashed_files += in_this_domain;
            continue;
        }

        if (!e.is_regular_file()) {
            r.problems.push_back("无法识别的条目：" + name);
            continue;
        }
        if (is_manifest(e.path())) {
            ++r.skipped;
            continue;
        }
        if (is_hex_name(name, 64)) {
            ++hashed_files;  // 根域下的哈希名文件
        } else {
            ++flat_files;
        }
    }

    r.domain_count = domain_dirs;
    r.file_count = hashed_files + flat_files;

    // 判定：有问题就不猜
    if (!r.problems.empty()) {
        r.mode = InputMode::Unknown;
        r.detail = "目录形态有 " + std::to_string(r.problems.size()) + " 处问题，无法判定";
        return r;
    }
    if (domain_dirs > 0 && flat_files > 0) {
        r.mode = InputMode::Unknown;
        r.problems.push_back("同时存在域目录和真实文件名，无法判定是哪种模式");
        r.detail = "混合形态，无法判定";
        return r;
    }
    if (r.file_count == 0) {
        r.mode = InputMode::Unknown;
        r.problems.push_back("目录里没有可打包的文件");
        r.detail = "空目录";
        return r;
    }

    if (domain_dirs > 0) {
        r.mode = (domain_dirs == 1) ? InputMode::SingleDomain : InputMode::MultiDomain;
        r.detail = std::string(r.mode == InputMode::SingleDomain ? "单域：" : "多域：") +
                   std::to_string(domain_dirs) + " 个域 / " + std::to_string(r.file_count) + " 个文件";
    } else {
        r.mode = InputMode::Patch;
        r.detail = "平铺：" + std::to_string(r.file_count) + " 个文件（按真实文件名算哈希）";
    }
    if (r.skipped > 0) r.detail += "，忽略 " + std::to_string(r.skipped) + " 个清单文件";
    return r;
}

}  // namespace hxv4::pack_static
