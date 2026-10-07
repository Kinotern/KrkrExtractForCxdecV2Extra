#include "pack_static/enumerate.h"

#include "core/resource_hash.h"
#include "params/cafestella.h"

#include <algorithm>
#include <array>
#include <filesystem>

namespace hxv4::pack_static {
namespace {

namespace fs = std::filesystem;
namespace cs = hxv4::params::cafestella;

void parse_hex_into(const std::string& hex, uint8_t* out, size_t out_len) {
    size_t n = 0;
    int hi = -1;
    for (const char c : hex) {
        int v;
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        } else {
            continue;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n < out_len) out[n++] = static_cast<uint8_t>((hi << 4) | v);
            hi = -1;
        }
    }
}

// 域哈希按**大端**写进 8 字节域字段。
// CafeStella 实测：根域算得 0x94D4A97C61498621，索引里存的正是 94 D4 A9 7C …
std::array<uint8_t, 8> domain_bytes(uint64_t value) {
    std::array<uint8_t, 8> b{};
    for (int i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>(value >> (8 * (7 - i)));
    return b;
}

// 条目 0 的警告占位图。它全工具一致，与游戏无关。
//
// 它的 file_hash 用的是**抄下来的常量**，只对这套盐（"xp3hnp"）成立——
// 占位图的逻辑名我们不知道，没法按盐重算。换了盐这条会不准，
// 但游戏从来不读条目 0，所以只是复刻比对时的一个已知差异。
PackEntry make_placeholder(const std::array<uint8_t, 8>& domain) {
    PackEntry e0;
    e0.domain_hash = domain;
    e0.index_name = std::u16string(1, static_cast<char16_t>(0x5000));
    parse_hex_into(std::string(cs::kPlaceholderFileHash), e0.file_hash.data(), e0.file_hash.size());
    e0.key = hx_per_file_key(0);
    e0.raw = true;
    e0.info_flags = 0;
    e0.plaintext.assign(cs::placeholder(), cs::placeholder() + cs::kPlaceholderSize);
    return e0;
}

Hash32 hash_for_name(const GameProfile& profile, const std::u16string& name) {
    if (profile.use_keyed_hash) {
        return file_hash_keyed(name, profile.hash_key.data(), profile.media_name);
    }
    return file_hash(name, profile.media_name);
}

}  // namespace

bool enumerate_directory(const std::string& utf8_dir, InputMode mode, const GameProfile& profile,
                         bool rescramble, std::vector<PackEntry>& out, EnumerateStats& stats,
                         std::string& err) {
    out.clear();
    stats = EnumerateStats{};

    if (!profile.valid()) {
        err = "参数不完整，无法打包";
        return false;
    }

    const fs::path dir = fs::u8path(utf8_dir);
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        err = "不是目录：" + utf8_dir;
        return false;
    }

    const auto root_domain = domain_bytes(domain_hash(u"", profile.media_name));
    out.push_back(make_placeholder(root_domain));

    if (mode == InputMode::Patch) {
        std::vector<fs::path> files;
        for (const auto& e : fs::directory_iterator(dir, ec)) {
            if (!e.is_regular_file()) continue;
            // 解包器留下的 .alst 清单不是资源。嗅探那边也是这么跳过的——
            // 两边判断必须一致，否则报告说「忽略 N 个」，包却照样多打进去。
            if (is_manifest_file(e.path().filename().u8string())) continue;
            files.push_back(e.path());
        }
        if (files.empty()) {
            err = "目录里没有文件";
            return false;
        }
        std::sort(files.begin(), files.end());

        for (const fs::path& f : files) {
            PackEntry e;
            e.domain_hash = root_domain;
            e.index_name = f.filename().u16string();
            e.file_hash = hash_for_name(profile, e.index_name);
            e.key = hx_per_file_key(stats.files + 1);
            e.source_path = f.u8string();
            e.rescramble = rescramble;
            ++stats.files;
            out.push_back(std::move(e));
        }
        return true;
    }

    // 模式 1/2：域目录 + 哈希名文件，名字本身就是哈希，不能再哈希一次
    struct Item {
        std::array<uint8_t, 8> domain;
        Hash32 file_hash;
        fs::path path;
    };
    std::vector<Item> items;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (e.is_directory()) {
            std::array<uint8_t, 8> domain{};
            parse_hex_into(e.path().filename().string(), domain.data(), domain.size());
            for (const auto& f : fs::directory_iterator(e.path(), ec)) {
                if (!f.is_regular_file()) continue;
                if (is_manifest_file(f.path().filename().u8string())) continue;  // 清单不是资源
                Item it;
                it.domain = domain;
                parse_hex_into(f.path().filename().string(), it.file_hash.data(),
                               it.file_hash.size());
                it.path = f.path();
                items.push_back(std::move(it));
            }
        } else if (e.is_regular_file()) {
            if (is_manifest_file(e.path().filename().u8string())) continue;  // 清单不是资源
            Item it;
            it.domain = root_domain;
            parse_hex_into(e.path().filename().string(), it.file_hash.data(), it.file_hash.size());
            it.path = e.path();
            items.push_back(std::move(it));
        }
    }
    if (items.empty()) {
        err = "目录里没有可打包的文件";
        return false;
    }
    // 映射表按域分组，同域的记录必须挨在一起
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.domain != b.domain) return a.domain < b.domain;
        return a.file_hash < b.file_hash;
    });

    for (const Item& it : items) {
        PackEntry e;
        e.domain_hash = it.domain;
        e.file_hash = it.file_hash;
        e.key = hx_per_file_key(stats.files + 1);
        e.index_name = std::u16string(1, static_cast<char16_t>(0x5000 + (stats.files + 1)));
        e.source_path = it.path.u8string();
        e.rescramble = rescramble;
        ++stats.files;
        out.push_back(std::move(e));
    }
    return true;
}

}  // namespace hxv4::pack_static
