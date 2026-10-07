#include "pack_static/enumerate.h"

#include "core/resource_hash.h"
#include "params/cafestella.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <unordered_map>

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

std::string upper_hex(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string bytes_to_upper_hex(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(digits[p[i] >> 4]);
        s.push_back(digits[p[i] & 0xF]);
    }
    return s;
}

// 清单里的排序键。大小写不敏感：解包器写的是大写，目录名大小写则未必。
std::string order_key(const std::string& domain_hex, const std::string& file_hex) {
    return upper_hex(domain_hex) + "|" + upper_hex(file_hex);
}

// 清单写在**输出目录的兄弟**位置上：<输出目录>.alst（见 CxdecExtractor 的
// ExtractCore）。也接受目录里恰好只有一个 .alst 的情况。
// 目录里有多个 .alst 就不猜——宁可退回默认顺序，也不要按错的清单排。
fs::path find_manifest(const fs::path& dir) {
    std::error_code ec;
    fs::path sibling = dir;
    sibling += L".alst";
    if (fs::is_regular_file(sibling, ec)) return sibling;

    fs::path only;
    int found = 0;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (!e.is_regular_file()) continue;
        if (!is_manifest_file(e.path().filename().u8string())) continue;
        only = e.path();
        ++found;
    }
    return found == 1 ? only : fs::path();
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct ManifestEntry {
    uint32_t rank = 0;
    uint64_t key = 0;
    // 老清单每行只有 4 段（hash -> hash），没有 Key 这一段
    bool has_key = false;
};

using ManifestOrder = std::unordered_map<std::string, ManifestEntry>;

// 读清单，得到「(域哈希, 文件哈希) -> 在原包里的条目序号 + 该条目的 Key」。
//
// 每行形如
//   <域哈希>##YSig##<域哈希>##YSig##<文件哈希>##YSig##<文件哈希>[##YSig##<Key>]
// 顺序就是原包的条目顺序，第 0 行是占位条目。UTF-16LE 带 BOM，但内容是纯 ASCII，
// 逐字节取低位即可。清单里只有 hash->hash、没有明文名，所以模式 3 用不上它。
//
// Key 那段是后加的：原包每个文件的过滤器密钥是打包方自由挑的，只存在于包里，
// 不记下来就只能自己另挑一把——顺序和明文都对上了，密文仍然整片不同。
bool load_manifest_order(const fs::path& alst, ManifestOrder& out) {
    if (alst.empty()) return false;

    std::ifstream f(alst, std::ios::binary);
    if (!f) return false;
    const std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    std::string text;
    text.reserve(raw.size() / 2 + 1);
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
        // ASCII 内容的高位字节恒为 0，读到 0x0000 就是结尾
        if (raw[i] == '\0') break;
        text.push_back(raw[i]);
    }
    if (!text.empty() && static_cast<unsigned char>(text[0]) == 0xFF) {
        text.erase(0, 1);  // BOM 的低位字节
    }

    size_t pos = 0;
    uint32_t rank = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        std::string line =
            text.substr(pos, (nl == std::string::npos ? text.size() : nl) - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;

        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const uint32_t this_rank = rank++;  // 行号就是原包条目序号

        std::vector<std::string> fields;
        size_t start = 0;
        while (true) {
            const size_t sep = line.find("##YSig##", start);
            if (sep == std::string::npos) {
                fields.push_back(line.substr(start));
                break;
            }
            fields.push_back(line.substr(start, sep - start));
            start = sep + 8;
        }
        if (fields.size() < 3 || fields[0].empty() || fields[2].empty()) continue;

        ManifestEntry e;
        e.rank = this_rank;
        if (fields.size() >= 5 && fields[4].size() == 16) {
            uint64_t v = 0;
            bool ok = true;
            for (const char c : fields[4]) {
                const int d = hex_val(c);
                if (d < 0) {
                    ok = false;
                    break;
                }
                v = (v << 4) | static_cast<uint64_t>(d);
            }
            if (ok) {
                e.key = v;
                e.has_key = true;
            }
        }
        out.emplace(order_key(fields[0], fields[2]), e);
    }
    return !out.empty();
}

uint32_t rank_in(const ManifestOrder& order, const std::string& key) {
    const auto it = order.find(key);
    return it == order.end() ? 0xFFFFFFFFu : it->second.rank;
}

// 清单里这一条有没有记 Key
bool manifest_key_for(const ManifestOrder& order, const std::string& key, uint64_t& out) {
    const auto it = order.find(key);
    if (it == order.end() || !it->second.has_key) return false;
    out = it->second.key;
    return true;
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

    // 清单要在占位条目之前读：原包第 0 行就是占位条目，它的 Key 同样得还原，
    // 否则条目 0 的密钥对不上、索引里的段表也会跟着差。
    ManifestOrder manifest;
    stats.ordered_by_manifest = load_manifest_order(find_manifest(dir), manifest);

    PackEntry placeholder = make_placeholder(root_domain);
    {
        const std::string key = order_key(bytes_to_upper_hex(root_domain.data(), root_domain.size()),
                                          std::string(cs::kPlaceholderFileHash));
        uint64_t from_manifest = 0;
        if (manifest_key_for(manifest, key, from_manifest)) placeholder.key = from_manifest;
    }
    out.push_back(std::move(placeholder));

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
        std::string manifest_key;  // 清单里的 (域, 文件哈希)；清单里没有的排到最后
    };
    std::vector<Item> items;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (e.is_directory()) {
            const std::string dir_name = e.path().filename().string();
            std::array<uint8_t, 8> domain{};
            parse_hex_into(dir_name, domain.data(), domain.size());
            for (const auto& f : fs::directory_iterator(e.path(), ec)) {
                if (!f.is_regular_file()) continue;
                if (is_manifest_file(f.path().filename().u8string())) continue;  // 清单不是资源
                const std::string file_name = f.path().filename().string();
                Item it;
                it.domain = domain;
                parse_hex_into(file_name, it.file_hash.data(), it.file_hash.size());
                it.path = f.path();
                it.manifest_key = order_key(dir_name, file_name);
                items.push_back(std::move(it));
            }
        } else if (e.is_regular_file()) {
            const std::string file_name = e.path().filename().string();
            if (is_manifest_file(file_name)) continue;  // 清单不是资源
            Item it;
            it.domain = root_domain;
            parse_hex_into(file_name, it.file_hash.data(), it.file_hash.size());
            it.path = e.path();
            it.manifest_key = order_key(bytes_to_upper_hex(root_domain.data(), root_domain.size()),
                                        file_name);
            items.push_back(std::move(it));
        }
    }
    if (items.empty()) {
        err = "目录里没有可打包的文件";
        return false;
    }

    // 优先按解包清单还原**原包的条目顺序**；没有清单才退回按哈希排。
    //
    // 顺序不是无关紧要的：原包每条记录的 filter_flag 低 16 位就是条目序号，而每个
    // 文件的过滤器密钥又是按序号发的——顺序变了，密钥跟着变，整包的密文全不同。
    // 按清单排，重封包才能与原件对上；退回排序只是"能用"。
    std::sort(items.begin(), items.end(), [&](const Item& a, const Item& b) {
        if (stats.ordered_by_manifest) {
            const uint32_t ra = rank_in(manifest, a.manifest_key);
            const uint32_t rb = rank_in(manifest, b.manifest_key);
            if (ra != rb) return ra < rb;
        }
        // 映射表按域分组，同域的记录必须挨在一起
        if (a.domain != b.domain) return a.domain < b.domain;
        return a.file_hash < b.file_hash;
    });

    for (const Item& it : items) {
        PackEntry e;
        e.domain_hash = it.domain;
        e.file_hash = it.file_hash;

        // 清单里记了原包的 Key 就用它——密钥是打包方自由挑的，照着用才能与原件
        // 逐字节一致。没有清单、或老清单没这一列，才自己按序号生成一把。
        uint64_t from_manifest = 0;
        if (manifest_key_for(manifest, it.manifest_key, from_manifest)) {
            e.key = from_manifest;
        } else {
            e.key = hx_per_file_key(stats.files + 1);
        }
        e.index_name = std::u16string(1, static_cast<char16_t>(0x5000 + (stats.files + 1)));
        e.source_path = it.path.u8string();
        e.rescramble = rescramble;
        ++stats.files;
        out.push_back(std::move(e));
    }
    return true;
}

}  // namespace hxv4::pack_static
