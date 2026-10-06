#include "pack_static/profile.h"

#include "pack_static/keystore.h"
#include "params/cafestella.h"

#include <cstring>
#include <filesystem>
#include <utility>

namespace hxv4::pack_static {
namespace {

namespace fs = std::filesystem;

void parse_hex(const std::string& hex, uint8_t* out, size_t out_len) {
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

}  // namespace

bool GameProfile::valid() const {
    return drip.valid() && !id.empty();
}

ProfileStore::ProfileStore(std::string root_dir) : root_(std::move(root_dir)) {}

const GameProfile& ProfileStore::builtin() {
    static const GameProfile p = [] {
        namespace cs = hxv4::params::cafestella;
        GameProfile g;
        g.id = "builtin:cafestella";
        parse_hex(std::string(cs::kHxv4Key), g.index.root_key.data(), g.index.root_key.size());
        parse_hex(std::string(cs::kHxv4Nonce0), g.index.nonce0.data(), g.index.nonce0.size());
        parse_hex(std::string(cs::kHxv4Nonce1), g.index.nonce1.data(), g.index.nonce1.size());
        g.unique = std::string(cs::kUnique);
        g.archive_seed = cs::kArchiveSeed;
        g.drip = cs::drip_program();
        // 读侧用的是 unkeyed，走这条
        g.use_keyed_hash = false;
        g.source = "编译期内置";
        return g;
    }();
    return p;
}

ResolvedProfile ProfileStore::resolve(const std::string& utf8_exe_path) const {
    ResolvedProfile r;

    if (!utf8_exe_path.empty() && !root_.empty()) {
        std::string digest;
        if (FileDigest(utf8_exe_path, digest)) {
            Manifest m((fs::u8path(root_) / "manifest.txt").u8string());
            m.load();
            if (const ManifestEntry* e = m.find_exe(digest)) {
                // 静态持有：返回的是指针，得保证生命周期。参数只读，不会有竞争。
                static GameProfile cached;
                std::string why;
                const fs::path p = fs::u8path(root_) / e->store_dir / "profile.hxv4p";
                if (LoadProfileHxv4p(p.u8string(), cached, &why)) {
                    r.profile = &cached;
                    r.origin = ProfileOrigin::Loaded;
                    r.note = "已载入该游戏派生的参数（" + e->keys_hash.substr(0, 16) + "…）";
                    return r;
                }
                r.note = "清单里有记录但参数载不出来（" + why + "），";
            } else {
                r.note = "这个 EXE 还没派生过参数，";
            }
        } else {
            r.note = "读不到该 EXE，";
        }
    }

    // 回落：必须说清用的是哪一套，别让用户以为已经按他的游戏派生了
    r.profile = &builtin();
    r.origin = ProfileOrigin::Builtin;
    r.note += "使用内置参数（" + builtin().id + "）；目标游戏不是它的话结果不会对";
    return r;
}

}  // namespace hxv4::pack_static
