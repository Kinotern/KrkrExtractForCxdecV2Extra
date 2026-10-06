#pragma once

#include "hxv4p/Hxv4p.h"
#include "pack_static/profile.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hxv4::pack_static {

// 对文件内容算摘要，十六进制小写。用于给 EXE 建索引、以及给参数集做内容寻址。
bool FileDigest(const std::string& utf8_path, std::string& hex_out);

// 参数集的内容摘要。**只作记录和比对，不作查找主键** —— 查找一律认 EXE 摘要。
//
// 只哈希**打包真正用到**的部分：unkeyed 时 hash_key 根本不参与，就不能算进来——
// 不同派生来源给出的 hash_key 未必一样，算进来会让同一套有效参数得到不同摘要。
// context / holder_words 同理只取前 1024 / 6 项，多出来的冗余不算。
std::string KeysHash(const Hxv4p::Parameters& params, bool use_keyed = false);

// 清单里的一条。
struct ManifestEntry {
    std::string exe_digest;  // EXE 内容摘要
    std::string keys_hash;   // 参数内容摘要（记录用，用来识别参数是否真的变了）
    std::string store_dir;   // 参数文件所在子目录，通常是 exe_digest
    std::string exe_path;    // 只作提示，不作主键
    std::string derived_at;
    std::string source;      // 派生产物来自哪儿

    bool empty() const { return exe_digest.empty(); }
};

// 清单文件：<root>/manifest.txt，每行一条 TSV。
class Manifest {
public:
    explicit Manifest(std::string path);

    bool load();
    bool save() const;

    const ManifestEntry* find_exe(const std::string& exe_digest) const;

    // 同 exe_digest（没给 exe 时按 store_dir）的旧条目会被替换
    void upsert(const ManifestEntry& e);

    const std::vector<ManifestEntry>& entries() const { return entries_; }

private:
    std::string path_;
    std::vector<ManifestEntry> entries_;
};

// 从 .hxv4p 载入参数。失败时 why 写明原因。
bool LoadProfileHxv4p(const std::string& utf8_path, GameProfile& out, std::string* why);

// 把一个 .hxv4p 收进参数仓库：
//   解参数 -> 算 keys_hash -> 落 <root>/<keys_hash>/profile.hxv4p -> 记清单
// exe_path 可空，给了就顺便建 EXE 摘要索引，下次能自动命中。
bool ImportProfileHxv4p(const std::string& utf8_hxv4p, const std::string& utf8_exe,
                        const std::string& keys_root, std::string* note_out,
                        std::string* why_out);

// 从游戏 EXE 取参数并收进仓库。顺序：
//   1. 先看 exe 旁边有没有**已经生成好的**产物（`ExtractKey_Output\Static\<exe名>_drip_program.hxv4p`），
//      有就直接收编 —— 同一个游戏不必派生两次；只认同名的那份，别的 exe 的参数不收。
//   2. 没有才真的去派生：调同目录的 CxdecKeyStatic.dll，产物先落 <keys_root>/.derive，
//      收进仓库后清掉，不碰游戏目录。
bool DeriveProfile(const std::string& utf8_exe, const std::string& keys_root,
                   std::string* note_out, std::string* why_out);

// 仓库里有没有这个 EXE 对应的参数（不载入，只查清单）。
bool HasProfileForExe(const std::string& utf8_exe, const std::string& keys_root);

}  // namespace hxv4::pack_static
