#pragma once

#include "core/archive.h"
#include "core/drip.h"

#include <array>
#include <cstdint>
#include <string>

namespace hxv4::pack_static {

// 一个游戏的完整参数集。
//
// 分三层看：索引层材料 + 哈希材料 + 数据层 VM。换游戏时这三层都要换，
// 但索引层与数据层的**公式**不变，变的只是数值。
struct GameProfile {
    std::string id;
    Hxv4Keys index;                      // 映射表 XChaCha20-Poly1305 材料
    std::array<uint8_t, 32> hash_key{};  // 派生产物里带着的 hash_key
    std::string unique;
    uint64_t archive_seed = 0;
    DripProgram drip;                    // holder_words + context + lanes
    std::string source;                  // 参数来源，给界面显示

    // 是否用 keyed BLAKE2s 算 file_hash。**不能靠 hash_key 非零来判断**：
    // 派生产物里总是带着一个 hash_key，但游戏未必用它（读侧用的就是 unkeyed）。
    // 既然 .hxv4p 表达不了这个状态，就单独存一个标志，默认 unkeyed。
    bool use_keyed_hash = false;

    bool valid() const;
};

enum class ProfileOrigin {
    Builtin,  // 编译期内置
    Loaded,   // 从参数仓库载入
};

struct ResolvedProfile {
    const GameProfile* profile = nullptr;
    ProfileOrigin origin = ProfileOrigin::Builtin;
    std::string note;  // 给用户看的一句话；回落时必须说清

    bool ok() const { return profile != nullptr; }
};

// 参数仓库。
//
//   <root>/manifest.txt                   索引：EXE 摘要 → 参数摘要，带来源留痕
//   <root>/<keys_hash>/profile.hxv4p      参数本体
//
// 用**参数摘要**当主键而不是 EXE 摘要：同一个游戏换个 exe（比如自己改过几字节的
// crack 版）参数并没变，用 EXE 摘要做主键会重复存、重复派生。
class ProfileStore {
public:
    explicit ProfileStore(std::string root_dir);

    // 按 EXE 找参数：查清单 → 取 keys_hash → 载入参数。
    // 找不到就回落内置，并在 note 里写明用的是哪一套。
    ResolvedProfile resolve(const std::string& utf8_exe_path) const;

    // 内置参数。离线可用，也是自检基准。
    static const GameProfile& builtin();

private:
    std::string root_;
};

}  // namespace hxv4::pack_static
