#include "ExportApi.h"

#include "TryExport.h"

#include "pack_static/keystore.h"
#include "pack_static/pack_static.h"
#include "pack_static/sniff.h"

#include <string>
#include <vector>

namespace {

// 模块内部统一用 UTF-8，导出边界上转成 ANSI（与其余模块的 char* 约定一致）
std::string ToUtf8(const wchar_t* s) {
    if (s == nullptr) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// 导出约定里出参是 ANSI，异常消息和正常错误串走同一套转换
using ExportGuard::WriteAnsi;

std::string JoinProblems(const std::vector<std::string>& problems) {
    std::string s;
    for (size_t i = 0; i < problems.size(); ++i) {
        if (i != 0) s += "；";
        s += problems[i];
    }
    return s;
}

}  // namespace

extern "C" BOOL __stdcall SniffInputDir(const wchar_t* inputDir, int* modeOut, char* detailOut,
                                        int detailOutSize, char* errorOut, int errorOutSize) {
    const bool ok = ExportGuard::Run(
        [&](const std::string& m) { WriteAnsi(m, errorOut, errorOutSize); },
        [&]() -> bool {
            if (inputDir == nullptr) {
                WriteAnsi("输入目录为空", errorOut, errorOutSize);
                return false;
            }

            const hxv4::pack_static::SniffResult s =
                hxv4::pack_static::sniff_directory(ToUtf8(inputDir));
            if (modeOut != nullptr) *modeOut = static_cast<int>(s.mode);
            WriteAnsi(s.detail, detailOut, detailOutSize);

            if (!s.ok()) {
                std::string w = "无法判定目录形态";
                if (!s.problems.empty()) w += "：" + JoinProblems(s.problems);
                WriteAnsi(w, errorOut, errorOutSize);
                return false;
            }
            return true;
        });
    return ok ? TRUE : FALSE;
}

extern "C" BOOL __stdcall Repack(const wchar_t* inputDir, const wchar_t* outputXp3,
                                 const wchar_t* exePath, const wchar_t* keysRoot,
                                 const wchar_t* mediaName, int modeOverride, int rescramble,
                                 char* detailOut, int detailOutSize, char* errorOut,
                                 int errorOutSize) {
    const bool ok = ExportGuard::Run(
        [&](const std::string& m) { WriteAnsi(m, errorOut, errorOutSize); },
        [&]() -> bool {
            if (inputDir == nullptr || outputXp3 == nullptr) {
                WriteAnsi("输入目录或输出路径为空", errorOut, errorOutSize);
                return false;
            }

            hxv4::pack_static::PackOptions opts;
            opts.exe_path = ToUtf8(exePath);
            opts.media_name = ToUtf8(mediaName);
            if (keysRoot != nullptr) {
                const std::string root = ToUtf8(keysRoot);
                if (!root.empty()) opts.profile_root = root;
            }
            opts.mode_override = modeOverride;
            opts.rescramble = (rescramble != 0);

            const hxv4::pack_static::PackReport r =
                hxv4::pack_static::pack_static(ToUtf8(inputDir), ToUtf8(outputXp3), opts);
            if (!r.ok()) {
                WriteAnsi(r.error, errorOut, errorOutSize);
                return false;
            }

            std::string d = hxv4::pack_static::mode_name(r.mode);
            d += "，";
            d += std::to_string(r.files);
            d += " 个文件，open_flag=";
            d += std::to_string(r.open_flag);
            d += "，";
            d += std::to_string(r.bytes);
            d += " 字节";
            if (r.rescrambled != 0) {
                d += "（重新加扰 " + std::to_string(r.rescrambled) + " 个文本）";
            }
            // 用了哪套参数必须说清：回落内置时用户得知道结果可能不对
            d += "；参数：";
            d += r.profile_id.empty() ? "?" : r.profile_id;
            if (r.profile_id.rfind("builtin:", 0) == 0) {
                d += "（内置，目标游戏不是它就不会对）";
            }
            // 盐也报出来：它错了完全不报错，只能靠这里看
            d += "，盐=\"";
            d += r.media_name;
            d += "\"";
            // 顺序决定重封包能不能和原件对上，同样得说清
            d += r.ordered_by_manifest ? "，条目顺序按解包清单还原"
                                       : "，条目顺序按哈希排（没有解包清单，与原件不会逐字节一致）";
            if (!r.derive_note.empty()) {
                d += "；";
                d += r.derive_note;
            }
            WriteAnsi(d, detailOut, detailOutSize);
            return true;
        });
    return ok ? TRUE : FALSE;
}

// 这个导出没有错误出参，异常只能吞掉返回 1 —— 代价是可能覆盖已存在的 patch@r1.xp3。
// 内部走的全是 error_code 重载，实际上很难抛。
extern "C" unsigned int __stdcall NextPatchRevision(const wchar_t* gameDir) {
    try {
        if (gameDir == nullptr) return 1;
        const unsigned int r = hxv4::pack_static::next_patch_revision(ToUtf8(gameDir));
        return r == 0 ? 1 : r;
    } catch (...) {
        return 1;
    }
}

extern "C" BOOL __stdcall ImportKeyFile(const wchar_t* hxv4pPath, const wchar_t* exePath,
                                        const wchar_t* keysRoot, char* noteOut, int noteOutSize,
                                        char* errorOut, int errorOutSize) {
    const bool ok = ExportGuard::Run(
        [&](const std::string& m) { WriteAnsi(m, errorOut, errorOutSize); },
        [&]() -> bool {
            if (hxv4pPath == nullptr || keysRoot == nullptr) {
                WriteAnsi("参数文件或仓库目录为空", errorOut, errorOutSize);
                return false;
            }

            std::string note;
            std::string why;
            if (!hxv4::pack_static::ImportProfileHxv4p(ToUtf8(hxv4pPath), ToUtf8(exePath),
                                                       ToUtf8(keysRoot), &note, &why)) {
                WriteAnsi(why, errorOut, errorOutSize);
                return false;
            }
            WriteAnsi(note, noteOut, noteOutSize);
            return true;
        });
    return ok ? TRUE : FALSE;
}

extern "C" BOOL __stdcall DeriveKeys(const wchar_t* exePath, const wchar_t* keysRoot,
                                     char* noteOut, int noteOutSize, char* errorOut,
                                     int errorOutSize) {
    const bool ok = ExportGuard::Run(
        [&](const std::string& m) { WriteAnsi(m, errorOut, errorOutSize); },
        [&]() -> bool {
            if (exePath == nullptr || keysRoot == nullptr) {
                WriteAnsi("游戏 EXE 或仓库目录为空", errorOut, errorOutSize);
                return false;
            }

            std::string note;
            std::string why;
            if (!hxv4::pack_static::DeriveProfile(ToUtf8(exePath), ToUtf8(keysRoot), &note, &why)) {
                WriteAnsi(why, errorOut, errorOutSize);
                return false;
            }
            WriteAnsi(note, noteOut, noteOutSize);
            return true;
        });
    return ok ? TRUE : FALSE;
}
