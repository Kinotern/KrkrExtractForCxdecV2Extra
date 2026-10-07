#include "pack_static/keystore.h"

#include "crypto/blake2s.h"

#include <windows.h>

#include <cctype>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>

namespace hxv4::pack_static {
namespace {

namespace fs = std::filesystem;

constexpr const char* kManifestName = "manifest.txt";
constexpr const char* kProfileName = "profile.hxv4p";

std::string hex_lower(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xF]);
    }
    return s;
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// 参数集 -> 规范字节流。与任何序列化格式无关，只取决于**打包真正用到**的参数。
//
// 两处只取有效部分：context 在有的派生产物里是 3106 项、holder_words 也可能多于 6 项，
// 但 VM 只寻址前 1024 项 / 用前 6 项 —— 多出来的冗余字节混进摘要，会让同一套有效参数
// 算出不同的 keys_hash，缓存就永远命中不了。
std::vector<uint8_t> CanonicalBytes(const Hxv4p::Parameters& p, bool use_keyed) {
    std::vector<uint8_t> out;
    auto put = [&](const uint8_t* data, size_t n) {
        put32(out, static_cast<uint32_t>(n));
        out.insert(out.end(), data, data + n);
    };
    put(p.hxv4_key, sizeof(p.hxv4_key));
    put(p.hxv4_nonce0, sizeof(p.hxv4_nonce0));
    put(p.hxv4_nonce1, sizeof(p.hxv4_nonce1));
    // hash_key 只在用 keyed 哈希时才算数（不同派生来源给的它未必一样）
    if (use_keyed) put(p.hash_key, sizeof(p.hash_key));

    // 盐同样是打包真正用到的参数：换盐结果就不同，摘要得跟着变，
    // 否则「只有盐不同」的两套参数会算出同一个 keys_hash。
    put(reinterpret_cast<const uint8_t*>(p.hash_domain.data()), p.hash_domain.size());

    put32(out, 6);
    for (size_t i = 0; i < 6 && i < p.holder_words.size(); ++i) put32(out, p.holder_words[i]);

    put32(out, 1024);
    for (size_t i = 0; i < 1024 && i < p.context_u32.size(); ++i) put32(out, p.context_u32[i]);

    put32(out, 128);
    for (size_t i = 0; i < 128 && i < p.lanes.size(); ++i) {
        const Hxv4p::Lane& lane = p.lanes[i];
        put32(out, static_cast<uint32_t>(lane.size()));
        for (const Hxv4p::LaneRecord& r : lane) {
            put32(out, r.param);
            put32(out, r.opcode);
        }
    }
    return out;
}

bool read_file(const fs::path& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    const std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    out.assign(static_cast<size_t>(n > 0 ? n : 0), 0);
    if (!out.empty()) f.read(reinterpret_cast<char*>(out.data()), n);
    return static_cast<bool>(f) || f.eof();
}

std::string now_string() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// 字段里不能有制表符和换行，否则 TSV 会被拆坏
void sanitize(std::string& s) {
    for (char& c : s) {
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    }
}

}  // namespace

bool FileDigest(const std::string& utf8_path, std::string& hex_out) {
    hex_out.clear();
    std::ifstream f(fs::u8path(utf8_path), std::ios::binary);
    if (!f) return false;
    crypto::Blake2s h;
    char buf[64 * 1024];
    while (f) {
        f.read(buf, sizeof(buf));
        const std::streamsize got = f.gcount();
        if (got > 0) h.update(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(got));
    }
    uint8_t digest[32];
    h.finalize(digest);
    hex_out = hex_lower(digest, sizeof(digest));
    return true;
}

std::string KeysHash(const Hxv4p::Parameters& params, bool use_keyed) {
    const std::vector<uint8_t> bytes = CanonicalBytes(params, use_keyed);
    uint8_t digest[32];
    crypto::blake2s256(bytes.data(), bytes.size(), digest);
    return hex_lower(digest, sizeof(digest));
}

Manifest::Manifest(std::string path) : path_(std::move(path)) {}

bool Manifest::load() {
    entries_.clear();
    std::ifstream f(fs::u8path(path_));
    if (!f) return true;  // 还不存在就当空的

    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        // 6 段 TSV：exe_digest / keys_hash / store_dir / exe_path / derived_at / source
        std::vector<std::string> f6;
        size_t start = 0;
        for (int i = 0; i < 5; ++i) {
            const size_t tab = line.find('\t', start);
            if (tab == std::string::npos) break;
            f6.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        f6.push_back(line.substr(start));
        if (f6.size() < 3 || f6[2].empty()) continue;  // store_dir 是必需的

        ManifestEntry e;
        e.exe_digest = f6[0];
        e.keys_hash = f6[1];
        e.store_dir = f6[2];
        e.exe_path = (f6.size() > 3) ? f6[3] : "";
        e.derived_at = (f6.size() > 4) ? f6[4] : "";
        e.source = (f6.size() > 5) ? f6[5] : "";
        entries_.push_back(std::move(e));
    }
    return true;
}

bool Manifest::save() const {
    const fs::path p = fs::u8path(path_);
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);

    std::ofstream f(p, std::ios::binary);
    if (!f) return false;
    f << "# exe_digest\tkeys_hash\tstore_dir\texe_path\tderived_at\tsource\n";
    for (const ManifestEntry& e : entries_) {
        std::string a = e.exe_digest, b = e.keys_hash, sd = e.store_dir, c = e.exe_path,
                    d = e.derived_at, s = e.source;
        sanitize(a); sanitize(b); sanitize(sd); sanitize(c); sanitize(d); sanitize(s);
        f << a << '\t' << b << '\t' << sd << '\t' << c << '\t' << d << '\t' << s << '\n';
    }
    return static_cast<bool>(f);
}

const ManifestEntry* Manifest::find_exe(const std::string& exe_digest) const {
    if (exe_digest.empty()) return nullptr;
    for (const ManifestEntry& e : entries_) {
        if (e.exe_digest == exe_digest) return &e;
    }
    return nullptr;
}

void Manifest::upsert(const ManifestEntry& e) {
    // 去重只看这条记录指向哪个目录，同一个 EXE 再来一次只留最新的一条。
    // 不能按 keys_hash 删：同一套参数可能对应多个 EXE，删掉会连累它们的索引，
    // 那两个 EXE 就会互相驱逐、每次都要重新派生。
    const std::string key = e.exe_digest.empty() ? e.store_dir : e.exe_digest;
    for (size_t i = 0; i < entries_.size();) {
        const ManifestEntry& cur = entries_[i];
        const std::string cur_key = cur.exe_digest.empty() ? cur.store_dir : cur.exe_digest;
        if (!key.empty() && cur_key == key) {
            entries_.erase(entries_.begin() + static_cast<ptrdiff_t>(i));
        } else {
            ++i;
        }
    }
    entries_.push_back(e);
}

bool LoadProfileHxv4p(const std::string& utf8_path, GameProfile& out, std::string* why) {
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        return false;
    };

    std::vector<uint8_t> blob;
    if (!read_file(fs::u8path(utf8_path), blob) || blob.empty())
        return fail("读不到参数文件：" + utf8_path);

    Hxv4p::Parameters p;
    std::string err;
    if (!Hxv4p::Decode(blob, p, err)) return fail("解析失败：" + err);

    out = GameProfile{};
    std::memcpy(out.index.root_key.data(), p.hxv4_key, sizeof(p.hxv4_key));
    std::memcpy(out.index.nonce0.data(), p.hxv4_nonce0, sizeof(p.hxv4_nonce0));
    std::memcpy(out.index.nonce1.data(), p.hxv4_nonce1, sizeof(p.hxv4_nonce1));
    std::memcpy(out.hash_key.data(), p.hash_key, sizeof(p.hash_key));

    // 盐：产物里记了就用它——**哪怕是空串**（盐可以就是空的）；只有压根没记
    //（早先的产物没有这个 chunk）才回落默认值。
    out.media_name = p.hash_domain_known ? p.hash_domain : std::string(kDefaultMediaName);

    std::vector<std::vector<DripRecord>> lanes;
    lanes.reserve(p.lanes.size());
    for (const Hxv4p::Lane& lane : p.lanes) {
        std::vector<DripRecord> recs;
        recs.reserve(lane.size());
        for (const Hxv4p::LaneRecord& r : lane) recs.push_back(DripRecord{r.param, r.opcode});
        lanes.push_back(std::move(recs));
    }
    out.drip = DripProgram(p.holder_words, p.context_u32, std::move(lanes));

    out.id = "hxv4p:" + KeysHash(p).substr(0, 16);
    out.source = utf8_path;
    // .hxv4p 表达不了"用不用 keyed 哈希"，而它总是带着一个 hash_key。
    // 读侧用的是 unkeyed，所以这里默认 unkeyed；哪天真遇到 keyed 的游戏再加开关。
    out.use_keyed_hash = false;
    // UNIQUE / archive_seed 不在 hxv4p 里，写侧用不到，留空
    if (!out.valid()) return fail("参数不完整（holder_words / context / lanes 不足）");
    return true;
}

bool ImportProfileHxv4p(const std::string& utf8_hxv4p, const std::string& utf8_exe,
                        const std::string& keys_root, std::string* note_out,
                        std::string* why_out) {
    auto fail = [&](const std::string& m) {
        if (why_out) *why_out = m;
        return false;
    };

    std::vector<uint8_t> blob;
    if (!read_file(fs::u8path(utf8_hxv4p), blob) || blob.empty())
        return fail("读不到参数文件：" + utf8_hxv4p);

    Hxv4p::Parameters p;
    std::string err;
    if (!Hxv4p::Decode(blob, p, err)) return fail("解析失败：" + err);
    if (p.lanes.size() != 128 || p.holder_words.size() < 6 || p.context_u32.size() < 1024)
        return fail("参数不完整：这个 .hxv4p 不是可直接封包的参数集");

    const std::string kh = KeysHash(p);
    std::string exe_digest;
    if (!utf8_exe.empty()) FileDigest(utf8_exe, exe_digest);

    // 存目录用 **EXE 摘要**，不是参数摘要。
    //
    // 曾经想用参数摘要做内容寻址（同一套参数只存一份），实测不成立：
    // 两个来源派生的同一套**有效**参数，因为 lane 程序里 STOP 之后的死尾巴不同，
    // 摘要就会不同（产物却逐字节一致）。而查找本来就是按 EXE 摘要走的，
    // 用 EXE 摘要当目录还顺带避免了同一次派生重复调用时残留旧目录。
    const std::string store_dir = exe_digest.empty() ? kh : exe_digest;

    std::error_code ec;
    const fs::path root = fs::u8path(keys_root);
    const fs::path dir = root / store_dir;
    fs::create_directories(dir, ec);

    const fs::path dst = dir / kProfileName;
    {
        std::ofstream f(dst, std::ios::binary);
        if (!f) return fail("写不出 " + dst.u8string());
        f.write(reinterpret_cast<const char*>(blob.data()),
                static_cast<std::streamsize>(blob.size()));
        if (!f) return fail("写入中断 " + dst.u8string());
    }

    Manifest m((root / kManifestName).u8string());
    m.load();
    ManifestEntry e;
    e.exe_digest = exe_digest;
    e.keys_hash = kh;
    e.store_dir = store_dir;
    e.derived_at = now_string();
    e.source = utf8_hxv4p;
    if (!exe_digest.empty()) e.exe_path = utf8_exe;
    m.upsert(e);
    if (!m.save()) return fail("写不出清单文件");

    if (note_out) {
        *note_out = "参数已收进仓库：" + kh.substr(0, 16) + "…" +
                    (exe_digest.empty() ? "" : "（已建 EXE 索引）");
    }
    return true;
}

namespace {

// 本 DLL 所在的目录，用来找同目录的 CxdecKeyStatic.dll
bool ModuleDir(std::wstring& dir_out) {
    HMODULE h = nullptr;
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(&ModuleDir), &h)) {
        return false;
    }
    wchar_t path[MAX_PATH] = {};
    if (!::GetModuleFileNameW(h, path, MAX_PATH)) return false;
    std::wstring s(path);
    const size_t bs = s.find_last_of(L"\\/");
    dir_out = (bs == std::wstring::npos) ? std::wstring() : s.substr(0, bs + 1);
    return true;
}

// 游戏目录旁已经生成好的产物：
//   <exe 目录>\ExtractKey_Output\Static\<exe 名>_drip_program.hxv4p
//
// 只认与当前 exe **同名**的那一份。同一目录里可能还躺着别的 exe 的参数，
// 收错了会被当成这个 exe 的参数存进仓库，之后一直用错。文件名比较忽略大小写。
bool FindSideProduct(const std::string& utf8_exe, std::string& out) {
    std::error_code ec;
    const fs::path exe = fs::u8path(utf8_exe);
    const fs::path dir = exe.parent_path() / L"ExtractKey_Output" / L"Static";
    if (!fs::is_directory(dir, ec)) return false;

    std::string want = exe.stem().u8string() + "_drip_program.hxv4p";
    for (char& c : want) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        std::string name = entry.path().filename().u8string();
        for (char& c : name) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        if (name == want) {
            out = entry.path().u8string();
            return true;
        }
    }
    return false;
}

}  // namespace

bool HasProfileForExe(const std::string& utf8_exe, const std::string& keys_root) {
    if (utf8_exe.empty() || keys_root.empty()) return false;
    std::string digest;
    if (!FileDigest(utf8_exe, digest)) return false;
    Manifest m((fs::u8path(keys_root) / kManifestName).u8string());
    m.load();
    return m.find_exe(digest) != nullptr;
}

bool DeriveProfile(const std::string& utf8_exe, const std::string& keys_root,
                   std::string* note_out, std::string* why_out) {
    auto fail = [&](const std::string& m) {
        if (why_out) *why_out = m;
        return false;
    };
    if (utf8_exe.empty()) return fail("没指定游戏 EXE");

    // 先确认这个 EXE 读得出来：收编出来的条目是按 EXE 摘要建索引的，读不到摘要
    // 就只能按参数摘要存，那样永远命中不了 —— 与其悄悄成功，不如直接说清楚。
    std::string exe_digest;
    if (!FileDigest(utf8_exe, exe_digest)) return fail("读不到这个 EXE：" + utf8_exe);

    // 1. 游戏目录旁已经生成过就直接收编 —— 同一个游戏不必派生两次
    std::string side;
    if (FindSideProduct(utf8_exe, side)) {
        std::string note, why;
        if (ImportProfileHxv4p(side, utf8_exe, keys_root, &note, &why)) {
            if (note_out) *note_out = "收编游戏目录旁已有的产物：" + note;
            return true;
        }
        // 那份收编不了（残缺或格式不对）就当没看见，照常现场派生
    }

    // 2. 现场派生
    std::wstring dir;
    if (!ModuleDir(dir)) return fail("取不到本模块所在目录");
    const std::wstring dll = dir + L"CxdecKeyStatic.dll";

    HMODULE h = ::LoadLibraryW(dll.c_str());
    if (h == nullptr) return fail("找不到密钥派生模块 CxdecKeyStatic.dll");

    typedef BOOL(__stdcall * tExtractKey)(const wchar_t*, const wchar_t*, char*, int);
    auto fn = (tExtractKey)::GetProcAddress(h, "ExtractKey");
    if (fn == nullptr) {
        ::FreeLibrary(h);
        return fail("CxdecKeyStatic.dll 缺少 ExtractKey 导出");
    }

    // 派生产物先落到仓库下的临时目录，成功后再把 .hxv4p 收进仓库、清掉临时目录——
    // 整个过程不碰游戏目录。
    std::error_code ec;
    const fs::path tmp = fs::u8path(keys_root) / ".derive";
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);

    const std::wstring exe_w = fs::u8path(utf8_exe).wstring();
    const std::wstring tmp_w = tmp.wstring();
    char err[512] = {};
    const BOOL ok = fn(exe_w.c_str(), tmp_w.c_str(), err, sizeof(err));

    std::string hxv4p;
    if (fs::is_directory(tmp, ec)) {
        for (const auto& e : fs::directory_iterator(tmp, ec)) {
            const fs::path& p = e.path();
            if (p.extension() == ".hxv4p" &&
                p.filename().u8string().find("drip_program") != std::string::npos) {
                hxv4p = p.u8string();
                break;
            }
        }
    }
    if (hxv4p.empty()) {
        fs::remove_all(tmp, ec);
        ::FreeLibrary(h);
        return fail(ok ? "派生跑完了但没产出 .hxv4p" : (std::string("派生失败：") + err));
    }

    std::string note, why;
    const bool imported = ImportProfileHxv4p(hxv4p, utf8_exe, keys_root, &note, &why);
    fs::remove_all(tmp, ec);
    ::FreeLibrary(h);
    if (!imported) return fail(why);
    if (note_out) *note_out = "已现场派生并入库：" + note;
    return true;
}

}  // namespace hxv4::pack_static
