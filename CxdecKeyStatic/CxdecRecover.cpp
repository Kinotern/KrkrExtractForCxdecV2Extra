#include "CxdecRecover.h"
#include "PeResource.h"
#include "BresDecrypt.h"
#include "Tjs2Decompile.h"
#include "BootstrapExtract.h"
#include "FilterManager.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>

namespace Engine {

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int wsz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wsz <= 0) return {};
    std::wstring out(wsz - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], wsz);
    return out;
}

// --- 自动检测salt候选 ---

static std::vector<size_t> find_salt_candidates(const uint8_t* data, size_t size,
                                                  size_t salt_size) {
    std::vector<size_t> candidates;

    // 1) V2Link标记：salt在标记前salt_size字节处
    const char marker[] = "V2Link";
    for (size_t i = 0; i + sizeof(marker) <= size; ++i) {
        if (memcmp(data + i, marker, sizeof(marker) - 1) == 0) {
            if (i >= salt_size)
                candidates.push_back(i - salt_size);
        }
    }

    // 2) forcedataxp3标记：附近对齐到0x10的区域
    const char marker2[] = "forcedataxp3";
    for (size_t i = 0; i + sizeof(marker2) <= size; ++i) {
        if (memcmp(data + i, marker2, sizeof(marker2) - 1) == 0) {
            size_t start = (i + sizeof(marker2) - 1 + 0xF) & ~(size_t)0xF;
            size_t end = (i + 0x100 < size) ? (i + 0x100) : size;
            if (end > size - salt_size) end = size - salt_size;
            for (size_t off = start; off <= end; off += 0x10) {
                if (off + salt_size <= size)
                    candidates.push_back(off);
            }
        }
    }

    // 3) 代码模式：mov dword ptr [VA], offset; mov dword ptr [size], salt_size
    for (size_t pos = 0; pos + 10 <= size; ++pos) {
        if (data[pos] == 0xC7 && data[pos+1] == 0x05 && pos + 6 <= size) {
            uint32_t salt_va = (uint32_t)data[pos+6]
                             | ((uint32_t)data[pos+7] << 8)
                             | ((uint32_t)data[pos+8] << 16)
                             | ((uint32_t)data[pos+9] << 24);
            if (salt_va < 0x400000) continue;

            size_t limit = (pos + 64 < size) ? (pos + 64) : size;
            for (size_t j = pos + 10; j + 5 <= limit; ++j) {
                if (data[j] == 0xC7 && data[j+1] == 0x05) {
                    uint32_t sz_val = (uint32_t)data[j+6]
                                    | ((uint32_t)data[j+7] << 8)
                                    | ((uint32_t)data[j+8] << 16)
                                    | ((uint32_t)data[j+9] << 24);
                    if (sz_val == (uint32_t)salt_size) {
                        uint32_t salt_rva = salt_va - 0x400000;
                        if (salt_rva + salt_size <= size)
                            candidates.push_back(salt_rva);
                        break;
                    }
                }
            }
        }
    }

    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

// --- TEXT/127提取：解析bres URL并提取key ---

static std::string extract_bres_key_from_utf16le(const uint8_t* data, size_t len) {
    if (len < 2) return {};

    std::wstring ws;
    for (size_t i = 0; i + 1 < len; i += 2) {
        wchar_t ch = (wchar_t)data[i] | ((wchar_t)data[i+1] << 8);
        if (ch == 0) break;
        ws.push_back(ch);
    }

    // 去除BOM
    if (!ws.empty() && ws[0] == 0xFEFF)
        ws.erase(0, 1);

    // 转换为UTF-8以便字符串操作
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string url(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &url[0], sz, nullptr, nullptr);

    // 提取key：格式"bres://./KEY"或"bres://./KEY/"
    const char prefix[] = "bres://./";
    size_t pos = url.find(prefix);
    if (pos == std::string::npos) {
        // 返回去除前后的URL作为key
        while (!url.empty() && url.back() == '/') url.pop_back();
        return url;
    }

    std::string key = url.substr(pos + strlen(prefix));
    while (!key.empty() && (key.back() == '/' || key.back() == '\\'))
        key.pop_back();
    return key;
}

// --- 在解密后的STARTUP.TJS字节中查找bootstrap URL（UTF-16LE搜索）---

static std::string find_bootstrap_url_in_bytes(const uint8_t* data, size_t len) {
    // "bres://./"的UTF-16LE编码
    const uint8_t prefix[] = {0x62,0x00, 0x72,0x00, 0x65,0x00, 0x73,0x00,
                               0x3a,0x00, 0x2f,0x00, 0x2f,0x00, 0x2e,0x00, 0x2f,0x00};
    const size_t prefix_len = sizeof(prefix);

    for (size_t pos = 0; pos + prefix_len <= len; pos += 2) {
        if (memcmp(data + pos, prefix, prefix_len) != 0) continue;

        size_t end = pos;
        while (end + 1 < len) {
            if (data[end] == 0 && data[end+1] == 0) break;
            end += 2;
        }

        std::wstring ws;
        for (size_t i = pos; i + 1 < end; i += 2) {
            wchar_t ch = (wchar_t)data[i] | ((wchar_t)data[i+1] << 8);
            if (ch == 0) break;
            ws.push_back(ch);
        }

        // 不区分大小写检查bootstrap
        std::wstring lower = ws;
        for (auto& c : lower) c = towlower(c);
        if (lower.find(L"bootstrap") == std::wstring::npos) {
            pos = end + 2;
            continue;
        }

        int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sz <= 0) { pos = end + 2; continue; }
        std::string url(sz - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &url[0], sz, nullptr, nullptr);
        return url;
    }
    return {};
}

// 从URL提取key："bres://./KEY/bootstrap" -> "KEY"
static std::string bres_key_from_url(const std::string& url) {
    const char prefix[] = "bres://./";
    size_t p = url.find(prefix);
    if (p == std::string::npos) return {};
    p += strlen(prefix);
    size_t slash = url.find('/', p);
    if (slash == std::string::npos) slash = url.size();
    return url.substr(p, slash - p);
}

// --- 主入口 ---

bool recover_drip_program(const std::wstring& exe_path,
                           const std::wstring& output_dir,
                           const GameParams& params,
                           std::string* error_out) {
#define FAIL(msg) do { if (error_out) *error_out = (msg); return false; } while(0)

    // 1. 将整个EXE读入内存
    std::vector<uint8_t> exe_data;
    {
        std::ifstream f(exe_path, std::ios::binary | std::ios::ate);
        if (!f) FAIL("Cannot open EXE");
        exe_data.resize((size_t)f.tellg());
        f.seekg(0);
        f.read((char*)exe_data.data(), exe_data.size());
        if (exe_data.empty()) FAIL("EXE is empty");
    }

    // 2. 读取PE资源
    auto startup_ct = PeResource::read_rcdata(exe_path.c_str(), L"STARTUP.TJS");
    if (startup_ct.empty()) FAIL("STARTUP.TJS resource not found");

    auto bootstrap_ct = PeResource::read_rcdata(exe_path.c_str(), L"BOOTSTRAP");
    if (bootstrap_ct.empty()) FAIL("BOOTSTRAP resource not found");

    // 3. 确定startup filter path（从TEXT/127自动或手动）
    std::wstring startup_filter_path = params.startup_filter_path;
    if (startup_filter_path.empty()) {
        // 先尝试Windows API，再尝试手动PE解析器
        auto text127 = PeResource::read_custom_resource(exe_path.c_str(), L"TEXT", 127);
        if (text127.empty())
            text127 = PeResource::read_custom_resource(
                exe_data.data(), exe_data.size(), "TEXT", 127);
        if (text127.empty())
            FAIL("Cannot auto-detect startup filter path (TEXT/127 not found)");

        std::string key = extract_bres_key_from_utf16le(text127.data(), text127.size());
        if (key.empty())
            FAIL("TEXT/127 resource produced an empty startup key");

        int wlen = MultiByteToWideChar(CP_UTF8, 0, key.c_str(), -1, nullptr, 0);
        if (wlen <= 0) FAIL("UTF-8 to wide conversion failed");
        startup_filter_path.resize(wlen - 1);
        MultiByteToWideChar(CP_UTF8, 0, key.c_str(), -1, &startup_filter_path[0], wlen);
    }

    // 4. 生成salt候选并找到正确的
    std::vector<size_t> candidates;
    if (params.salt_offset > 0) {
        candidates.push_back(params.salt_offset);
    } else {
        candidates = find_salt_candidates(exe_data.data(), exe_data.size(),
                                           params.salt_size);
    }
    if (candidates.empty())
        FAIL("Cannot find any salt candidates in EXE");

    const uint8_t* salt_ptr = nullptr;
    std::vector<uint8_t> startup_plain;

    for (size_t cand : candidates) {
        if (cand + params.salt_size > exe_data.size()) continue;
        const uint8_t* trial_salt = exe_data.data() + cand;
        std::vector<uint8_t> plain;

        if (!Crypto::bres_decrypt(startup_filter_path,
                                   trial_salt, params.salt_size,
                                   startup_ct.data(), startup_ct.size(), plain))
            continue;

        if (plain.size() >= 8 && memcmp(plain.data(), "TJS2100\x00", 8) == 0) {
            salt_ptr = trial_salt;
            startup_plain = std::move(plain);
            break;
        }
    }

    if (!salt_ptr || startup_plain.empty())
        FAIL("Cannot find valid salt -- decrypted STARTUP.TJS is not TJS2100 bytecode");

    // 5. 提取TJS2字符串用于prefix/URL提取
    auto str_result = Tjs2::extract_strings(startup_plain.data(), startup_plain.size());

    // 6. 确定bootstrap filter path（从STARTUP.TJS自动或手动）
    std::wstring bootstrap_filter_path = params.bootstrap_filter_path;
    if (bootstrap_filter_path.empty()) {
        std::string bootstrap_url;
        if (str_result.ok)
            bootstrap_url = Tjs2::find_bootstrap_url(str_result.strings);
        if (bootstrap_url.empty())
            bootstrap_url = find_bootstrap_url_in_bytes(startup_plain.data(),
                                                         startup_plain.size());
        if (bootstrap_url.empty())
            FAIL("Bootstrap bres URL not found in decrypted STARTUP.TJS");

        std::string bkey = bres_key_from_url(bootstrap_url);
        if (bkey.empty())
            FAIL("Cannot parse bootstrap key from bres URL");

        int wlen = MultiByteToWideChar(CP_UTF8, 0, bkey.c_str(), -1, nullptr, 0);
        if (wlen <= 0) FAIL("UTF-8 to wide conversion failed");
        bootstrap_filter_path.resize(wlen - 1);
        MultiByteToWideChar(CP_UTF8, 0, bkey.c_str(), -1, &bootstrap_filter_path[0], wlen);
    }

    // 7. 查找bootstrap prefix（某些游戏可能为空）
    std::string prefix_utf8;
    if (str_result.ok) {
        prefix_utf8 = Tjs2::find_bootstrap_prefix(str_result.strings);
    }
    // 回退：在UTF-16LE字节中搜索"All Rights Reserved"
    if (prefix_utf8.empty()) {
        const char needle[] = "All Rights Reserved";
        const size_t needle_len = strlen(needle);
        for (size_t i = 0; i + needle_len * 2 <= startup_plain.size(); i += 2) {
            bool match = true;
            for (size_t j = 0; j < needle_len; ++j) {
                if (startup_plain[i + j * 2] != (uint8_t)needle[j]) { match = false; break; }
            }
            if (match) {
                // 向前搜索找到UTF-16LE中ASCII字符串的起始位置
                size_t start = i;
                while (start >= 2) {
                    if (startup_plain[start - 2] >= 0x20 && startup_plain[start - 2] < 0x7F &&
                        startup_plain[start - 1] == 0)
                        start -= 2;
                    else
                        break;
                }
                // 向后搜索找到结束位置
                size_t end = i + needle_len * 2;
                while (end + 1 < startup_plain.size()) {
                    if (startup_plain[end] >= 0x20 && startup_plain[end] < 0x7F &&
                        startup_plain[end + 1] == 0)
                        end += 2;
                    else
                        break;
                }
                if (end > start) {
                    // 将UTF-16LE转换为UTF-8
                    std::wstring ws;
                    for (size_t k = start; k + 1 < end; k += 2) {
                        wchar_t ch = (wchar_t)startup_plain[k] | ((wchar_t)startup_plain[k+1] << 8);
                        ws.push_back(ch);
                    }
                    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
                    if (sz > 0) {
                        prefix_utf8.resize(sz - 1);
                        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &prefix_utf8[0], sz, nullptr, nullptr);
                    }
                }
                break;
            }
        }
    }

    // 8. 解密并提取BOOTSTRAP
    auto bscfg = Bootstrap::extract_bootstrap(
        bootstrap_ct.data(), bootstrap_ct.size(),
        bootstrap_filter_path,
        salt_ptr, params.salt_size,
        params.rva_archive_seed);
    if (!bscfg.ok) FAIL("Failed to extract BOOTSTRAP config");

    // 9. 构建final_bootstrap = prefix + WARNING
    std::wstring final_bootstrap = utf8_to_wide(prefix_utf8);
    final_bootstrap += bscfg.warning;

    // 10. 尝试FilterManager派生（需要正确的per-game RVA）
    auto prog = FilterManager::derive_drip_program(
        bscfg.dll_data.data(), bscfg.dll_data.size(),
        final_bootstrap, bscfg.unique,
        bscfg.params.data(), bscfg.params.size(),
        bscfg.archive_seed,
        params.rva_manager_ctor, params.rva_bootstrap_derive,
        params.rva_archive_derive, params.rva_hashkey_derive);

    // 如果FilterManager失败，写入部分scheme
    if (!prog.ok) {
        // 将bootstrap key转换为UTF-8以写入JSON
        int bsz = WideCharToMultiByte(CP_UTF8, 0, bootstrap_filter_path.c_str(), -1,
                                       nullptr, 0, nullptr, nullptr);
        std::string bkey_utf8(bsz > 0 ? (size_t)(bsz - 1) : 0, 0);
        if (bsz > 0)
            WideCharToMultiByte(CP_UTF8, 0, bootstrap_filter_path.c_str(), -1,
                                &bkey_utf8[0], bsz, nullptr, nullptr);

        int skz = WideCharToMultiByte(CP_UTF8, 0, startup_filter_path.c_str(), -1,
                                       nullptr, 0, nullptr, nullptr);
        std::string skey_utf8(skz > 0 ? (size_t)(skz - 1) : 0, 0);
        if (skz > 0)
            WideCharToMultiByte(CP_UTF8, 0, startup_filter_path.c_str(), -1,
                                &skey_utf8[0], skz, nullptr, nullptr);

        int uz = WideCharToMultiByte(CP_UTF8, 0, bscfg.unique.c_str(), -1,
                                      nullptr, 0, nullptr, nullptr);
        std::string unique_utf8(uz > 0 ? (size_t)(uz - 1) : 0, 0);
        if (uz > 0)
            WideCharToMultiByte(CP_UTF8, 0, bscfg.unique.c_str(), -1,
                                &unique_utf8[0], uz, nullptr, nullptr);

        int wz = WideCharToMultiByte(CP_UTF8, 0, bscfg.warning.c_str(), -1,
                                      nullptr, 0, nullptr, nullptr);
        std::string warning_utf8(wz > 0 ? (size_t)(wz - 1) : 0, 0);
        if (wz > 0)
            WideCharToMultiByte(CP_UTF8, 0, bscfg.warning.c_str(), -1,
                                &warning_utf8[0], wz, nullptr, nullptr);

        FILE* fs = _wfopen((output_dir + L"\\_scheme.json").c_str(), L"w");
        if (fs) {
            fprintf(fs, "{\n");
            fprintf(fs, "  \"bres\": {\n");
            fprintf(fs, "    \"startup_key\": \"%s\",\n", skey_utf8.c_str());
            fprintf(fs, "    \"bootstrap_key\": null,\n");
            fprintf(fs, "    \"bootstrap_url\": null,\n");
            fprintf(fs, "    \"bootstrap_zlib_offset\": 8,\n");
            fprintf(fs, "    \"salt\": { \"mode\": \"auto\", \"size\": %u }\n",
                    params.salt_size);
            fprintf(fs, "  },\n");
            fprintf(fs, "  \"bootstrap\": {\n");
            fprintf(fs, "    \"prefix\": \"%s\",\n", prefix_utf8.c_str());
            fprintf(fs, "    \"warning\": \"%.*s\",\n",
                    (int)warning_utf8.size(), warning_utf8.c_str());
            fprintf(fs, "    \"archive_unique_key\": \"%.*s\"\n",
                    (int)unique_utf8.size(), unique_utf8.c_str());
            fprintf(fs, "  },\n");
            fprintf(fs, "  \"hxv4\": {},\n");
            fprintf(fs, "  \"note\": \"FilterManager derivation failed (RVAs may be per-game). Set correct RVAs in GameParams.\"\n");
            fprintf(fs, "}\n");
            fclose(fs);
        }
        FAIL("FilterManager derivation failed (RVAs may be game-specific). Partial _scheme.json saved.");
    }

    
    
    // 11. 确定EXE stem用于文件命名
    std::wstring exe_stem;
    {
        size_t last_slash = exe_path.rfind(L'\\');
        if (last_slash == std::wstring::npos) last_slash = exe_path.rfind(L'/');
        std::wstring exe_name = (last_slash != std::wstring::npos)
            ? exe_path.substr(last_slash + 1) : exe_path;
        size_t dot = exe_name.rfind(L'.');
        if (dot != std::wstring::npos) exe_name = exe_name.substr(0, dot);
        exe_stem = exe_name;
    }

    auto ws2utf8 = [](const std::wstring& ws) -> std::string {
        if (ws.empty()) return "";
        int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sz <= 0) return "";
        std::string out(sz - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &out[0], sz, nullptr, nullptr);
        return out;
    };
    auto write_hex = [](FILE* ff, const uint8_t* d, size_t n) {
        for (size_t i = 0; i < n; ++i) fprintf(ff, "%02x", d[i]);
    };

    std::string skey_utf8 = ws2utf8(startup_filter_path);
    std::string bkey_utf8 = ws2utf8(bootstrap_filter_path);
    std::string unique_utf8 = ws2utf8(bscfg.unique);
    std::string warning_utf8 = ws2utf8(bscfg.warning);
    std::string stem_utf8 = ws2utf8(exe_stem);
    std::string out_utf8 = ws2utf8(output_dir);
    std::string exe_name_utf8 = ws2utf8(exe_path.substr(exe_path.rfind(L'\\') + 1));

    // 写入_scheme.json
    {
        std::wstring scheme_path = output_dir + L"\\" + exe_stem + L"_scheme.json";
        FILE* fs = _wfopen(scheme_path.c_str(), L"w");
        if (!fs) FAIL("Cannot write scheme JSON");

        fprintf(fs, "{\n");
        fprintf(fs, "  \"id\": \"%s\",\n", stem_utf8.c_str());
        fprintf(fs, "  \"name\": \"%s HXV4\",\n", stem_utf8.c_str());
        fprintf(fs, "  \"engine\": \"Kirikiri/Krkrz XP3 HXV4\",\n");
        fprintf(fs, "  \"exe\": {\n");
        fprintf(fs, "    \"default_path\": \"%s\"\n", exe_name_utf8.c_str());
        fprintf(fs, "  },\n");
        fprintf(fs, "  \"bres\": {\n");
        fprintf(fs, "    \"startup_key\": \"%s\",\n", skey_utf8.c_str());
        fprintf(fs, "    \"bootstrap_key\": \"%s\",\n", bkey_utf8.c_str());
        fprintf(fs, "    \"bootstrap_url\": \"bres://./%s/bootstrap\",\n", bkey_utf8.c_str());
        fprintf(fs, "    \"bootstrap_zlib_offset\": 8,\n");
        fprintf(fs, "    \"salt\": { \"mode\": \"auto\", \"size\": %u }\n", params.salt_size);
        fprintf(fs, "  },\n");
        fprintf(fs, "  \"bootstrap\": {\n");
        fprintf(fs, "    \"prefix\": \"%s\",\n", prefix_utf8.c_str());
        fprintf(fs, "    \"warning\": \"%s\",\n", warning_utf8.c_str());
        fprintf(fs, "    \"archive_unique_key\": \"%s\"\n", unique_utf8.c_str());
        fprintf(fs, "  },\n");
        fprintf(fs, "  \"hxv4\": {\n");
        fprintf(fs, "    \"hash_domain\": \"\",\n");
        fprintf(fs, "    \"key\": \"");
        write_hex(fs, prog.hxv4_key.data(), 32);
        fprintf(fs, "\",\n");
        fprintf(fs, "    \"nonce0\": \"");
        write_hex(fs, prog.hxv4_nonce0.data(), 24);
        fprintf(fs, "\",\n");
        fprintf(fs, "    \"nonce1\": \"");
        write_hex(fs, prog.hxv4_nonce1.data(), 24);
        fprintf(fs, "\",\n");
        fprintf(fs, "    \"open_flag_source\": \"descriptor.flags & 1\"\n");
        fprintf(fs, "  },\n");
        fprintf(fs, "  \"derive\": {\n");
        fprintf(fs, "    \"drip_program\": \"%s_drip_program.json\",\n", stem_utf8.c_str());
        fprintf(fs, "    \"mode\": \"auto\"\n");
        fprintf(fs, "  }\n");
        fprintf(fs, "}\n");
        fclose(fs);
    }

    // 写入_drip_program.json
    {
        std::wstring drip_path = output_dir + L"\\" + exe_stem + L"_drip_program.json";
        FILE* fj = _wfopen(drip_path.c_str(), L"w");
        if (!fj) FAIL("Cannot write drip_program JSON");

        fprintf(fj, "{\n");
        fprintf(fj, "  \"callback_rva_base\": %zu,\n", prog.source_module_base);
        fprintf(fj, "  \"source_module_base\": %zu,\n", prog.source_module_base);
        fprintf(fj, "  \"context_va\": %zu,\n", prog.context_va);
        fprintf(fj, "  \"drip_impl_va\": %zu,\n", prog.drip_impl_va);
        fprintf(fj, "  \"hash_key\": \"");
        write_hex(fj, prog.hash_key.data(), 32);
        fprintf(fj, "\",\n");
        fprintf(fj, "  \"version\": 1,\n");
        fprintf(fj, "  \"hxv4_key\": \"");
        write_hex(fj, prog.hxv4_key.data(), 32);
        fprintf(fj, "\",\n");
        fprintf(fj, "  \"hxv4_nonce0\": \"");
        write_hex(fj, prog.hxv4_nonce0.data(), 24);
        fprintf(fj, "\",\n");
        fprintf(fj, "  \"hxv4_nonce1\": \"");
        write_hex(fj, prog.hxv4_nonce1.data(), 24);
        fprintf(fj, "\",\n");
        fprintf(fj, "  \"source_module\": \"bootstrap.dll\",\n");
        fprintf(fj, "  \"manager_va\": %zu\n", prog.manager_va);
        fprintf(fj, "}\n");
        fclose(fj);
    }

    // 写入_drip_program.bin
    {
        std::wstring bin_path = output_dir + L"\\" + exe_stem + L"_drip_program.bin";
        FILE* fb = _wfopen(bin_path.c_str(), L"wb");
        if (fb) {
            uint32_t magic = 0x50495244;
            fwrite(&magic, 4, 1, fb);
            uint32_t hw_count = 6;
            uint32_t ctx_count = (uint32_t)prog.context_u32.size();
            uint32_t lane_count = (uint32_t)prog.lanes.size();
            fwrite(&hw_count, 4, 1, fb);
            fwrite(&ctx_count, 4, 1, fb);
            fwrite(&lane_count, 4, 1, fb);
            fwrite(prog.holder_words.data(), 4, 6, fb);
            if (ctx_count > 0) fwrite(prog.context_u32.data(), 4, ctx_count, fb);
            for (auto& lane : prog.lanes) {
                uint32_t rc = 0;
                fwrite(&rc, 4, 1, fb);
            }
            fclose(fb);
        }
    }

    // 写入_static_recover.summary.json
    {
        std::wstring sum_path = output_dir + L"\\" + exe_stem + L"_static_recover.summary.json";
        FILE* fs = _wfopen(sum_path.c_str(), L"w");
        if (fs) {
            fprintf(fs, "{\n");
            fprintf(fs, "  \"archive_unique_key\": \"%s\",\n", unique_utf8.c_str());
            fprintf(fs, "  \"bootstrap_key\": \"%s\",\n", bkey_utf8.c_str());
            fprintf(fs, "  \"bootstrap_prefix\": \"%s\",\n", prefix_utf8.c_str());
            fprintf(fs, "  \"bootstrap_url\": \"bres://./%s/bootstrap\",\n", bkey_utf8.c_str());
            fprintf(fs, "  \"outputs\": {\n");
            fprintf(fs, "    \"dll\": \"%s\\\\bootstrap.dll\",\n", out_utf8.c_str());
            fprintf(fs, "    \"drip_program\": \"%s\\\\%s_drip_program.json\"\n", out_utf8.c_str(), stem_utf8.c_str());
            fprintf(fs, "  },\n");
            fprintf(fs, "  \"startup_key\": \"%s\",\n", skey_utf8.c_str());
            fprintf(fs, "  \"warning\": \"%s\"\n", warning_utf8.c_str());
            fprintf(fs, "}\n");
            fclose(fs);
        }
    }

#undef FAIL
}

} // namespace Engine
