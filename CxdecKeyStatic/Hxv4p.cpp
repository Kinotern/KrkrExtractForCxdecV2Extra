#include "Hxv4p.h"

#include <algorithm>
#include <cstring>

#include "Crypto/ZlibInflate.h"

namespace Hxv4p {

const uint32_t kOpcodes[kOpcodeCount] = {
    0x51D90,  // STOP
    0x17C50,  // ADD_IMM
    0x17C60,  // RECURSE
    0x17CB0,  // ADD_SCRATCH
    0x17CD0,  // MUL_SCRATCH
    0x17CF0,  // SCRATCH_MINUS_RESULT
    0x17D10,  // SHL_SCRATCH
    0x17D30,  // SHR_SCRATCH
    0x17D50,  // SUB_SCRATCH
    0x17D70,  // BIT_SHUFFLE
    0x17DA0,  // SET_IMM
    0x17DB0,  // SET_SEED
    0x17DD0,  // DEC
    0x17DE0,  // INC
    0x17DF0,  // NEG
    0x17E00,  // NOT
    0x17E10,  // TABLE_IMM
    0x17E30,  // TABLE_MASKED
    0x17E50,  // SUB_IMM
    0x17E60,  // STORE_SCRATCH
    0x17E80,  // XOR_IMM
};

namespace {

constexpr uint32_t kOpTableImm = 0x17E10;
constexpr uint32_t kOpTableMasked = 0x17E30;

void AppendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value & 0xFF));
    out.push_back((uint8_t)((value >> 8) & 0xFF));
}

void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back((uint8_t)((value >> (8 * i)) & 0xFF));
}

void AppendVarint(std::vector<uint8_t>& out, uint32_t value) {
    for (;;) {
        uint8_t byte = (uint8_t)(value & 0x7F);
        value >>= 7;
        out.push_back((uint8_t)(byte | (value ? 0x80 : 0x00)));
        if (!value) break;
    }
}

bool ReadVarint(const uint8_t* data, size_t size, size_t& off, uint32_t& value) {
    value = 0;
    int shift = 0;
    while (off < size) {
        uint8_t byte = data[off++];
        value |= (uint32_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) return true;
        shift += 7;
        if (shift > 28) return false;
    }
    return false;
}

void AppendChunk(std::vector<uint8_t>& out, uint16_t type, const std::vector<uint8_t>& body) {
    AppendU16(out, type);
    AppendU16(out, 0);
    AppendU32(out, (uint32_t)body.size());
    out.insert(out.end(), body.begin(), body.end());
    size_t pad = (4u - (body.size() % 4u)) % 4u;
    out.insert(out.end(), pad, 0u);
}

uint32_t Adler32(const uint8_t* data, size_t size) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < size; ++i) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

// 合法 zlib 流，全部使用 deflate 的 stored block。
// 读取端（本仓库的 Crypto::zlib_decompress、Python 的 zlib）都能直接解开。
std::vector<uint8_t> ZlibStore(const std::vector<uint8_t>& raw) {
    std::vector<uint8_t> out;
    out.push_back(0x78);
    out.push_back(0x01);

    size_t off = 0;
    do {
        size_t chunk = std::min<size_t>(raw.size() - off, 65535u);
        bool final = (off + chunk) >= raw.size();
        out.push_back(final ? 0x01 : 0x00);
        uint16_t len = (uint16_t)chunk;
        AppendU16(out, len);
        AppendU16(out, (uint16_t)~len);
        out.insert(out.end(), raw.begin() + off, raw.begin() + off + chunk);
        off += chunk;
    } while (off < raw.size());

    uint32_t adler = Adler32(raw.data(), raw.size());
    for (int i = 3; i >= 0; --i) out.push_back((uint8_t)((adler >> (8 * i)) & 0xFF));
    return out;
}

}  // namespace

int OpcodeIndexOf(uint32_t callbackRva) {
    for (size_t i = 0; i < kOpcodeCount; ++i) {
        if (kOpcodes[i] == callbackRva) return (int)i;
    }
    return -1;
}

bool NormalizeLanesToRva(std::vector<Lane>& lanes, uint32_t source_module_base) {
    uint32_t maxCallback = 0;
    for (const auto& lane : lanes) {
        for (const auto& rec : lane) maxCallback = (std::max)(maxCallback, rec.opcode);
    }
    if (maxCallback < kVaLowerBound) return false;

    for (auto& lane : lanes) {
        for (auto& rec : lane) rec.opcode -= source_module_base;
    }
    return true;
}

uint32_t Crc32(const uint8_t* data, size_t size) {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

std::vector<uint8_t> EncodePayload(const Parameters& params, std::string& error) {
    std::vector<uint8_t> out;

    {
        std::vector<uint8_t> body;
        AppendVarint(body, (uint32_t)params.source_module.size());
        body.insert(body.end(), params.source_module.begin(), params.source_module.end());
        AppendU32(body, params.source_module_base);
        AppendU32(body, params.manager_va);
        AppendU32(body, params.context_va);
        AppendU32(body, params.drip_impl_va);
        AppendChunk(out, kChunkIdentity, body);
    }

    {
        std::vector<uint8_t> body;
        body.insert(body.end(), params.hxv4_key, params.hxv4_key + sizeof(params.hxv4_key));
        body.insert(body.end(), params.hxv4_nonce0, params.hxv4_nonce0 + sizeof(params.hxv4_nonce0));
        body.insert(body.end(), params.hxv4_nonce1, params.hxv4_nonce1 + sizeof(params.hxv4_nonce1));
        body.insert(body.end(), params.hash_key, params.hash_key + sizeof(params.hash_key));
        AppendChunk(out, kChunkKeyMaterial, body);
    }

    // pathHash / fileHash 的盐（运行时 CompoundStorageMedia 的 mediaName）。
    // **空串也要写**：盐可以就是空串（prefix 以冒号开头时正是如此），
    // 而「记了但是空」和「压根没记」必须分得开——否则空盐会被读侧当成默认值，
    // 整包哈希全错而且不报错。老产物没有这个 chunk，读侧才回落默认值。
    {
        std::vector<uint8_t> body(params.hash_domain.begin(), params.hash_domain.end());
        AppendChunk(out, kChunkHashDomain, body);
    }

    {
        std::vector<uint8_t> body;
        for (size_t i = 0; i < 6; ++i) {
            AppendU32(body, i < params.holder_words.size() ? params.holder_words[i] : 0u);
        }
        AppendChunk(out, kChunkHolderWords, body);
    }

    {
        uint32_t maxIndex = 0;
        for (const auto& lane : params.lanes) {
            for (const auto& rec : lane) {
                if (rec.opcode == kOpTableImm || rec.opcode == kOpTableMasked) {
                    maxIndex = (std::max)(maxIndex, rec.param);
                }
            }
        }
        size_t count = (std::max)(kTableMin, (size_t)maxIndex + 1u);
        if (count > params.context_u32.size()) {
            error = "table count " + std::to_string(count) + " exceeds context_u32 size " +
                    std::to_string(params.context_u32.size());
            return {};
        }
        std::vector<uint8_t> body;
        AppendU32(body, (uint32_t)count);
        for (size_t i = 0; i < count; ++i) AppendU32(body, params.context_u32[i]);
        AppendChunk(out, kChunkTable, body);
    }

    {
        std::vector<uint8_t> body;
        body.push_back((uint8_t)params.lanes.size());
        for (const auto& lane : params.lanes) {
            AppendU16(body, (uint16_t)lane.size());
            for (const auto& rec : lane) {
                int index = OpcodeIndexOf(rec.opcode);
                if (index < 0) {
                    error = "lane opcode " + std::to_string(rec.opcode) + " not in opcode table";
                    return {};
                }
                body.push_back((uint8_t)index);
                AppendVarint(body, rec.param);
            }
        }
        AppendChunk(out, kChunkLanes, body);
    }

    return out;
}

std::vector<uint8_t> Encode(const Parameters& params, bool compress, std::string& error) {
    std::vector<uint8_t> payload = EncodePayload(params, error);
    if (payload.empty()) return {};

    std::vector<uint8_t> stored = compress ? ZlibStore(payload) : payload;

    uint32_t flags = kFlagOpcodeIndex | kFlagRva;
    if (compress) flags |= kFlagZlib;

    std::vector<uint8_t> out;
    AppendU32(out, kMagic);
    AppendU16(out, kFormatVersion);
    AppendU16(out, (uint16_t)flags);
    AppendU32(out, (uint32_t)stored.size());
    AppendU32(out, (uint32_t)payload.size());
    AppendU32(out, Crc32(payload.data(), payload.size()));
    AppendU32(out, 0);
    out.insert(out.end(), stored.begin(), stored.end());
    return out;
}

bool Decode(const std::vector<uint8_t>& blob, Parameters& out, std::string& error) {
    if (blob.size() < 24) {
        error = "blob too small";
        return false;
    }

    auto readU16 = [&](size_t off) -> uint16_t { return (uint16_t)(blob[off] | (blob[off + 1] << 8)); };
    auto readU32 = [&](size_t off) -> uint32_t {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= (uint32_t)blob[off + i] << (8 * i);
        return v;
    };

    if (readU32(0) != kMagic) {
        error = "bad magic";
        return false;
    }
    uint16_t version = readU16(4);
    if (version != kFormatVersion) {
        error = "unsupported format_version " + std::to_string(version);
        return false;
    }
    uint32_t flags = readU16(6);
    uint32_t storedSize = readU32(8);
    uint32_t rawSize = readU32(12);
    uint32_t crc = readU32(16);

    if (24 + (size_t)storedSize > blob.size()) {
        error = "truncated payload";
        return false;
    }

    std::vector<uint8_t> payload;
    if (flags & kFlagZlib) {
        payload = Crypto::zlib_decompress(blob.data() + 24, storedSize);
        if (payload.empty()) {
            error = "zlib decompress failed";
            return false;
        }
    } else {
        payload.assign(blob.begin() + 24, blob.begin() + 24 + storedSize);
    }

    if (payload.size() != rawSize) {
        error = "raw size mismatch";
        return false;
    }
    if (Crc32(payload.data(), payload.size()) != crc) {
        error = "crc32 mismatch";
        return false;
    }

    size_t off = 0;
    while (off + 8 <= payload.size()) {
        uint16_t type = (uint16_t)(payload[off] | (payload[off + 1] << 8));
        uint32_t length = (uint32_t)payload[off + 4] | ((uint32_t)payload[off + 5] << 8) |
                          ((uint32_t)payload[off + 6] << 16) | ((uint32_t)payload[off + 7] << 24);
        off += 8;
        // 不能写成 off + length > payload.size()：32 位下 size_t 就是 32 位，
        // 而 length 是从文件里读的，两者相加会回绕，畸形文件能骗过这个判断。
        if (length > payload.size() - off) {
            error = "chunk overruns payload";
            return false;
        }
        const uint8_t* body = payload.data() + off;
        size_t bodyOff = 0;

        switch (type) {
            case kChunkIdentity: {
                uint32_t nameLen = 0;
                if (!ReadVarint(body, length, bodyOff, nameLen) || bodyOff + nameLen + 16 > length) {
                    error = "bad IDENTITY chunk";
                    return false;
                }
                out.source_module.assign((const char*)body + bodyOff, nameLen);
                bodyOff += nameLen;
                auto rd = [&](size_t at) -> uint32_t {
                    uint32_t v = 0;
                    for (int i = 0; i < 4; ++i) v |= (uint32_t)body[at + i] << (8 * i);
                    return v;
                };
                out.source_module_base = rd(bodyOff);
                out.manager_va = rd(bodyOff + 4);
                out.context_va = rd(bodyOff + 8);
                out.drip_impl_va = rd(bodyOff + 12);
                break;
            }
            case kChunkKeyMaterial: {
                if (length < 112) {
                    error = "short KEY_MATERIAL chunk";
                    return false;
                }
                std::memcpy(out.hxv4_key, body, 32);
                std::memcpy(out.hxv4_nonce0, body + 32, 24);
                std::memcpy(out.hxv4_nonce1, body + 56, 24);
                std::memcpy(out.hash_key, body + 80, 32);
                break;
            }
            case kChunkHashDomain: {
                out.hash_domain.assign(reinterpret_cast<const char*>(body),
                                       static_cast<size_t>(length));
                out.hash_domain_known = true;
                break;
            }
            case kChunkHolderWords: {
                out.holder_words.clear();
                for (size_t i = 0; i + 4 <= length; i += 4) {
                    out.holder_words.push_back((uint32_t)body[i] | ((uint32_t)body[i + 1] << 8) |
                                               ((uint32_t)body[i + 2] << 16) |
                                               ((uint32_t)body[i + 3] << 24));
                }
                break;
            }
            case kChunkTable: {
                if (length < 4) {
                    error = "short TABLE chunk";
                    return false;
                }
                uint32_t count = (uint32_t)body[0] | ((uint32_t)body[1] << 8) |
                                 ((uint32_t)body[2] << 16) | ((uint32_t)body[3] << 24);
                if (4 + (size_t)count * 4 > length) {
                    error = "TABLE count overruns chunk";
                    return false;
                }
                out.context_u32.clear();
                out.context_u32.reserve(count);
                for (uint32_t i = 0; i < count; ++i) {
                    const uint8_t* p = body + 4 + i * 4;
                    out.context_u32.push_back((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                                              ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
                }
                break;
            }
            case kChunkLanes: {
                if (length < 1) {
                    error = "short LANES chunk";
                    return false;
                }
                size_t pos = 0;
                uint8_t laneCount = body[pos++];
                out.lanes.clear();
                for (uint8_t li = 0; li < laneCount; ++li) {
                    if (pos + 2 > length) {
                        error = "LANES truncated at lane count";
                        return false;
                    }
                    uint16_t recordCount = (uint16_t)(body[pos] | (body[pos + 1] << 8));
                    pos += 2;
                    Lane lane;
                    lane.reserve(recordCount);
                    for (uint16_t ri = 0; ri < recordCount; ++ri) {
                        if (pos >= length) {
                            error = "LANES truncated at opcode";
                            return false;
                        }
                        uint8_t index = body[pos++];
                        if (index >= kOpcodeCount) {
                            error = "opcode index out of range";
                            return false;
                        }
                        uint32_t param = 0;
                        if (!ReadVarint(body, length, pos, param)) {
                            error = "LANES truncated at param";
                            return false;
                        }
                        lane.push_back(LaneRecord{param, kOpcodes[index]});
                    }
                    out.lanes.push_back(std::move(lane));
                }
                break;
            }
            default:
                break;  // 未知 chunk 按格式要求跳过
        }

        off += length + ((4u - (length % 4u)) % 4u);
    }

    return true;
}

}  // namespace Hxv4p
