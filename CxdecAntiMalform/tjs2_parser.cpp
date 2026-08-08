#include "tjs2_parser.h"
#include <cstring>
#include <cstdio>
#include <windows.h>
#include <cstdarg>
static void T2Log(const wchar_t* fmt, ...) {
    wchar_t buf[512];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, args);
    va_end(args);
    OutputDebugStringW(buf);
    FILE* f = nullptr;
    {
    static wchar_t _logPath[MAX_PATH] = {0};
    if (!_logPath[0]) {
        HMODULE _hMod = NULL;
        GetModuleHandleExW(6, (LPCWSTR)&T2Log, &_hMod);
        GetModuleFileNameW(_hMod, _logPath, MAX_PATH);
        wchar_t* _bs = wcsrchr(_logPath, L'\\');
        if (_bs) *(_bs+1) = 0;
        wcscat_s(_logPath, L"CxdecAntiMalform.log");
    }
    _wfopen_s(&f, _logPath, L"a");
}
    if (f) { fwprintf(f, L"%s\n", buf); fflush(f); fclose(f); }
}


namespace Tjs2Parser {

static inline uint16_t LE16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
static inline uint32_t LE32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// SEH-guarded read helpers: bounds check + __try/__except safety net.
// Matches original AntiMalform's defensive read pattern (pure-C engine used
// function-level SEH; our C++ code uses read-level SEH to coexist with
// std::vector / std::string destructors).
static inline bool SafeRead16(const uint8_t* data, size_t off, size_t size, uint16_t* out) {
    if (off + 2 > size) return false;
    __try {
        *out = LE16(data + off);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        T2Log(L"[T2] SEH: AV at SafeRead16 off=0x%zX size=0x%zX", off, size);
        return false;
    }
}

static inline bool SafeRead32(const uint8_t* data, size_t off, size_t size, uint32_t* out) {
    if (off + 4 > size) return false;
    __try {
        *out = LE32(data + off);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        T2Log(L"[T2] SEH: AV at SafeRead32 off=0x%zX size=0x%zX", off, size);
        return false;
    }
}

static constexpr uint32_t FILE_TAG = ('T')|('J'<<8)|('S'<<16)|('2'<<24);
static constexpr uint32_t VER_TAG  = ('1')|('0'<<8)|('0'<<16)|(0   <<24);
static constexpr uint32_t DATA_TAG = ('D')|('A'<<8)|('T'<<16)|('A'<<24);
static constexpr uint32_t OBJ_TAG  = ('O')|('B'<<8)|('J'<<16)|('S'<<24);

bool IsTjs2(const uint8_t* data, size_t size) {
    if (size < 20) return false;
    return LE32(data) == FILE_TAG && LE32(data + 4) == VER_TAG;
}

ByteCode Parse(const uint8_t* data, size_t size) {
    ByteCode bc;
    bc.valid = false;
    if (size < 20) return bc;
    if (LE32(data) != FILE_TAG || LE32(data + 4) != VER_TAG) { T2Log(L"[T2] BAD header"); return bc; }
    if (LE32(data + 8) != static_cast<uint32_t>(size)) { T2Log(L"[T2] BAD size: hdr=0x%X size=%zu", LE32(data+8), size); return bc; }

    // --- DATA section ---
    if (LE32(data + 12) != DATA_TAG) { T2Log(L"[T2] BAD DATA tag"); return bc; }
    uint32_t dataSize = LE32(data + 16);
    size_t off = 20;
    size_t dataEnd = off + dataSize;
    if (dataEnd > size) { T2Log(L"[T2] dataEnd=%zu > size=%zu", dataEnd, size); return bc; }

    // ReadDataArea format:
    //   byte array: count (4) + data (aligned to 4)
    //   short array: count (4) + data (2-byte LE, aligned to 4)
    //   long array: count (4) + data (4-byte LE)
    //   longlong array: count (4) + data (8-byte LE)
    //   double array: count (4) + data (8-byte LE)
    //   string array: count (4) + [len(4) + UTF-16LE(len*2) + pad if odd]...
    //   octet array: ...

    // safe_advance: validate count >= 0 and that off + count*elemSize stays within bound,
    // then advance off by the aligned byte count. Returns false on overflow/oob.
    auto safe_advance = [&](int32_t count, size_t elemSize, size_t align, size_t bound) -> bool {
        if (count < 0) { T2Log(L"[T2] Negative count %d", count); return false; }
        size_t bytes = static_cast<size_t>(count) * elemSize;
        if (off + bytes > bound) { T2Log(L"[T2] Advance OOB: off=%zu bytes=%zu bound=%zu", off, bytes, bound); return false; }
        off += bytes;
        if (align > 1) {
            size_t rem = off % align;
            if (rem != 0) {
                size_t pad = align - rem;
                if (off + pad > bound) { off = bound; return true; }
                off += pad;
            }
        }
        return true;
    };

    // byte array
    if (off + 4 > dataEnd) { T2Log(L"[T2] DATA truncated at byte array"); return bc; }
    int32_t count = static_cast<int32_t>(LE32(data + off)); off += 4;
    if (!safe_advance(count, 1, 4, dataEnd)) return bc;

    // short array
    if (off + 4 > dataEnd) { T2Log(L"[T2] DATA truncated at short array"); return bc; }
    count = static_cast<int32_t>(LE32(data + off)); off += 4;
    if (!safe_advance(count, 2, 4, dataEnd)) return bc;

    // long array
    if (off + 4 > dataEnd) { T2Log(L"[T2] DATA truncated at long array"); return bc; }
    count = static_cast<int32_t>(LE32(data + off)); off += 4;
    if (!safe_advance(count, 4, 1, dataEnd)) return bc;

    // longlong array
    if (off + 4 > dataEnd) { T2Log(L"[T2] DATA truncated at longlong array"); return bc; }
    count = static_cast<int32_t>(LE32(data + off)); off += 4;
    if (!safe_advance(count, 8, 1, dataEnd)) return bc;

    // double array
    if (off + 4 > dataEnd) { T2Log(L"[T2] DATA truncated at double array"); return bc; }
    count = static_cast<int32_t>(LE32(data + off)); off += 4;
    if (!safe_advance(count, 8, 1, dataEnd)) return bc;

    // --- String array ---
    count = static_cast<int32_t>(LE32(data + off)); off += 4;
    std::vector<std::string> strings;
    strings.reserve(count > 0 ? count : 0);
    for (int32_t i = 0; i < count; ++i) {
        if (off + 4 > dataEnd) break;
        int32_t slen = static_cast<int32_t>(LE32(data + off)); off += 4;
        std::string s;
        s.reserve(slen);
        for (int32_t j = 0; j < slen; ++j) {
            if (off + 2 > dataEnd) break;
            uint16_t ch = LE16(data + off); off += 2;
            // Store as UTF-8 (ASCII-subset chars only for our needs)
            if (ch < 0x80) s.push_back(static_cast<char>(ch));
            else s.push_back('?');
        }
        strings.push_back(s);
        if (slen & 1) off += 2;
    }
    bc.strings = strings; // save global string pool

    // Save strings for later
    // (Remaining DATA items: octet array — skip if present)

    // Try multiple OBJS offsets: some TJS2 variants include DATA tag in dataSize
    size_t objsOff = 20 + dataSize;
    if (objsOff + 4 > size || LE32(data + objsOff) != OBJ_TAG) {
        objsOff = 12 + dataSize;  // dataSize includes DATA tag+size
        if (objsOff + 4 > size || LE32(data + objsOff) != OBJ_TAG) {
            objsOff = 20 + dataSize - 8;  // dataSize includes just the DATA tag
        }
    }
    T2Log(L"[T2] Trying OBJS at 0x%zX: tag=0x%08X", objsOff, (objsOff+4<=size)?LE32(data+objsOff):0);
    if (objsOff + 4 > size || LE32(data + objsOff) != OBJ_TAG) {
        T2Log(L"[T2] BAD OBJS tag");
        return bc;
    }
    off = objsOff;

    off += 4; // skip OBJS tag
    uint32_t objsSize = LE32(data + off) - 8; // objsSize includes tag+size
    off += 4;
    size_t objsEnd = off + objsSize;
    T2Log(L"[T2] OBJS data size=%u objsEnd=%zu", objsSize, objsEnd);
    if (objsEnd > size) {
        T2Log(L"[T2] objsEnd=%zu > size=%zu, adjusting", objsEnd, size);
        objsEnd = size;
    }

    // Some TJS2 variants have an object count field after objs_size
    // Check if next bytes are not "TJS2" (i.e., count field present)
    if (off + 4 <= objsEnd && LE32(data + off) != FILE_TAG) {
        uint32_t objCount = LE32(data + off);
        T2Log(L"[T2] Object count field: %u", objCount);
        off += 8; // skip count (4 bytes) + reserved (4 bytes)
    }

    while (off + 28 <= objsEnd) {
        uint32_t objTag = LE32(data + off);
        if (objTag != FILE_TAG) {
            T2Log(L"[T2] obj tag not TJS2 at 0x%zX: 0x%08X", off, objTag);
            break;
        }
        off += 4; // tag
        uint32_t objSize = LE32(data + off) - 8; // objSize includes tag+size
        off += 4;

        off += 4; // parent
        int32_t nameIdx = static_cast<int32_t>(LE32(data + off)); off += 4;
        off += 4; // ctxType
        off += 4; // maxVariableCount
        off += 4; // variableReserveCount
        off += 4; // maxFrameCount
        off += 4; // funcDeclArgCount
        off += 4; // funcDeclUnnamedArgArrayBase
        off += 4; // funcDeclCollapseBase
        off += 4; // propSetter
        off += 4; // propGetter
        off += 4; // superClassGetter

        // Source positions
        if (off + 4 > objsEnd) break;
        int32_t srcCount = static_cast<int32_t>(LE32(data + off));
        off += 4;
        if (!safe_advance(srcCount, 8, 1, objsEnd)) break;

        // Code array
        if (off + 4 > objsEnd) break;
        int32_t codeCount = static_cast<int32_t>(LE32(data + off));
        off += 4;
        if (codeCount < 0) { T2Log(L"[T2] Negative codeCount %d", codeCount); break; }

        ByteCode::Context ctx;
        ctx.name = (nameIdx >= 0 && nameIdx < static_cast<int32_t>(strings.size()))
                   ? strings[nameIdx] : "";
        ctx.code.reserve(static_cast<size_t>(codeCount));

        size_t codeStart = off;
        ctx.rawCodeOffset = codeStart;

        for (int32_t i = 0; i < codeCount; ++i) {
            if (off + 2 > objsEnd) break;
            uint16_t op16;
            if (!SafeRead16(data, off, objsEnd, &op16)) break;
            int16_t op = static_cast<int16_t>(op16);
            ctx.code.push_back(static_cast<int32_t>(op));
            off += 2;
        }
        // alignment pad if odd codeCount
        if (codeCount & 1) {
            if (off + 2 <= objsEnd) off += 2;
        }

        // Variant array
        if (off + 4 > objsEnd) break;
        int32_t varCount = static_cast<int32_t>(LE32(data + off));
        off += 4;
        if (varCount < 0) { T2Log(L"[T2] Negative varCount %d", varCount); break; }

        std::vector<std::pair<int16_t, int16_t>> variants;
        variants.reserve(static_cast<size_t>(varCount));
        for (int32_t i = 0; i < varCount; ++i) {
            if (off + 4 > objsEnd) break;
            uint16_t vt16, vi16;
            if (!SafeRead16(data, off, objsEnd, &vt16)) break;
            if (!SafeRead16(data, off + 2, objsEnd, &vi16)) break;
            int16_t vt = static_cast<int16_t>(vt16);
            int16_t vi = static_cast<int16_t>(vi16);
            variants.push_back({vt, vi});
            off += 4;
        }

        ctx.strings.resize(static_cast<size_t>(varCount), "");
        for (int32_t i = 0; i < static_cast<int32_t>(variants.size()); ++i) {
            if (variants[i].first == 3 && variants[i].second >= 0 &&
                variants[i].second < static_cast<int32_t>(strings.size())) {
                ctx.strings[i] = strings[variants[i].second];
            }
        }

        // scgetterps
        if (off + 4 > objsEnd) break;
        int32_t scCount = static_cast<int32_t>(LE32(data + off));
        off += 4;
        if (!safe_advance(scCount, 4, 1, objsEnd)) break;

        // properties
        if (off + 4 > objsEnd) break;
        int32_t propCount = static_cast<int32_t>(LE32(data + off));
        off += 4;
        if (!safe_advance(propCount, 8, 1, objsEnd)) break;

        bc.contexts.push_back(std::move(ctx));
    }

    bc.valid = !bc.contexts.empty();
    T2Log(L"[T2] Parse done: valid=%d contexts=%zu", bc.valid, bc.contexts.size());
    return bc;
}

} // namespace Tjs2Parser
