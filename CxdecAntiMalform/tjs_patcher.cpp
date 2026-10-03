#include "tjs_patcher.h"
#include "tjs2_parser.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <vector>

static void TjsLog(const wchar_t* fmt, ...) {
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
        GetModuleHandleExW(6, (LPCWSTR)&TjsLog, &_hMod);
        GetModuleFileNameW(_hMod, _logPath, MAX_PATH);
        wchar_t* _bs = wcsrchr(_logPath, L'\\');
        if (_bs) *(_bs+1) = 0;
        wcscat_s(_logPath, L"CxdecAntiMalform.log");
    }
    _wfopen_s(&f, _logPath, L"a");
}
    if (f) { fwprintf(f, L"%s\n", buf); fflush(f); fclose(f); }
}


namespace TjsPatcher {

bool IsTjs2Bytecode(const uint8_t* data, size_t size) {
    return Tjs2Parser::IsTjs2(data, size);
}

// TJS2 VM opcode 编号
enum : int32_t {
    VM_NOP = 0, VM_CONST, VM_CP, VM_CL, VM_CCL, VM_TT, VM_TF, VM_CEQ, VM_CDEQ, VM_CLT, VM_CGT,
    VM_SETF, VM_SETNF, VM_LNOT, VM_NF, VM_JF, VM_JNF, VM_JMP, VM_INC, VM_INCPD, VM_INCPI, VM_INCP,
    VM_DEC, VM_DECPD, VM_DECPI, VM_DECP,
    VM_LOR = 26, VM_LAND = 30, VM_BOR = 34, VM_BXOR = 38, VM_BAND = 42, VM_SAR = 46,
    VM_SAL = 50, VM_SR = 54, VM_ADD = 58, VM_SUB = 62, VM_MOD = 66, VM_DIV = 70,
    VM_IDIV = 74, VM_MUL = 78,
    VM_BNOT = 82, VM_TYPEOF, VM_TYPEOFD, VM_TYPEOFI, VM_EVAL, VM_EEXP, VM_CHKINS, VM_ASC,
    VM_CHR, VM_NUM, VM_CHS, VM_INV, VM_CHKINV, VM_INT, VM_REAL, VM_STR, VM_OCTET,
    VM_CALL = 99, VM_CALLD, VM_CALLI, VM_NEW, VM_GPD, VM_SPD, VM_SPDE, VM_SPDEH, VM_GPI,
    VM_SPI, VM_SPIE, VM_GPDS, VM_SPDS, VM_GPIS, VM_SPIS, VM_SETP, VM_GETP, VM_DELD,
    VM_DELI, VM_SRV, VM_RET, VM_ENTRY, VM_EXTRY, VM_THROW, VM_CHGTHIS, VM_GLOBAL,
    VM_ADDCI, VM_REGMEMBER, VM_DEBUGGER
};

// 要匹配的调用形式：System.checkSignature()，其后紧跟条件跳转
static const char* kTargetMethod = "checkSignature";
static const char* kTargetObject = "System";

// 一条指令占多少个 word
static int InstructionSize(const std::vector<int32_t>& code, size_t pos)
{
    if (pos >= code.size()) return 1;
    int op = code[pos];
    if (op < 0 || op > 127) return 1;

    switch (op)
    {
        case VM_NOP: case VM_NF: case VM_RET: case VM_EXTRY: case VM_REGMEMBER: case VM_DEBUGGER:
            return 1;
        case VM_TT: case VM_TF: case VM_SETF: case VM_SETNF: case VM_LNOT:
        case VM_BNOT: case VM_ASC: case VM_CHR: case VM_NUM: case VM_CHS:
        case VM_CL: case VM_INV: case VM_CHKINV: case VM_TYPEOF: case VM_EVAL:
        case VM_EEXP: case VM_INT: case VM_REAL: case VM_STR: case VM_OCTET:
        case VM_JF: case VM_JNF: case VM_JMP: case VM_SRV: case VM_THROW:
        case VM_GLOBAL: case VM_INC: case VM_DEC:
            return 2;
        case VM_CONST: case VM_CP: case VM_CEQ: case VM_CDEQ: case VM_CLT:
        case VM_CGT: case VM_CHKINS: case VM_CHGTHIS: case VM_ADDCI: case VM_CCL:
        case VM_ENTRY: case VM_SETP: case VM_GETP: case VM_INCP: case VM_DECP:
            return 3;
        default:
            break;
    }

    // 二元运算族：基础 3 字，*PD/*PI 5 字，*P 4 字
    static const int kBinaryBase[] = {
        VM_LOR, VM_LAND, VM_BOR, VM_BXOR, VM_BAND, VM_SAR, VM_SAL, VM_SR,
        VM_ADD, VM_SUB, VM_MOD, VM_DIV, VM_IDIV, VM_MUL
    };
    for (int base : kBinaryBase)
    {
        if (op == base)     return 3;
        if (op == base + 1) return 5;
        if (op == base + 2) return 5;
        if (op == base + 3) return 4;
    }

    switch (op)
    {
        case VM_INCPD: case VM_DECPD: case VM_INCPI: case VM_DECPI:
        case VM_GPD: case VM_GPDS: case VM_GPI: case VM_GPIS:
        case VM_SPD: case VM_SPDE: case VM_SPDEH: case VM_SPDS:
        case VM_SPI: case VM_SPIE: case VM_SPIS:
        case VM_DELD: case VM_DELI: case VM_TYPEOFD: case VM_TYPEOFI:
            return 4;
        default:
            break;
    }

    if (op == VM_CALL || op == VM_NEW)
    {
        if (pos + 3 >= code.size()) return 4;
        int argc = code[pos + 3];
        if (argc == -1) return 4;
        if (argc == -2) return (pos + 4 < code.size()) ? (5 + code[pos + 4] * 2) : 5;
        return 4 + (argc > 0 ? argc : 0);
    }

    if (op == VM_CALLD || op == VM_CALLI)
    {
        if (pos + 4 >= code.size()) return 5;
        int argc = code[pos + 4];
        if (argc == -1) return 5;
        if (argc == -2) return (pos + 5 < code.size()) ? (6 + code[pos + 5] * 2) : 6;
        return 5 + (argc > 0 ? argc : 0);
    }

    return 1;
}

struct Instr {
    size_t  pos;   // code 里的 word 下标
    int32_t op;
    size_t  size;
};

// 名字操作数是变体槽号，要经 ctx.strings 映射。映射不上返回空串。
static const std::string& SlotName(const std::vector<std::string>& ctxStrings, int32_t slot)
{
    static const std::string kEmpty;
    if (slot < 0 || slot >= (int32_t)ctxStrings.size()) return kEmpty;
    return ctxStrings[(size_t)slot];
}

PatchedData PatchBytecode(const uint8_t* data, size_t size) {
    PatchedData result;
    result.bytes.assign(data, data + size);
    result.modified = false;
    result.patchesApplied = 0;

    Tjs2Parser::ByteCode bc = Tjs2Parser::Parse(data, size);
    TjsLog(L"[TJS] Parse: valid=%d ctx=%zu", (int)bc.valid, bc.contexts.size());
    if (!bc.valid) {
        TjsLog(L"[TJS] parse FAILED");
        return result;
    }

    for (const auto& ctx : bc.contexts) {
        const auto& code = ctx.code;
        if (code.size() < 5) continue;

        // 先建指令表：结构化匹配必须按指令下标走，不能按 word 线性扫。
        std::vector<Instr> ins;
        for (size_t pos = 0; pos < code.size();) {
            int sz = InstructionSize(code, pos);
            if (sz <= 0 || pos + (size_t)sz > code.size()) break;
            ins.push_back(Instr{ pos, code[pos], (size_t)sz });
            pos += (size_t)sz;
        }

        for (size_t c = 1; c + 2 < ins.size(); ++c) {
            if (ins[c].op != VM_CALLD) continue;

            // 名字在 CALLD 的操作数里（pos+3），且要经变体表解析
            const std::string& callName = SlotName(ctx.strings, code[ins[c].pos + 3]);
            if (_stricmp(callName.c_str(), kTargetMethod) != 0) continue;

            // 上一条必须是 GPD，且名字解析为 System
            if (ins[c - 1].op != VM_GPD) continue;
            const std::string& objName = SlotName(ctx.strings, code[ins[c - 1].pos + 3]);
            if (_stricmp(objName.c_str(), kTargetObject) != 0) continue;

            // 只做单向 TF -> TT，重复处理同一个 exe 是幂等的
            const Instr& br = ins[c + 1];
            if (br.op != VM_TF) continue;
            const Instr& nx = ins[c + 2];
            if (nx.op != VM_JF && nx.op != VM_JNF) continue;

            size_t byteOff = ctx.rawCodeOffset + (br.pos * 2);
            if (byteOff + 2 > result.bytes.size()) continue;

            int32_t newOp = VM_TT;
            result.bytes[byteOff]     = (uint8_t)(newOp & 0xFF);
            result.bytes[byteOff + 1] = (uint8_t)((newOp >> 8) & 0xFF);
            result.modified = true;
            result.patchesApplied++;
            result.patchOffsets.push_back(byteOff);

            wchar_t _dbg[256];
            swprintf_s(_dbg, L"[TJS] PATCH ctx=%hs wordOff=%zu byteOff=0x%zX op %d->%d",
                ctx.name.c_str(), br.pos, byteOff, (int)br.op, (int)newOp);
            TjsLog(_dbg);
        }
    }

    TjsLog(L"[TJS] PatchBytecode done: modified=%d patches=%d",
        result.modified, result.patchesApplied);
    return result;
}

} // namespace TjsPatcher
