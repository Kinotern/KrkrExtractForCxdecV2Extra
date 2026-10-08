// Cxdec 开发调试命令行。
//
// 目的：不点 UI 也能把**可离线跑**的那几件事走一遍（判定目录形态、封包、派生参数、
// 收编参数文件、静态取 Key、逐字节比对），出问题直接看控制台和退出码，方便写脚本回归。
//
// 需要游戏进程才成立的功能（解包、运行时 Hash 映射、Hook 撞库）不在这个工具里 ——
// 那些必须由 Loader 注入游戏进程跑。
//
// 位置：本 exe 必须和 CxdecRepacker.dll / CxdecKeyStatic.dll 放在同一个目录
// （发布结构里的 CxdecExtractordll\），它按自己的模块目录去找那两个 DLL。
//
// 退出码：0 成功、1 失败、2 用法错误。

#include "ModuleApi.h"

#include <Windows.h>
#include <fcntl.h>
#include <io.h>

#include <cstdio>
#include <cstdlib>
#include <cwctype>
#include <string>
#include <vector>

namespace
{
    constexpr int kExitOk = 0;
    constexpr int kExitFail = 1;
    constexpr int kExitUsage = 2;

    using Arguments = std::vector<std::wstring>;

    void SetupConsole()
    {
        // 控制台按 UTF-8 走，中文路径和消息才不会变问号（重定向到文件时也是 UTF-8）
        ::SetConsoleOutputCP(CP_UTF8);
        ::_setmode(::_fileno(stdout), _O_U8TEXT);
        ::_setmode(::_fileno(stderr), _O_U8TEXT);
    }

    void PrintUsage()
    {
        fwprintf(stdout, L"Cxdec 开发调试命令行\n\n");
        fwprintf(stdout, L"用法：CxdecCli <命令> [参数]\n\n");
        fwprintf(stdout, L"  sniff <目录>\n");
        fwprintf(stdout, L"      判定目录形态（模式 1/2/3），不打包。\n\n");
        fwprintf(stdout, L"  repack <目录> <输出.xp3> [选项]\n");
        fwprintf(stdout, L"      目录封成 hxv4 变体 XP3。\n");
        fwprintf(stdout, L"        --exe <游戏.exe>     按这个 EXE 查参数仓库；仓库里没有就现场派生\n");
        fwprintf(stdout, L"        --keys <目录>        参数仓库根目录（默认 <工具目录>\\keys）\n");
        fwprintf(stdout, L"        --media-name <盐>    覆盖盐，只在派生的那套不对时才用\n");
        fwprintf(stdout, L"        --mode <1|2|3>       覆盖嗅探结果\n");
        fwprintf(stdout, L"        --rescramble         把干净文本搅回加扰形态\n\n");
        fwprintf(stdout, L"  keys <游戏.exe> [选项]\n");
        fwprintf(stdout, L"      只派生/收编参数，不打包。选项同上（--keys）。\n\n");
        fwprintf(stdout, L"  importkey <参数文件.hxv4p> [选项]\n");
        fwprintf(stdout, L"      把一个 .hxv4p 参数文件收进仓库。选项：--exe、--keys。\n\n");
        fwprintf(stdout, L"  nextrev <游戏目录>\n");
        fwprintf(stdout, L"      扫描已有的 patch@r<N>.xp3，给出下一个可用修订号。\n\n");
        fwprintf(stdout, L"  keystatic <游戏.exe> [--out <目录>]\n");
        fwprintf(stdout, L"      调 CxdecKeyStatic 做静态 Key 提取。\n");
        fwprintf(stdout, L"      默认输出到 <游戏目录>\\ExtractKey_Output\\Static。\n\n");
        fwprintf(stdout, L"  cmp <文件A> <文件B>\n");
        fwprintf(stdout, L"      逐字节比对两份文件（复刻验证用）：只报首个差异偏移，不打印全文。\n\n");
        fwprintf(stdout, L"  help\n");
    }

    // ---------- 小工具 ----------

    std::wstring ToLower(const std::wstring& text)
    {
        std::wstring lower = text;
        for (wchar_t& ch : lower)
        {
            ch = static_cast<wchar_t>(::towlower(ch));
        }
        return lower;
    }

    std::wstring ParentDirectory(const std::wstring& path)
    {
        const size_t separator = path.find_last_of(L"\\/");
        return separator == std::wstring::npos ? std::wstring() : path.substr(0, separator);
    }

    std::wstring LeafName(const std::wstring& path)
    {
        const size_t separator = path.find_last_of(L"\\/");
        return separator == std::wstring::npos ? path : path.substr(separator + 1);
    }

    // 工具根目录 = 本 exe 所在目录的上一层，前提是那一层叫 CxdecExtractordll
    std::wstring ToolRoot()
    {
        const std::wstring& own = ModuleApi::ToolDirectory();
        if (ToLower(LeafName(own)) == L"cxdecextractordll")
        {
            return ParentDirectory(own);
        }
        return own;
    }

    std::wstring DefaultKeysRoot()
    {
        return ToolRoot() + L"\\keys";
    }

    // 命令行选项。名字直接对应 CxdecRepacker 的导出参数。
    struct Options
    {
        std::wstring exePath;
        std::wstring keysRoot = DefaultKeysRoot();
        std::wstring mediaName;
        std::wstring outputDirectory;  // 只有 keystatic 用
        int modeOverride = -1;
        bool rescramble = false;
    };

    // 每个命令认哪些选项
    enum class OptionSet
    {
        Repack,      // --exe --keys --media-name --mode --rescramble
        ExeAndKeys,  // --exe --keys
        KeyStaticOut // --out
    };

    bool Accepts(OptionSet set, const wchar_t* name)
    {
        switch (set)
        {
            case OptionSet::Repack:
                return _wcsicmp(name, L"--exe") == 0 || _wcsicmp(name, L"--keys") == 0 ||
                       _wcsicmp(name, L"--media-name") == 0 || _wcsicmp(name, L"--mode") == 0 ||
                       _wcsicmp(name, L"--rescramble") == 0;
            case OptionSet::ExeAndKeys:
                return _wcsicmp(name, L"--exe") == 0 || _wcsicmp(name, L"--keys") == 0;
            case OptionSet::KeyStaticOut:
                return _wcsicmp(name, L"--out") == 0;
        }
        return false;
    }

    bool NeedsValue(const wchar_t* name)
    {
        return _wcsicmp(name, L"--rescramble") != 0;
    }

    // 解析命令之后的选项。
    //
    // 用法错误一律返回 false 并由调用方直接退出 —— 不能"报一句然后接着跑"：
    // 那样 `repack dir out.xp3 --exe`（漏了 EXE 路径）会被当成没给这个选项，
    // 乖乖封出一个参数不对的包，看起来还成功了。
    bool ParseOptions(const Arguments& args, size_t first, OptionSet set, Options& options,
                      std::wstring& reason)
    {
        for (size_t index = first; index < args.size();)
        {
            const std::wstring& token = args[index];

            if (!Accepts(set, token.c_str()))
            {
                // 是 -- 开头的就说明是选项写错了；否则当成长了个多出来的位置参数
                if (token.rfind(L"--", 0) == 0)
                {
                    reason = L"不认识的选项：" + token;
                }
                else
                {
                    reason = L"多出来的参数：" + token;
                }
                return false;
            }

            if (NeedsValue(token.c_str()))
            {
                if (index + 1 >= args.size())
                {
                    reason = L"选项 " + token + L" 后面缺参数";
                    return false;
                }

                const std::wstring& value = args[index + 1];
                if (_wcsicmp(token.c_str(), L"--exe") == 0)
                {
                    options.exePath = value;
                }
                else if (_wcsicmp(token.c_str(), L"--keys") == 0)
                {
                    options.keysRoot = value;
                }
                else if (_wcsicmp(token.c_str(), L"--media-name") == 0)
                {
                    options.mediaName = value;
                }
                else if (_wcsicmp(token.c_str(), L"--out") == 0)
                {
                    options.outputDirectory = value;
                }
                else
                {
                    const int mode = _wtoi(value.c_str());
                    if (mode < 1 || mode > 3)
                    {
                        reason = L"--mode 只接受 1/2/3，收到：" + value;
                        return false;
                    }
                    options.modeOverride = mode;
                }
                index += 2;
                continue;
            }

            options.rescramble = true;
            ++index;
        }
        return true;
    }

    void PrintNote(const wchar_t* label, const std::wstring& text)
    {
        if (!text.empty())
        {
            fwprintf(stdout, L"%s：%s\n", label, text.c_str());
        }
    }

    // ---------- 子命令 ----------

    int CmdSniff(const Arguments& args)
    {
        if (args.size() != 2)
        {
            fwprintf(stderr, L"用法：CxdecCli sniff <目录>\n");
            return kExitUsage;
        }

        ModuleApi::Repacker api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        char detail[4096] = {};
        char failure[2048] = {};
        int mode = -1;
        if (!api.Sniff(args[1].c_str(), &mode, detail, sizeof(detail), failure, sizeof(failure)))
        {
            fwprintf(stderr, L"判定失败：%s\n", ModuleApi::FromAnsi(failure).c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"mode=%d\n", mode);
        PrintNote(L"说明", ModuleApi::FromAnsi(detail));
        return kExitOk;
    }

    int CmdRepack(const Arguments& args)
    {
        if (args.size() < 3)
        {
            fwprintf(stderr, L"用法：CxdecCli repack <目录> <输出.xp3> [--exe X] [--keys X] "
                             L"[--media-name X] [--mode N] [--rescramble]\n");
            return kExitUsage;
        }

        const std::wstring inputDirectory = args[1];
        const std::wstring outputXp3 = args[2];

        Options options;
        std::wstring reason;
        if (!ParseOptions(args, 3, OptionSet::Repack, options, reason))
        {
            fwprintf(stderr, L"%s\n", reason.c_str());
            return kExitUsage;
        }

        ModuleApi::Repacker api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"输入：%s\n", inputDirectory.c_str());
        fwprintf(stdout, L"输出：%s\n", outputXp3.c_str());
        fwprintf(stdout, L"参数仓库：%s\n", options.keysRoot.c_str());
        if (!options.exePath.empty())
        {
            fwprintf(stdout, L"游戏 EXE：%s\n", options.exePath.c_str());
        }
        if (options.modeOverride > 0)
        {
            fwprintf(stdout, L"模式覆盖：%d\n", options.modeOverride);
        }
        if (options.rescramble)
        {
            fwprintf(stdout, L"重新加扰：是\n");
        }

        char detail[4096] = {};
        char failure[4096] = {};
        const wchar_t* exeArg = options.exePath.empty() ? nullptr : options.exePath.c_str();
        const wchar_t* keysArg = options.keysRoot.empty() ? nullptr : options.keysRoot.c_str();
        const wchar_t* mediaArg = options.mediaName.empty() ? nullptr : options.mediaName.c_str();

        const BOOL ok = api.Repack(inputDirectory.c_str(), outputXp3.c_str(), exeArg, keysArg,
                                   mediaArg, options.modeOverride, options.rescramble ? 1 : 0,
                                   detail, sizeof(detail), failure, sizeof(failure));
        if (!ok)
        {
            fwprintf(stderr, L"封包失败：%s\n", ModuleApi::FromAnsi(failure).c_str());
            PrintNote(L"部分信息", ModuleApi::FromAnsi(detail));
            return kExitFail;
        }

        fwprintf(stdout, L"封包完成：%s\n", ModuleApi::FromAnsi(detail).c_str());
        return kExitOk;
    }

    int CmdKeys(const Arguments& args)
    {
        if (args.size() < 2)
        {
            fwprintf(stderr, L"用法：CxdecCli keys <游戏.exe> [--keys <目录>]\n");
            return kExitUsage;
        }

        const std::wstring exePath = args[1];

        Options options;
        std::wstring reason;
        if (!ParseOptions(args, 2, OptionSet::ExeAndKeys, options, reason))
        {
            fwprintf(stderr, L"%s\n", reason.c_str());
            return kExitUsage;
        }

        ModuleApi::Repacker api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"游戏 EXE：%s\n", exePath.c_str());
        fwprintf(stdout, L"参数仓库：%s\n", options.keysRoot.c_str());

        char note[4096] = {};
        char failure[4096] = {};
        if (!api.DeriveKeys(exePath.c_str(), options.keysRoot.c_str(), note, sizeof(note), failure,
                            sizeof(failure)))
        {
            fwprintf(stderr, L"取参数失败：%s\n", ModuleApi::FromAnsi(failure).c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"参数已就绪：%s\n", ModuleApi::FromAnsi(note).c_str());
        return kExitOk;
    }

    int CmdImportKey(const Arguments& args)
    {
        if (args.size() < 2)
        {
            fwprintf(stderr, L"用法：CxdecCli importkey <参数文件.hxv4p> [--exe X] [--keys X]\n");
            return kExitUsage;
        }

        const std::wstring hxv4pPath = args[1];

        Options options;
        std::wstring reason;
        if (!ParseOptions(args, 2, OptionSet::ExeAndKeys, options, reason))
        {
            fwprintf(stderr, L"%s\n", reason.c_str());
            return kExitUsage;
        }

        ModuleApi::Repacker api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        char note[4096] = {};
        char failure[4096] = {};
        const wchar_t* exeArg = options.exePath.empty() ? nullptr : options.exePath.c_str();
        if (!api.ImportKey(hxv4pPath.c_str(), exeArg, options.keysRoot.c_str(), note, sizeof(note),
                           failure, sizeof(failure)))
        {
            fwprintf(stderr, L"收编失败：%s\n", ModuleApi::FromAnsi(failure).c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"已收编：%s\n", ModuleApi::FromAnsi(note).c_str());
        return kExitOk;
    }

    int CmdNextRev(const Arguments& args)
    {
        if (args.size() != 2)
        {
            fwprintf(stderr, L"用法：CxdecCli nextrev <游戏目录>\n");
            return kExitUsage;
        }

        ModuleApi::Repacker api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"%u\n", api.NextRevision(args[1].c_str()));
        return kExitOk;
    }

    int CmdKeyStatic(const Arguments& args)
    {
        if (args.size() < 2)
        {
            fwprintf(stderr, L"用法：CxdecCli keystatic <游戏.exe> [--out <目录>]\n");
            return kExitUsage;
        }

        const std::wstring exePath = args[1];

        Options options;
        std::wstring reason;
        if (!ParseOptions(args, 2, OptionSet::KeyStaticOut, options, reason))
        {
            fwprintf(stderr, L"%s\n", reason.c_str());
            return kExitUsage;
        }

        std::wstring outputDirectory = options.outputDirectory;
        if (outputDirectory.empty())
        {
            // 与 Loader 的默认一致：产物放游戏目录下。
            // 只给了个不带目录的文件名时 ParentDirectory 会返回空串，退回当前目录。
            const std::wstring parent = ParentDirectory(exePath);
            outputDirectory = (parent.empty() ? std::wstring(L".") : parent) +
                              L"\\ExtractKey_Output\\Static";
        }

        ModuleApi::KeyStatic api;
        std::wstring error;
        if (!api.Load(error))
        {
            fwprintf(stderr, L"%s\n", error.c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"游戏 EXE：%s\n", exePath.c_str());
        fwprintf(stdout, L"输出目录：%s\n", outputDirectory.c_str());

        char failure[2048] = {};
        if (!api.ExtractKey(exePath.c_str(), outputDirectory.c_str(), failure, sizeof(failure)))
        {
            fwprintf(stderr, L"静态提取失败：%s\n", ModuleApi::FromAnsi(failure).c_str());
            return kExitFail;
        }

        fwprintf(stdout, L"静态提取完成\n");
        return kExitOk;
    }

    // 逐字节比对。只报首个差异的位置，不打印内容 —— 复刻验证时两包都是几十 MB，
    // 打印出来没有意义；给了偏移就能直接去看那一段。
    int CmdCompare(const Arguments& args)
    {
        if (args.size() != 3)
        {
            fwprintf(stderr, L"用法：CxdecCli cmp <文件A> <文件B>\n");
            return kExitUsage;
        }

        HANDLE left = ::CreateFileW(args[1].c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (left == INVALID_HANDLE_VALUE)
        {
            fwprintf(stderr, L"打不开 %s（%s）\n", args[1].c_str(),
                     ModuleApi::DescribeLastError(L"CreateFile").c_str());
            return kExitFail;
        }

        HANDLE right = ::CreateFileW(args[2].c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (right == INVALID_HANDLE_VALUE)
        {
            fwprintf(stderr, L"打不开 %s（%s）\n", args[2].c_str(),
                     ModuleApi::DescribeLastError(L"CreateFile").c_str());
            ::CloseHandle(left);
            return kExitFail;
        }

        LARGE_INTEGER leftSize{};
        LARGE_INTEGER rightSize{};
        ::GetFileSizeEx(left, &leftSize);
        ::GetFileSizeEx(right, &rightSize);

        fwprintf(stdout, L"A：%lld 字节  %s\n", leftSize.QuadPart, args[1].c_str());
        fwprintf(stdout, L"B：%lld 字节  %s\n", rightSize.QuadPart, args[2].c_str());

        std::vector<unsigned char> leftBuffer(1u << 16);
        std::vector<unsigned char> rightBuffer(1u << 16);
        unsigned long long offset = 0;
        bool found = false;

        for (;;)
        {
            DWORD leftRead = 0;
            DWORD rightRead = 0;
            if (!::ReadFile(left, leftBuffer.data(), (DWORD)leftBuffer.size(), &leftRead, nullptr) ||
                !::ReadFile(right, rightBuffer.data(), (DWORD)rightBuffer.size(), &rightRead,
                            nullptr))
            {
                fwprintf(stderr, L"读文件失败（%s）\n",
                         ModuleApi::DescribeLastError(L"ReadFile").c_str());
                ::CloseHandle(left);
                ::CloseHandle(right);
                return kExitFail;
            }

            const DWORD common = leftRead < rightRead ? leftRead : rightRead;
            for (DWORD i = 0; i < common; ++i)
            {
                if (leftBuffer[i] != rightBuffer[i])
                {
                    fwprintf(stdout, L"首个差异：偏移 %llu（0x%llX）  A=%02X B=%02X\n",
                             offset + i, offset + i, leftBuffer[i], rightBuffer[i]);
                    found = true;
                    break;
                }
            }

            if (found)
            {
                break;
            }
            if (leftRead == 0 && rightRead == 0)
            {
                break;
            }
            if (leftRead != rightRead)
            {
                // 长度不同：短的那个结束后第一个多出来的字节处就是差异
                fwprintf(stdout, L"首个差异：偏移 %llu（0x%llX）  一侧已结束\n", offset + common,
                         offset + common);
                found = true;
                break;
            }
            offset += leftRead;
        }

        ::CloseHandle(left);
        ::CloseHandle(right);

        if (!found && leftSize.QuadPart == rightSize.QuadPart)
        {
            fwprintf(stdout, L"逐字节一致\n");
            return kExitOk;
        }

        return kExitFail;
    }
}

int wmain(int argc, wchar_t** argv)
{
    SetupConsole();

    Arguments args;
    for (int index = 1; index < argc; ++index)
    {
        args.push_back(argv[index]);
    }

    if (args.empty() ||
        _wcsicmp(args[0].c_str(), L"help") == 0 ||
        _wcsicmp(args[0].c_str(), L"--help") == 0 ||
        _wcsicmp(args[0].c_str(), L"-h") == 0)
    {
        PrintUsage();
        return args.empty() ? kExitUsage : kExitOk;
    }

    const std::wstring& command = args[0];
    if (_wcsicmp(command.c_str(), L"sniff") == 0)
    {
        return CmdSniff(args);
    }
    if (_wcsicmp(command.c_str(), L"repack") == 0)
    {
        return CmdRepack(args);
    }
    if (_wcsicmp(command.c_str(), L"keys") == 0)
    {
        return CmdKeys(args);
    }
    if (_wcsicmp(command.c_str(), L"importkey") == 0)
    {
        return CmdImportKey(args);
    }
    if (_wcsicmp(command.c_str(), L"nextrev") == 0)
    {
        return CmdNextRev(args);
    }
    if (_wcsicmp(command.c_str(), L"keystatic") == 0)
    {
        return CmdKeyStatic(args);
    }
    if (_wcsicmp(command.c_str(), L"cmp") == 0)
    {
        return CmdCompare(args);
    }

    fwprintf(stderr, L"不认识的命令：%s\n\n", command.c_str());
    PrintUsage();
    return kExitUsage;
}
