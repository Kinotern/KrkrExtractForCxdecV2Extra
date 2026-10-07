#pragma once
#include <windows.h>

// CxdecRepacker 模块接口。
//
// 把「一个资源目录」封成 hxv4 变体 XP3。三种输入形态自动判定：
//   模式 1  单个域目录（16 位 hex 目录名 + 64 位 hex 文件名）
//   模式 2  多个域目录
//   模式 3  平铺的真实文件名（补丁包）
// 混合、嵌套、空目录一律报错，不猜。
//
// 输出字符串都是 **ANSI**（与其余模块一致）。

#ifdef __cplusplus
extern "C" {
#endif

// 只判断形态，不打包。
//   modeOut：1/2/3；-1 = 无法判定（此时 errorOut 写明理由）
//   detailOut：给人看的一句话，例如「多域：23 个域 / 1238 个文件」
__declspec(dllexport) BOOL __stdcall SniffInputDir(
    const wchar_t* inputDir,
    int* modeOut,
    char* detailOut, int detailOutSize,
    char* errorOut, int errorOutSize);

// 目录 -> xp3。
//   exePath        可空；给了就按它查参数仓库
//   keysRoot       参数仓库根目录（ImportKeyFile 写的就是这个）；可空，默认 "keys"
//   mediaName      盐（pathHash/fileHash 的额外输入串）。**可空**，留空就用参数里
//                  带的那个（派生产物会记下来，没有则 "xp3hnp"）。
//                  只有派生的那套不对时才需要手动指定。
//   modeOverride   1/2/3；传 -1 用嗅探结果
//   rescramble     非 0 时把干净文本搅回加扰形态
//   detailOut      会写明用了哪套参数；回落内置时会标注出来
__declspec(dllexport) BOOL __stdcall Repack(
    const wchar_t* inputDir,
    const wchar_t* outputXp3,
    const wchar_t* exePath,
    const wchar_t* keysRoot,
    const wchar_t* mediaName,
    int modeOverride,
    int rescramble,
    char* detailOut, int detailOutSize,
    char* errorOut, int errorOutSize);

// 扫描游戏目录里已有的 patch@r<N>.xp3，返回下一个可用修订号（至少 1）。
__declspec(dllexport) unsigned int __stdcall NextPatchRevision(const wchar_t* gameDir);

// 把一个 .hxv4p 参数文件收进参数仓库（记清单 + 建索引）。
//   keysRoot  仓库根目录，其下是 manifest.txt 和 <exe摘要>/profile.hxv4p
//   exePath   可空；给了就按这个 EXE 的内容摘要建索引，下次自动命中；
//             不给就按参数摘要存目录（之后只能靠 ImportKeyFile 再指定 EXE 补索引）
__declspec(dllexport) BOOL __stdcall ImportKeyFile(
    const wchar_t* hxv4pPath,
    const wchar_t* exePath,
    const wchar_t* keysRoot,
    char* noteOut, int noteOutSize,
    char* errorOut, int errorOutSize);

// 只取参数、不打包：先收编游戏目录旁已经生成好的产物，没有才从 EXE 现场派生
// （调同目录的 CxdecKeyStatic.dll），结果都收进仓库。
// Repack 在仓库里找不到参数时会自己做这件事，这个入口给界面单独用。
__declspec(dllexport) BOOL __stdcall DeriveKeys(
    const wchar_t* exePath,
    const wchar_t* keysRoot,
    char* noteOut, int noteOutSize,
    char* errorOut, int errorOutSize);

// 让导出表同时包含无装饰名，便于 GetProcAddress 直接按名字查找
// 后面的 @N 是 __stdcall 的参数字节数，改签名就得跟着改
#pragma comment(linker, "/EXPORT:SniffInputDir=_SniffInputDir@24")
#pragma comment(linker, "/EXPORT:Repack=_Repack@44")
#pragma comment(linker, "/EXPORT:NextPatchRevision=_NextPatchRevision@4")
#pragma comment(linker, "/EXPORT:ImportKeyFile=_ImportKeyFile@28")
#pragma comment(linker, "/EXPORT:DeriveKeys=_DeriveKeys@24")

#ifdef __cplusplus
}
#endif
