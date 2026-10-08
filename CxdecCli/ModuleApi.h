#pragma once

#include <Windows.h>
#include <string>

// 功能模块（DLL）的加载。
//
// 这些 DLL 的导出约定是「入参 wchar_t*、出参 char*（本地代码页，与其余模块一致）」，
// 导出表里同时有无装饰名和 __stdcall 装饰名，这里按无装饰名查。
//
// DLL 查找顺序与 Loader 一致：先看本 exe 的模块目录，再看其下的 CxdecExtractordll\
// —— 发布结构里 CxdecCli.exe 就在 CxdecExtractordll\ 目录里，所以第一条就命中。
namespace ModuleApi
{
    // 出参缓冲按本地代码页解成宽串（模块那边写的是 ANSI/CP_ACP）
    std::wstring FromAnsi(const char* text);

    // 本 exe 所在目录
    const std::wstring& ToolDirectory();

    // 按上面的顺序找 DLL；找不到返回空串
    std::wstring ResolveModulePath(const wchar_t* dllName);

    // 把 Win32 错误码拼成一句人看的
    std::wstring DescribeLastError(const wchar_t* what);

    struct Repacker
    {
        HMODULE module = nullptr;
        std::wstring path;

        BOOL(__stdcall* Sniff)(const wchar_t* inputDir, int* modeOut, char* detailOut,
                               int detailOutSize, char* errorOut, int errorOutSize) = nullptr;
        BOOL(__stdcall* Repack)(const wchar_t* inputDir, const wchar_t* outputXp3,
                                const wchar_t* exePath, const wchar_t* keysRoot,
                                const wchar_t* mediaName, int modeOverride, int rescramble,
                                char* detailOut, int detailOutSize, char* errorOut,
                                int errorOutSize) = nullptr;
        unsigned int(__stdcall* NextRevision)(const wchar_t* gameDir) = nullptr;
        BOOL(__stdcall* ImportKey)(const wchar_t* hxv4pPath, const wchar_t* exePath,
                                   const wchar_t* keysRoot, char* noteOut, int noteOutSize,
                                   char* errorOut, int errorOutSize) = nullptr;
        BOOL(__stdcall* DeriveKeys)(const wchar_t* exePath, const wchar_t* keysRoot, char* noteOut,
                                    int noteOutSize, char* errorOut, int errorOutSize) = nullptr;

        bool Load(std::wstring& error);
        ~Repacker();
    };

    struct KeyStatic
    {
        HMODULE module = nullptr;
        std::wstring path;

        BOOL(__stdcall* ExtractKey)(const wchar_t* exePath, const wchar_t* outputDir,
                                    char* errorOut, int errorOutSize) = nullptr;

        bool Load(std::wstring& error);
        ~KeyStatic();
    };
}
