#pragma once

#include <Windows.h>

#include <string>
#include <vector>

#include "win32error.h"
#include "file.h"

// 启动时的环境快照。
//
// 排查"某些机器上解包失败"时，最先要排除的就是环境差异：路径过长、盘符是网络盘、
// 剩余空间不足、系统没开长路径支持、代码页不对、输出目录干脆不可写。
// 这些一条日志就能排除，缺了就只能靠用户来回描述。
//
// header-only：Common 下的 .cpp 是逐个列进各项目文件的，加新 .cpp 要同时改一圈
// .vcxproj；这几个小工具不值得那样铺开。
//
// 依赖：用到注册表 API，链接时要有 advapi32.lib（各项目基本都已隐式带入）。
namespace Diag
{
    // 读注册表用 RegOpenKeyEx + RegQueryValueEx，而不是 RegGetValue：
    // 后者的 RRF_* 标志要求较新的 SDK 版本，本仓库各项目对 _WIN32_WINNT 的设定
    // 并不统一，用老接口最省事。KEY_WOW64_64KEY 保证看的是 64 位视图
    //（进程是 32 位，否则会被重定向到 WOW6432Node，读不到 LongPathsEnabled）。
    inline std::wstring ReadMachineValue(const wchar_t* subKey, const wchar_t* value,
                                         DWORD* typeOut)
    {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &key) !=
            ERROR_SUCCESS)
        {
            return std::wstring();
        }

        wchar_t buffer[512] = {};
        DWORD size = sizeof(buffer) - sizeof(wchar_t);
        DWORD type = 0;
        const LSTATUS status =
            ::RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size);
        ::RegCloseKey(key);

        if (status != ERROR_SUCCESS || type != REG_SZ)
        {
            return std::wstring();
        }
        if (typeOut != nullptr)
        {
            *typeOut = type;
        }
        return std::wstring(buffer);
    }

    inline std::wstring ReadMachineString(const wchar_t* subKey, const wchar_t* value)
    {
        return ReadMachineValue(subKey, value, nullptr);
    }

    inline DWORD ReadMachineDword(const wchar_t* subKey, const wchar_t* value, DWORD fallback)
    {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &key) !=
            ERROR_SUCCESS)
        {
            return fallback;
        }

        DWORD data = 0;
        DWORD size = sizeof(data);
        DWORD type = 0;
        const LSTATUS status = ::RegQueryValueExW(key, value, nullptr, &type,
                                                  reinterpret_cast<LPBYTE>(&data), &size);
        ::RegCloseKey(key);

        if (status != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(data))
        {
            return fallback;
        }
        return data;
    }

    // 探针：在目标目录里写一个小文件再删掉。
    // 这一步直接回答"这个目录到底能不能写"，比任何推断都可靠。
    inline bool ProbeWritable(const std::wstring& directory, Win32Error::Info& error)
    {
        if (directory.empty())
        {
            error.code = ERROR_INVALID_NAME;
            error.message = Win32Error::DescribeCode(error.code);
            return false;
        }

        std::wstring probe = directory;
        if (probe.back() != L'\\' && probe.back() != L'/')
        {
            probe += L'\\';
        }
        probe += L"cxdec_write_probe.tmp";

        const char payload[8] = { 'c', 'x', 'd', 'e', 'c', 0, 0, 0 };
        File::WriteStage stage = File::WriteStage::None;
        if (!File::WriteAllBytes(probe, payload, sizeof(payload), &stage, &error))
        {
            return false;
        }

        Win32Error::Info ignored;
        File::Delete(probe, &ignored);  // 删不掉不影响结论，只当没写成功过
        return true;
    }

    // 一行一条，方便调用方按自己的日志格式逐行写出。
    inline std::vector<std::wstring> SnapshotLines(const std::wstring& outputDirectory)
    {
        std::vector<std::wstring> lines;

        const std::wstring product =
            ReadMachineString(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
        const std::wstring build =
            ReadMachineString(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
        const std::wstring display =
            ReadMachineString(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");

        BOOL wow64 = FALSE;
        ::IsWow64Process(::GetCurrentProcess(), &wow64);

        lines.push_back(L"OS=" + (product.empty() ? std::wstring(L"?") : product) +
                        L" build=" + (build.empty() ? std::wstring(L"?") : build) +
                        L" ver=" + (display.empty() ? std::wstring(L"?") : display) +
                        L" process=" + (wow64 ? L"WOW64(32-on-64)" : L"32bit"));
        lines.push_back(L"ACP=" + std::to_wstring(::GetACP()) +
                        L" OEMCP=" + std::to_wstring(::GetOEMCP()) +
                        L" longPaths=" +
                        (ReadMachineDword(L"SYSTEM\\CurrentControlSet\\Control\\FileSystem",
                                          L"LongPathsEnabled", 0) != 0
                             ? L"1"
                             : L"0"));

        // 输出目标：路径、长度、盘符类型——"路径过长/网络盘"这类问题看这一行就够
        Win32Error::PathInfo path = Win32Error::InspectPath(outputDirectory);
        std::wstring target = L"output=" + path.Describe();

        ULARGE_INTEGER freeBytes{};
        ULARGE_INTEGER totalBytes{};
        if (path.drive != 0)
        {
            wchar_t root[4] = { path.drive, L':', L'\\', L'\0' };
            if (::GetDiskFreeSpaceExW(root, &freeBytes, &totalBytes, nullptr))
            {
                target += L" free=" + std::to_wstring(freeBytes.QuadPart / (1024ull * 1024ull)) +
                          L"MB/" + std::to_wstring(totalBytes.QuadPart / (1024ull * 1024ull)) + L"MB";
            }
            else
            {
                Win32Error::Info err = Win32Error::Capture();
                target += L" free=?(GetDiskFreeSpaceEx ";
                target += Win32Error::Describe(err);
                target += L")";
            }
        }
        lines.push_back(target);

        // 可写探针：直接给结论，不留推断空间
        Win32Error::Info probeError;
        if (ProbeWritable(outputDirectory, probeError))
        {
            lines.push_back(L"output writable=yes");
        }
        else
        {
            lines.push_back(L"output writable=NO " + Win32Error::FailureLine(L"probe", outputDirectory, probeError));
        }

        return lines;
    }
}
