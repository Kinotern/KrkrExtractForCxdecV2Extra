#pragma once

// 本头文件会经 file.h / directory.h 被很广地包含进去，
// 所以必须先把 min/max 宏关掉：Windows.h 默认把它们定义成宏，
// 会把别处的 std::max / std::min 直接撞坏（实测 Common/file.cpp 立刻中招）。
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <cerrno>
#include <cwctype>
#include <string>

// 统一的"失败现场"：哪一步、哪个路径、哪个错误码。
//
// 为什么单独拎出来：现有代码的失败路径普遍只写一句 "Write Error"，
// CreateDirectoryW / _wfopen_s / fwrite 的返回值与错误码全被丢掉，
// 用户机器上出问题时无从判断是权限、路径过长、磁盘满还是名字冲突。
//
// 做成 header-only（全 inline）：Common 下的 .cpp 是逐个列进各项目文件的，
// 加新 .cpp 要同时改一圈 .vcxproj；这几个小工具不值得那样铺开。
namespace Win32Error
{
    // 错误码 + 系统消息。
    //
    // **必须立即捕获**：任何中间 API 调用都会冲掉 GetLastError，
    // 所以不要"先做点别的再回头看错误码"。
    struct Info
    {
        DWORD code = ERROR_SUCCESS;  // GetLastError() 的码
        int crtErrno = 0;            // CRT 层 errno（_wfopen_s / fwrite 用）
        std::wstring message;        // 系统消息（英文，便于搜索与反馈）

        bool ok() const { return code == ERROR_SUCCESS && crtErrno == 0; }
    };

    // 常见错误码的名字。日志里只写数字用户看不懂，写名字才一眼能判断方向。
    inline const wchar_t* CodeName(DWORD code)
    {
        switch (code)
        {
            case ERROR_SUCCESS: return L"ERROR_SUCCESS";
            case ERROR_FILE_NOT_FOUND: return L"ERROR_FILE_NOT_FOUND";
            case ERROR_PATH_NOT_FOUND: return L"ERROR_PATH_NOT_FOUND";
            case ERROR_ACCESS_DENIED: return L"ERROR_ACCESS_DENIED";
            case ERROR_INVALID_HANDLE: return L"ERROR_INVALID_HANDLE";
            case ERROR_INVALID_DRIVE: return L"ERROR_INVALID_DRIVE";
            case ERROR_NOT_SAME_DEVICE: return L"ERROR_NOT_SAME_DEVICE";
            case ERROR_WRITE_PROTECT: return L"ERROR_WRITE_PROTECT";
            case ERROR_CRC: return L"ERROR_CRC";
            case ERROR_SHARING_VIOLATION: return L"ERROR_SHARING_VIOLATION";
            case ERROR_LOCK_VIOLATION: return L"ERROR_LOCK_VIOLATION";
            case ERROR_HANDLE_DISK_FULL: return L"ERROR_HANDLE_DISK_FULL";
            case ERROR_CANNOT_MAKE: return L"ERROR_CANNOT_MAKE";
            case ERROR_INVALID_NAME: return L"ERROR_INVALID_NAME";
            case ERROR_BAD_PATHNAME: return L"ERROR_BAD_PATHNAME";
            case ERROR_ALREADY_EXISTS: return L"ERROR_ALREADY_EXISTS";
            case ERROR_DIR_NOT_EMPTY: return L"ERROR_DIR_NOT_EMPTY";
            case ERROR_FILENAME_EXCED_RANGE: return L"ERROR_FILENAME_EXCED_RANGE";
            case ERROR_DISK_FULL: return L"ERROR_DISK_FULL";
            case ERROR_DIRECTORY: return L"ERROR_DIRECTORY";
            case ERROR_TOO_MANY_OPEN_FILES: return L"ERROR_TOO_MANY_OPEN_FILES";
            case ERROR_NOT_ENOUGH_MEMORY: return L"ERROR_NOT_ENOUGH_MEMORY";
            case ERROR_IO_DEVICE: return L"ERROR_IO_DEVICE";
            case ERROR_DEVICE_NOT_CONNECTED: return L"ERROR_DEVICE_NOT_CONNECTED";
            case ERROR_PRIVILEGE_NOT_HELD: return L"ERROR_PRIVILEGE_NOT_HELD";
            default: return L"";
        }
    }

    // CRT errno 的名字与常见对应关系（写文件失败时 errno 往往比 GetLastError 更准）。
    inline const wchar_t* ErrnoName(int e)
    {
        switch (e)
        {
            case ENOENT: return L"ENOENT";
            case EACCES: return L"EACCES";
            case EEXIST: return L"EEXIST";
            case EIO: return L"EIO";
            case EMFILE: return L"EMFILE";
            case EINVAL: return L"EINVAL";
            case ENOMEM: return L"ENOMEM";
            case ENOSPC: return L"ENOSPC";
            case ENOTDIR: return L"ENOTDIR";
            case ENAMETOOLONG: return L"ENAMETOOLONG";
            default: return L"";
        }
    }

    // 按传入的码取系统消息。刻意**不**读 GetLastError：
    // Common/util.cpp 里那个 GetLastErrorMessageW() 读的是"当前"错误码，
    // 中间只要插进一次 API 调用就会记错，这里要的是"捕到就固定"的版本。
    inline std::wstring DescribeCode(DWORD code)
    {
        if (code == ERROR_SUCCESS)
        {
            return std::wstring();
        }

        LPWSTR buffer = nullptr;
        const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                            FORMAT_MESSAGE_IGNORE_INSERTS;
        const DWORD lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
        if (::FormatMessageW(flags, nullptr, code, lang,
                             reinterpret_cast<LPWSTR>(&buffer), 0, nullptr) == 0 ||
            buffer == nullptr)
        {
            return std::wstring();
        }

        std::wstring text(buffer);
        ::LocalFree(buffer);

        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' '))
        {
            text.pop_back();
        }
        return text;
    }

    // 立刻抓当前线程的最后一个 Win32 错误。
    inline Info Capture()
    {
        Info info;
        info.code = ::GetLastError();
        info.message = DescribeCode(info.code);
        return info;
    }

    // 立刻抓当前 errno，并把等价的 Win32 码一并带上（两个都给，便于交叉判断）。
    inline Info CaptureCrt()
    {
        Info info;
        info.crtErrno = errno;
        switch (info.crtErrno)
        {
            case ENOENT: info.code = ERROR_FILE_NOT_FOUND; break;
            case EACCES: info.code = ERROR_ACCESS_DENIED; break;
            case EEXIST: info.code = ERROR_ALREADY_EXISTS; break;
            case ENOSPC: info.code = ERROR_DISK_FULL; break;
            case ENOTDIR: info.code = ERROR_DIRECTORY; break;
            case ENAMETOOLONG: info.code = ERROR_FILENAME_EXCED_RANGE; break;
            case ENOMEM: info.code = ERROR_NOT_ENOUGH_MEMORY; break;
            default: break;
        }
        info.message = DescribeCode(info.code);
        return info;
    }

    // 一次把两个都抓下来：Win32 码（更具体）+ CRT errno（CRT 调用只设这个）。
    // 两者互补，都记下来最省事。**同样必须在失败那一刻调用**。
    inline Info CaptureBoth()
    {
        Info info;
        info.crtErrno = errno;
        info.code = ::GetLastError();
        if (info.code == ERROR_SUCCESS)
        {
            info.code = CaptureCrt().code;
        }
        info.message = DescribeCode(info.code);
        return info;
    }

    // 打成一行：code=5(ERROR_ACCESS_DENIED) errno=13(EACCES) Access is denied.
    //
    // Win32 侧没有码（CRT 调用失败常常只设 errno）时不打 code=0，
    // 否则日志里会出现"code=0(ERROR_SUCCESS)"这种误导。
    inline std::wstring Describe(const Info& info)
    {
        std::wstring out;
        if (info.code != ERROR_SUCCESS)
        {
            out = L"code=" + std::to_wstring(info.code);
            const wchar_t* codeName = CodeName(info.code);
            if (codeName[0] != L'\0')
            {
                out += L"(";
                out += codeName;
                out += L")";
            }
        }

        if (info.crtErrno != 0)
        {
            if (!out.empty())
            {
                out += L" ";
            }
            out += L"errno=" + std::to_wstring(info.crtErrno);
            const wchar_t* errnoName = ErrnoName(info.crtErrno);
            if (errnoName[0] != L'\0')
            {
                out += L"(";
                out += errnoName;
                out += L")";
            }
        }

        if (out.empty())
        {
            out = L"code=0(无错误码)";
        }

        if (!info.message.empty())
        {
            out += L" ";
            out += info.message;
        }
        return out;
    }

    // 路径诊断。排查"路径过长 / 非法字符 / 盘符不对"这类问题时，
    // 光有错误码不够，必须把完整路径和长度一起记下来。
    struct PathInfo
    {
        std::wstring full;
        size_t length = 0;         // 字符数（含盘符与反斜杠）
        bool overMaxPath = false;  // 是否达到传统 MAX_PATH 限制
        wchar_t drive = 0;         // 盘符（大写），没有则为 0
        UINT driveType = 0;        // GetDriveTypeW 的结果：0 表示取不到

        std::wstring Describe() const
        {
            std::wstring out = L"path=\"" + full + L"\" len=" + std::to_wstring(length);
            if (overMaxPath)
            {
                out += L" [>=MAX_PATH]";
            }
            if (drive != 0)
            {
                out += L" drive=";
                out += drive;
                out += L":";
            }
            switch (driveType)
            {
                case DRIVE_FIXED: out += L"(fixed)"; break;
                case DRIVE_REMOVABLE: out += L"(removable)"; break;
                case DRIVE_REMOTE: out += L"(network)"; break;
                case DRIVE_CDROM: out += L"(cdrom)"; break;
                case DRIVE_RAMDISK: out += L"(ramdisk)"; break;
                case DRIVE_NO_ROOT_DIR: out += L"(no-root)"; break;
                default: break;
            }
            return out;
        }
    };

    inline PathInfo InspectPath(const std::wstring& path)
    {
        PathInfo info;
        info.full = path;
        info.length = path.size();
        info.overMaxPath = path.size() >= MAX_PATH;

        if (path.size() >= 2 && path[1] == L':')
        {
            info.drive = static_cast<wchar_t>(::towupper(path[0]));
            wchar_t root[4] = { info.drive, L':', L'\\', L'\0' };
            info.driveType = ::GetDriveTypeW(root);
        }
        return info;
    }

    // 一步失败打成日志行：步骤名 + 路径诊断 + 错误码。
    inline std::wstring FailureLine(const wchar_t* step, const std::wstring& path, const Info& err)
    {
        std::wstring out = L"step=";
        out += (step != nullptr ? step : L"?");
        out += L" ";
        out += InspectPath(path).Describe();
        out += L" ";
        out += Describe(err);
        return out;
    }
}
