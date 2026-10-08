#include "ModuleApi.h"

#include <cstring>
#include <string>
#include <vector>

namespace ModuleApi
{
namespace
{
    std::wstring GetOwnModuleDirectory()
    {
        wchar_t path[MAX_PATH] = {};
        const DWORD length = ::GetModuleFileNameW(nullptr, path, _countof(path));
        if (length == 0 || length >= _countof(path))
        {
            return std::wstring();
        }

        std::wstring full(path, length);
        const size_t separator = full.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
        {
            return std::wstring();
        }
        return full.substr(0, separator);
    }

    bool FileExists(const std::wstring& path)
    {
        const DWORD attributes = ::GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    // 按名字取导出。GetProcAddress 失败时把错误码一并带出来 —— 常见的是
    // "名字对不上"（装饰名/无装饰名），盲猜很费时间。
    template <typename T>
    bool Bind(HMODULE module, const char* name, T& out, std::wstring& error)
    {
        out = reinterpret_cast<T>(::GetProcAddress(module, name));
        if (out == nullptr)
        {
            error += std::wstring(L"；导出 ") + std::wstring(name, name + strlen(name)) +
                     L" 找不到（" + DescribeLastError(L"GetProcAddress") + L"）";
            return false;
        }
        return true;
    }
}

std::wstring FromAnsi(const char* text)
{
    if (text == nullptr || text[0] == '\0')
    {
        return std::wstring();
    }

    const int length = ::MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
    if (length <= 0)
    {
        return std::wstring();
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_ACP, 0, text, -1, &wide[0], length);
    if (!wide.empty() && wide.back() == L'\0')
    {
        wide.pop_back();
    }
    return wide;
}

const std::wstring& ToolDirectory()
{
    static const std::wstring directory = GetOwnModuleDirectory();
    return directory;
}

std::wstring ResolveModulePath(const wchar_t* dllName)
{
    if (dllName == nullptr)
    {
        return std::wstring();
    }

    const std::wstring& directory = ToolDirectory();

    // 发布结构：exe 与 DLL 同在 CxdecExtractordll\，第一条命中
    const std::wstring beside = directory + L"\\" + dllName;
    if (FileExists(beside))
    {
        return beside;
    }

    // 兼容：exe 被放到工具根目录时，DLL 还在 CxdecExtractordll\ 下
    const std::wstring nested = directory + L"\\CxdecExtractordll\\" + dllName;
    if (FileExists(nested))
    {
        return nested;
    }

    return beside;
}

std::wstring DescribeLastError(const wchar_t* what)
{
    const DWORD code = ::GetLastError();

    LPWSTR message = nullptr;
    ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                         FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     reinterpret_cast<LPWSTR>(&message), 0, nullptr);

    std::wstring text = what != nullptr ? what : L"";
    text += L" code=" + std::to_wstring(code);
    if (message != nullptr)
    {
        std::wstring detail(message);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n'))
        {
            detail.pop_back();
        }
        ::LocalFree(message);
        if (!detail.empty())
        {
            text += L"(" + detail + L")";
        }
    }
    return text;
}

bool Repacker::Load(std::wstring& error)
{
    path = ResolveModulePath(L"CxdecRepacker.dll");
    module = ::LoadLibraryW(path.c_str());
    if (module == nullptr)
    {
        error = L"加载 " + path + L" 失败（" + DescribeLastError(L"LoadLibrary") + L"）";
        return false;
    }

    bool ok = true;
    ok = Bind(module, "SniffInputDir", Sniff, error) && ok;
    ok = Bind(module, "Repack", Repack, error) && ok;
    ok = Bind(module, "NextPatchRevision", NextRevision, error) && ok;
    ok = Bind(module, "ImportKeyFile", ImportKey, error) && ok;
    ok = Bind(module, "DeriveKeys", DeriveKeys, error) && ok;
    if (!ok)
    {
        error = L"从 " + path + L" 取导出失败：" + error;
        ::FreeLibrary(module);
        module = nullptr;
        return false;
    }
    return true;
}

Repacker::~Repacker()
{
    if (module != nullptr)
    {
        ::FreeLibrary(module);
        module = nullptr;
    }
}

bool KeyStatic::Load(std::wstring& error)
{
    path = ResolveModulePath(L"CxdecKeyStatic.dll");
    module = ::LoadLibraryW(path.c_str());
    if (module == nullptr)
    {
        error = L"加载 " + path + L" 失败（" + DescribeLastError(L"LoadLibrary") + L"）";
        return false;
    }

    if (!Bind(module, "ExtractKey", ExtractKey, error))
    {
        error = L"从 " + path + L" 取导出失败：" + error;
        ::FreeLibrary(module);
        module = nullptr;
        return false;
    }
    return true;
}

KeyStatic::~KeyStatic()
{
    if (module != nullptr)
    {
        ::FreeLibrary(module);
        module = nullptr;
    }
}
}  // namespace ModuleApi
