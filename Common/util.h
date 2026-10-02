#pragma once

#include <windows.h>
#include <string>

namespace Util
{
	std::string GetModulePathA(HMODULE hModule);

	std::wstring GetModulePathW(HMODULE hModule);

	std::string GetAppPathA();

	std::wstring GetAppPathW();

	std::string GetAppDirectoryA();

	std::wstring GetAppDirectoryW();

	std::string GetLastErrorMessageA();

	std::wstring GetLastErrorMessageW();

	__declspec(noreturn) void ThrowError(const char* format, ...);

	__declspec(noreturn) void ThrowError(const wchar_t* format, ...);

	void WriteDebugMessage(const char* format, ...);

	void WriteDebugMessage(const wchar_t* format, ...);

	std::string OpenFolderDialog(const std::string& title);

	std::wstring OpenFolderDialog(const std::wstring& title);
}
