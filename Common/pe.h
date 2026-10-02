#pragma once

#include <windows.h>
#include <type_traits>

namespace PE
{
	PVOID GetModuleBase(HMODULE hModule);

	DWORD GetModuleSize(HMODULE hModule);

	PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE hModule, PCSTR lpName);

	PVOID GetImportAddress(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName);

	PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen);

	BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize);

	template<typename T, typename std::enable_if_t<std::is_scalar_v<T>, bool> = true>
	BOOL WriteValue(PVOID lpAddress, T tValue)
	{
		return WriteMemory(lpAddress, &tValue, sizeof(T));
	}

	BOOL IATHook(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewProc, PVOID* lpOriginalProc);
}
