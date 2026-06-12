/**
 * @file pe.cpp
 * @brief PE文件操作工具类实现
 * 
 * 提供对 Windows PE（Portable Executable）文件的底层操作功能，
 * 包括模块基址获取、节区定位、导入表操作和内存搜索等。
 */

#include "pe.h"

namespace PE
{
    /**
     * @brief 获取指定模块的基地址
     * 
     * 使用 VirtualQuery 获取模块的实际分配基址。
     * 在启用 ASLR（地址空间布局随机化）的系统上，
     * 模块的实际加载地址可能与链接时的基址不同。
     * 
     * @param hModule 模块句柄
     * @return 模块基地址，失败返回 nullptr
     */
	PVOID GetModuleBase(HMODULE hModule)
	{
		MEMORY_BASIC_INFORMATION mem;

		if (!VirtualQuery(hModule, &mem, sizeof(mem)))
			return 0;

		return mem.AllocationBase;
	}

    /**
     * @brief 获取指定模块的大小
     * 
     * 从 PE 头的 OptionalHeader.SizeOfImage 字段获取模块总大小。
     * 该值表示整个模块在内存中的大小，包括所有节区和头部。
     * 
     * @param hModule 模块句柄
     * @return 模块大小（字节），失败返回 0
     */
	DWORD GetModuleSize(HMODULE hModule)
	{
		return ((PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	}

    /**
     * @brief 获取指定名称的节区头
     * 
     * 遍历 PE 文件的节区表，查找匹配名称的节区。
     * 节区名称存储在 IMAGE_SECTION_HEADER.Name 字段中（8字节，可能不足8字节时用0填充）。
     * 
     * @param hModule 模块句柄
     * @param lpName 节区名称（如 ".text", ".data"）
     * @return 节区头指针，未找到返回 nullptr
     */
	PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE hModule, PCSTR lpName)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
			return NULL;

		PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader + sizeof(pNtHeader->Signature) + sizeof(pNtHeader->FileHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader);

		for (DWORD n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++)
		{
			if (strcmp((PCSTR)pSectionHeaders[n].Name, lpName) == 0)
			{
				if (pSectionHeaders[n].VirtualAddress == 0 || pSectionHeaders[n].SizeOfRawData == 0)
					return NULL;

				return &pSectionHeaders[n];
			}
		}

		return NULL;
	}

    /**
     * @brief RVA 到实际地址的转换
     * 
     * 将 PE 文件中的相对虚拟地址（RVA）转换为内存中的实际地址。
     * 
     * @param pDosHeader DOS头指针
     * @param raddr RVA地址
     * @return 实际内存地址，失败返回 nullptr
     */
	static inline PBYTE RvaAdjust(PIMAGE_DOS_HEADER pDosHeader, DWORD raddr)
	{
		if (raddr != NULL)
		{
			return ((PBYTE)pDosHeader) + raddr;
		}

		return NULL;
	}

    /**
     * @brief 获取导入表中指定函数的地址
     * 
     * 遍历导入表，查找指定模块中的指定函数，返回其在 IAT（导入地址表）中的地址。
     * 
     * PE文件导入表结构：
     * - IMAGE_IMPORT_DESCRIPTOR 数组，每个元素对应一个导入模块
     * - 每个导入模块包含 OriginalFirstThunk（指向 IMAGE_THUNK_DATA 数组）
     * - IMAGE_THUNK_DATA 包含函数名或序号
     * - FirstThunk 指向 IAT，运行时被填充为实际函数地址
     * 
     * @param hModule 模块句柄
     * @param lpModuleName 导入模块名称（如 "kernel32.dll"）
     * @param lpProcName 函数名称
     * @return IAT 中函数地址的指针，未找到返回 nullptr
     */
	PVOID GetImportAddress(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
			return NULL;

		PIMAGE_IMPORT_DESCRIPTOR iidp = (PIMAGE_IMPORT_DESCRIPTOR)RvaAdjust(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (iidp == NULL)
			return NULL;

		for (; iidp->OriginalFirstThunk != 0; iidp++)
		{
			LPCSTR lpszModule = (LPCSTR)RvaAdjust(pDosHeader, iidp->Name);

			if (lpszModule == NULL)
				return NULL;

			if (_stricmp(lpszModule, lpModuleName) != 0)
				continue;

			PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);

			PVOID* pAddrs = (PVOID*)RvaAdjust(pDosHeader, iidp->FirstThunk);

			if (pThunks == NULL)
				continue;

			for (DWORD i = 0; pThunks[i].u1.Ordinal; i++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunks[i].u1.Ordinal))
					continue;

				LPCSTR lpszProc = (PCSTR)RvaAdjust(pDosHeader, (DWORD)pThunks[i].u1.AddressOfData + 2);

				if (lpszProc == NULL)
					continue;

				if (strcmp(lpszProc, lpProcName) == 0)
					return &pAddrs[i];
			}
		}

		return NULL;
	}

    /**
     * @brief 在内存中搜索指定模式
     * 
     * 使用暴力匹配算法搜索内存区域中的字节模式。
     * 支持通配符 '0x2A'（ASCII '*'）匹配任意字节。
     * 
     * 算法复杂度：O(n*m)，其中 n 是搜索范围大小，m 是模式长度。
     * 适用于较小的搜索范围（如单个模块），对于大内存区域效率较低。
     * 
     * @param lpStartSearch 搜索起始地址
     * @param dwSearchLen 搜索长度（字节）
     * @param lpPattern 搜索模式（字节数组）
     * @param dwPatternLen 模式长度（字节）
     * @return 匹配位置，未找到返回 nullptr
     */
	PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen)
	{
		ULONG_PTR dwStartAddr = (ULONG_PTR)lpStartSearch;
		ULONG_PTR dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

		while (dwStartAddr < dwEndAddr)
		{
			bool found = true;

			for (DWORD i = 0; i < dwPatternLen; i++)
			{
				char code = *(char*)(dwStartAddr + i);

				if (lpPattern[i] != 0x2A && lpPattern[i] != code)
				{
					found = false;
					break;
				}
			}

			if (found)
				return (PVOID)dwStartAddr;

			dwStartAddr++;
		}

		return 0;
	}

    /**
     * @brief 向指定地址写入数据
     * 
     * 使用 VirtualProtect 修改内存保护属性为 PAGE_EXECUTE_READWRITE，
     * 写入数据后恢复原保护属性。
     * 
     * @param lpAddress 目标地址
     * @param lpBuffer 数据缓冲区
     * @param nSize 数据大小（字节）
     * @return 写入成功返回 TRUE，失败返回 FALSE
     */
	BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize)
	{
		DWORD dwProtect;

		if (VirtualProtect(lpAddress, nSize, PAGE_EXECUTE_READWRITE, &dwProtect))
		{
			memcpy(lpAddress, lpBuffer, nSize);
			VirtualProtect(lpAddress, nSize, dwProtect, &dwProtect);
			return TRUE;
		}

		return FALSE;
	}

    /**
     * @brief Hook 导入表中的函数
     * 
     * 将导入表中指定函数的地址替换为新函数地址。
     * 首先使用 GetImportAddress 获取 IAT 中函数地址的指针，
     * 然后使用 WriteValue 写入新函数地址。
     * 
     * @param hModule 目标模块句柄
     * @param lpModuleName 导入模块名称
     * @param lpProcName 要 Hook 的函数名称
     * @param lpNewProc 新函数地址
     * @param lpOriginalProc [输出] 保存原始函数地址（可选）
     * @return Hook 成功返回 TRUE，失败返回 FALSE
     */
	BOOL IATHook(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewProc, PVOID* lpOriginalProc)
	{
		PVOID lpAddress = GetImportAddress(hModule, lpModuleName, lpProcName);

		if (lpAddress == NULL)
		{
			return FALSE;
		}

		if (lpOriginalProc)
		{
			*lpOriginalProc = *(PVOID*)lpAddress;
		}

		return WriteValue(lpAddress, lpNewProc);
	}
}
