/**
 * @file pe.h
 * @brief PE文件操作工具类
 * 
 * 提供对 Windows PE（Portable Executable）文件的底层操作功能，
 * 包括模块基址获取、节区定位、导入表操作和内存搜索等。
 */

#pragma once

#include <windows.h>
#include <type_traits>

namespace PE
{
    /**
     * @brief 获取指定模块的基地址
     * 
     * 使用 VirtualQuery 获取模块的实际分配基址，
     * 这可能与 HMODULE 值不同（如 ASLR 启用时）。
     * 
     * @param hModule 模块句柄
     * @return 模块基地址，失败返回 nullptr
     */
	PVOID GetModuleBase(HMODULE hModule);

    /**
     * @brief 获取指定模块的大小
     * 
     * 从 PE 头的 OptionalHeader.SizeOfImage 字段获取模块总大小。
     * 
     * @param hModule 模块句柄
     * @return 模块大小（字节），失败返回 0
     */
	DWORD GetModuleSize(HMODULE hModule);

    /**
     * @brief 获取指定名称的节区头
     * 
     * 遍历 PE 文件的节区表，查找匹配名称的节区。
     * 
     * @param hModule 模块句柄
     * @param lpName 节区名称（如 ".text", ".data"）
     * @return 节区头指针，未找到返回 nullptr
     */
	PIMAGE_SECTION_HEADER GetSectionHeader(HMODULE hModule, PCSTR lpName);

    /**
     * @brief 获取导入表中指定函数的地址
     * 
     * 遍历导入表，查找指定模块中的指定函数，返回其在 IAT 中的地址。
     * 
     * @param hModule 模块句柄
     * @param lpModuleName 导入模块名称（如 "kernel32.dll"）
     * @param lpProcName 函数名称
     * @return IAT 中函数地址的指针，未找到返回 nullptr
     */
	PVOID GetImportAddress(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName);

    /**
     * @brief 在内存中搜索指定模式
     * 
     * 使用暴力匹配算法搜索内存区域中的字节模式。
     * 支持通配符 '0x2A' 匹配任意字节。
     * 
     * @param lpStartSearch 搜索起始地址
     * @param dwSearchLen 搜索长度（字节）
     * @param lpPattern 搜索模式（字节数组）
     * @param dwPatternLen 模式长度（字节）
     * @return 匹配位置，未找到返回 nullptr
     */
	PVOID SearchPattern(PVOID lpStartSearch, DWORD dwSearchLen, const char* lpPattern, DWORD dwPatternLen);

    /**
     * @brief 向指定地址写入数据
     * 
     * 使用 VirtualProtect 修改内存保护属性为可写，写入数据后恢复原保护属性。
     * 
     * @param lpAddress 目标地址
     * @param lpBuffer 数据缓冲区
     * @param nSize 数据大小（字节）
     * @return 写入成功返回 TRUE，失败返回 FALSE
     */
	BOOL WriteMemory(PVOID lpAddress, PVOID lpBuffer, DWORD nSize);

    /**
     * @brief 向指定地址写入标量值
     * 
     * 模板函数，用于向内存地址写入各种标量类型（int, float, pointer等）。
     * 通过 std::enable_if 限制只接受标量类型。
     * 
     * @tparam T 标量类型（int, float, pointer等）
     * @param lpAddress 目标地址
     * @param tValue 要写入的值
     * @return 写入成功返回 TRUE，失败返回 FALSE
     */
	template<typename T, typename std::enable_if_t<std::is_scalar_v<T>, bool> = true>
	BOOL WriteValue(PVOID lpAddress, T tValue)
	{
		return WriteMemory(lpAddress, &tValue, sizeof(T));
	}

    /**
     * @brief Hook 导入表中的函数
     * 
     * 将导入表中指定函数的地址替换为新函数地址，
     * 可选保存原始函数地址。
     * 
     * @param hModule 目标模块句柄
     * @param lpModuleName 导入模块名称
     * @param lpProcName 要 Hook 的函数名称
     * @param lpNewProc 新函数地址
     * @param lpOriginalProc [输出] 保存原始函数地址（可选）
     * @return Hook 成功返回 TRUE，失败返回 FALSE
     */
	BOOL IATHook(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewProc, PVOID* lpOriginalProc);
}
