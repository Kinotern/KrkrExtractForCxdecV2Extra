#pragma once
#include <windows.h>
#include <cstdint>

// 遍历内存，找带 .detour 节且 key 匹配的模块
// 返回条目数据指针，找不到返回 nullptr
const uint8_t* FindDetourEntry();

// 应用条目里的三处补丁
// 打过补丁返回 true
bool ApplyDetourPatches(const uint8_t* entry);

// 调试用：转储完整载荷
void DumpDetourEntry(const uint8_t* entry);
