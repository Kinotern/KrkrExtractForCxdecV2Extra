#pragma once
#include <windows.h>
#include <cstdint>

// 挂钩引擎的 TJS 字节码加载函数，拦到 startup.tjs 时改字节码并产出 _crack.exe

// 按通配特征码在引擎模块里找挂钩目标并装钩
// 装上返回 true
bool InstallRuntimeHook();

// 摘掉挂钩
void RemoveRuntimeHook();
