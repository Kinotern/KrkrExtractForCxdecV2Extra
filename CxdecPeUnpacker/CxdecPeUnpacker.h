#pragma once

#ifdef CXDECPEUNPACKER_EXPORTS
#define CXDECPEUNPACKER_API __declspec(dllexport)
#else
#define CXDECPEUNPACKER_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 检测 PE 文件是否包含已知保护壳
CXDECPEUNPACKER_API bool CxdecPeUnpacker_Detect(const wchar_t* filePath);
// 执行脱壳，输出到指定路径
CXDECPEUNPACKER_API bool CxdecPeUnpacker_Process(const wchar_t* filePath, const wchar_t* outputPath);

#ifdef __cplusplus
}
#endif
