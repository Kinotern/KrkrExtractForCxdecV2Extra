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
// 上一次失败的原因（模块内的静态串，下次调用前一直有效）。
// 没失败时返回空串。这两个导出的错误本来只写在这里没人看，等于报不出来。
CXDECPEUNPACKER_API const wchar_t* CxdecPeUnpacker_LastError();

#ifdef __cplusplus
}
#endif
