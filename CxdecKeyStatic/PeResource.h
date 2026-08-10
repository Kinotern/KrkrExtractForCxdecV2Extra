#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace PeResource {

// --- 手动PE解析器API（接受内存中的原始PE数据） ---

/// 从原始PE数据读取命名RCData资源。
std::vector<uint8_t> read_rcdata(const uint8_t* pe_data, size_t pe_size,
                                  const char* name);

/// 通过类型名称字符串和整数ID读取自定义类型资源。
std::vector<uint8_t> read_custom_resource(const uint8_t* pe_data, size_t pe_size,
                                           const char* type, uint16_t id);

// --- Windows资源API（接受文件路径，使用LoadLibraryEx） ---

/// 从EXE文件读取命名RCData资源。
std::vector<uint8_t> read_rcdata(const wchar_t* exe_path, const wchar_t* name);

/// 通过类型名称字符串和整数ID读取自定义类型资源。
std::vector<uint8_t> read_custom_resource(const wchar_t* exe_path,
                                           const wchar_t* type_name, uint16_t id);

/// 从PE文件的给定文件偏移读取原始字节。
std::vector<uint8_t> read_raw_offset(const wchar_t* exe_path, uint32_t offset, size_t size);

} // namespace PeResource
