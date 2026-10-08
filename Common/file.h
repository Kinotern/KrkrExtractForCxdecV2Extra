#pragma once

#include <string>
#include "win32error.h"

namespace File
{
	std::string ReadAllText(const std::string& path);

	std::string ReadAllText(const std::wstring& path);

	// 写入失败发生在哪一步。
	//
	// 只回一个 false 时，"打不开文件"和"写到一半失败"在日志里没有区别。
	// 更要紧的是 fflush/fclose 的失败过去被完全忽略 —— 磁盘满时那往往正是
	// 唯一征兆，数据其实已经丢了，函数却返回成功。
	enum class WriteStage
	{
		None,
		Open,
		Arg,
		Write,
		Flush,
		Close,
	};

	const wchar_t* WriteStageName(WriteStage stage);

	bool WriteAllBytes(const std::string& path, const void* buffer, size_t size);

	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size);

	// 带阶段与错误码的写入。现有版本保留并委托给它，调用点可以逐个迁移。
	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size,
	                   WriteStage* stage, Win32Error::Info* error);

	void Delete(const std::string& path);

	void Delete(const std::wstring& path);

	// 带错误出参的删除。"文件本来就不在"算成功。
	bool Delete(const std::wstring& path, Win32Error::Info* error);
}
