#pragma once

#include <string>
#include "win32error.h"

namespace Directory
{
	bool Exists(const std::string& dirPath);

	bool Exists(const std::wstring& dirPath);

	void Create(const std::string& dirPath);

	void Create(const std::wstring& dirPath);

	// 带错误出参的建目录。
	//
	// 原来的版本把两次 CreateDirectoryW 的返回值全丢了，"建目录失败"和"写文件失败"
	// 在日志里长得一模一样，用户机器上出问题时无法判断是权限、路径过长还是磁盘满。
	// 这里把失败精确到"父目录建不出来"还是"自身建不出来"，各自带错误码。
	//
	// 现有 void 版本保留并委托给它，调用点可以逐个迁移。
	bool Create(const std::wstring& dirPath, Win32Error::Info* error);
}
