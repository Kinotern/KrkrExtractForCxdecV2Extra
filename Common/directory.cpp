﻿﻿﻿/**
 * @file directory.cpp
 * @brief 目录操作工具类实现
 * 
 * 提供目录存在性检查和目录创建功能，支持递归创建多级目录。
 */

#include <Windows.h>
#include "directory.h"
#include "path.h"

namespace Directory
{
    /**
     * @brief 检查目录是否存在（ANSI路径）
     * 
     * 使用 GetFileAttributesA 获取文件属性，判断是否为目录。
     * 
     * @param dirPath 目录路径（ANSI）
     * @return 目录存在返回 true，否则返回 false
     */
	bool Exists(const std::string& dirPath)
	{
		DWORD fileAttr = GetFileAttributesA(dirPath.c_str());
		if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			return false;
		}
		return true;
	}

    /**
     * @brief 检查目录是否存在（Unicode路径）
     * 
     * 使用 GetFileAttributesW 获取文件属性，判断是否为目录。
     * 
     * @param dirPath 目录路径（Unicode）
     * @return 目录存在返回 true，否则返回 false
     */
	bool Exists(const std::wstring& dirPath)
	{
		DWORD fileAttr = GetFileAttributesW(dirPath.c_str());
		if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			return false;
		}
		return true;
	}

    /**
     * @brief 创建目录（ANSI路径）
     * 
     * 支持递归创建多级目录。如果直接创建失败，先递归创建父目录。
     * 
     * @param dirPath 目录路径（ANSI）
     */
	void Create(const std::string& dirPath)
	{
		if (!Directory::Exists(dirPath))
		{
			if (!CreateDirectoryA(dirPath.c_str(), NULL))
			{
				Directory::Create(Path::GetDirectoryName(dirPath));
				CreateDirectoryA(dirPath.c_str(), NULL);
			}
		}
	}

    /**
     * @brief 创建目录（Unicode路径）
     * 
     * 支持递归创建多级目录。如果直接创建失败，先递归创建父目录。
     * 
     * @param dirPath 目录路径（Unicode）
     */
	void Create(const std::wstring& dirPath)
	{
		if (!Directory::Exists(dirPath))
		{
			if (!CreateDirectoryW(dirPath.c_str(), NULL))
			{
				Directory::Create(Path::GetDirectoryName(dirPath));
				CreateDirectoryW(dirPath.c_str(), NULL);
			}
		}
	}
}
