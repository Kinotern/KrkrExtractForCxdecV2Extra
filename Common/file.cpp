﻿/**
 * @file file.cpp
 * @brief 文件操作工具类实现
 * 
 * 提供基础的文件读写操作封装，支持 ANSI 和 Unicode 路径，
 * 自动处理 UTF-8 BOM 标记。
 */

#include <string>
#include <fstream>
#include <limits>
#include <cstdio>
#include "file.h"

namespace File
{
    /**
     * @brief 读取文本文件全部内容（ANSI路径）
     * 
     * 实现细节：
     * 1. 使用 fopen_s 打开文件（安全版本）
     * 2. 使用 _fseeki64/_ftelli64 支持大文件（超过 4GB）
     * 3. 检测 UTF-8 BOM（0xEF 0xBB 0xBF）并自动跳过
     * 4. 使用 goto 语句统一错误处理路径
     * 
     * @param path 文件路径（ANSI）
     * @return 文件内容字符串，失败时返回空字符串
     */
	std::string ReadAllText(const std::string& path)
	{
		FILE* fp;
		long long size;
		size_t length;
		unsigned char buf[3];
		bool utf8bom;
		std::string output;

		if (fopen_s(&fp, path.c_str(), "rb") != 0)
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_END) != 0)
		{
			goto error;
		}

		size = _ftelli64(fp);

		if (size <= 0)
		{
			goto error;
		}

		if (static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max())
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_SET) != 0)
		{
			goto error;
		}

		length = static_cast<size_t>(size);

		utf8bom = false;

		if (fread(buf, 3, 1, fp) == 1)
		{
			if (buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
			{
				utf8bom = true;
			}
		}

		if (utf8bom)
		{
			length -= 3;
		}
		else
		{
			if (_fseeki64(fp, 0, SEEK_SET) != 0)
			{
				goto error;
			}
		}

		if (length == 0)
		{
			goto error;
		}

		output.resize(length);

		if (fread(output.data(), length, 1, fp) != 1)
		{
			goto error;
		}

		fclose(fp);

		return output;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return std::string();
	}

    /**
     * @brief 读取文本文件全部内容（Unicode路径）
     * 
     * 与 ANSI 版本逻辑相同，仅路径参数类型不同。
     * 使用 _wfopen_s 支持 Unicode 路径。
     * 
     * @param path 文件路径（Unicode）
     * @return 文件内容字符串，失败时返回空字符串
     */
	std::string ReadAllText(const std::wstring& path)
	{
		FILE* fp;
		long long size;
		size_t length;
		unsigned char buf[3];
		bool utf8bom;
		std::string output;

		if (_wfopen_s(&fp, path.c_str(), L"rb") != 0)
		{
			goto error;
		}

		if (fp == nullptr)
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_END) != 0)
		{
			goto error;
		}

		size = _ftelli64(fp);

		if (size <= 0)
		{
			goto error;
		}

		if (static_cast<uint64_t>(size) > std::numeric_limits<size_t>::max())
		{
			goto error;
		}

		if (_fseeki64(fp, 0, SEEK_SET) != 0)
		{
			goto error;
		}

		length = static_cast<size_t>(size);

		utf8bom = false;

		if (fread(buf, 3, 1, fp) == 1)
		{
			if (buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
			{
				utf8bom = true;
			}
		}

		if (utf8bom)
		{
			length -= 3;
		}
		else
		{
			if (_fseeki64(fp, 0, SEEK_SET) != 0)
			{
				goto error;
			}
		}

		if (length == 0)
		{
			goto error;
		}

		output.resize(length);

		if (fread(output.data(), length, 1, fp) != 1)
		{
			goto error;
		}

		fclose(fp);

		return output;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return std::string();
	}

    /**
     * @brief 写入字节数据到文件（ANSI路径）
     * 
     * 实现细节：
     * 1. 使用 fopen_s 以二进制写入模式打开文件
     * 2. 写入前验证参数有效性（buffer 不为空、size > 0）
     * 3. 使用 fflush 确保数据立即写入磁盘
     * 4. 统一错误处理路径
     * 
     * @param path 文件路径（ANSI）
     * @param buffer 数据缓冲区指针
     * @param size 数据大小（字节）
     * @return 写入成功返回 true，失败返回 false
     */
	bool WriteAllBytes(const std::string& path, const void* buffer, size_t size)
	{
		FILE* fp;

		if (fopen_s(&fp, path.c_str(), "wb") != 0)
		{
			goto error;
		}

		if (buffer == nullptr)
		{
			goto error;
		}

		if (size == 0)
		{
			goto error;
		}

		if (fwrite(buffer, size, 1, fp) != 1)
		{
			goto error;
		}

		fflush(fp);

		fclose(fp);

		return true;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return false;
	}

    /**
     * @brief 写入字节数据到文件（Unicode路径）
     * 
     * 与 ANSI 版本逻辑相同，仅路径参数类型不同。
     * 使用 _wfopen_s 支持 Unicode 路径。
     * 
     * @param path 文件路径（Unicode）
     * @param buffer 数据缓冲区指针
     * @param size 数据大小（字节）
     * @return 写入成功返回 true，失败返回 false
     */
	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size)
	{
		FILE* fp;

		if (_wfopen_s(&fp, path.c_str(), L"wb") != 0)
		{
			goto error;
		}

		if (fp == nullptr)
		{
			goto error;
		}

		if (buffer == nullptr)
		{
			goto error;
		}

		if (size == 0)
		{
			goto error;
		}

		if (fwrite(buffer, size, 1, fp) != 1)
		{
			goto error;
		}

		fflush(fp);

		fclose(fp);

		return true;

	error:
		if (fp)
		{
			fclose(fp);
		}

		return false;
	}

    /**
     * @brief 删除文件（ANSI路径）
     * 
     * 使用标准 C 库函数 remove 删除文件，忽略删除失败。
     * 
     * @param path 文件路径（ANSI）
     */
	void Delete(const std::string& path)
	{
		remove(path.c_str());
	}

    /**
     * @brief 删除文件（Unicode路径）
     * 
     * 使用 Windows API _wremove 删除文件，支持 Unicode 路径。
     * 
     * @param path 文件路径（Unicode）
     */
	void Delete(const std::wstring& path)
	{
		_wremove(path.c_str());
	}
}
