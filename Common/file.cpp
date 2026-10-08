#include <string>
#include <fstream>
#include <limits>
#include <cstdio>
#include "file.h"

namespace File
{
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

	const wchar_t* WriteStageName(WriteStage stage)
	{
		switch (stage)
		{
			case WriteStage::Open: return L"Open";
			case WriteStage::Arg: return L"Arg";
			case WriteStage::Write: return L"Write";
			case WriteStage::Flush: return L"Flush";
			case WriteStage::Close: return L"Close";
			default: return L"None";
		}
	}

	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size)
	{
		return WriteAllBytes(path, buffer, size, nullptr, nullptr);
	}

	bool WriteAllBytes(const std::wstring& path, const void* buffer, size_t size,
	                   WriteStage* stage, Win32Error::Info* error)
	{
		if (stage != nullptr)
		{
			*stage = WriteStage::None;
		}

		// 错误码在失败那一刻就取：作为实参求值，保证"失败的那次调用"之后
		// 没有别的 API 插进来把 GetLastError / errno 冲掉。
		const auto record = [&](WriteStage s, DWORD win32Code, int crtCode) {
			if (stage != nullptr)
			{
				*stage = s;
			}
			if (error == nullptr)
			{
				return;
			}
			error->code = win32Code;
			error->crtErrno = crtCode;
			error->message = Win32Error::DescribeCode(win32Code);
		};

		FILE* fp = nullptr;
		if (_wfopen_s(&fp, path.c_str(), L"wb") != 0 || fp == nullptr)
		{
			record(WriteStage::Open, ::GetLastError(), errno);
			return false;
		}

		if (buffer == nullptr || size == 0)
		{
			record(WriteStage::Arg, ERROR_INVALID_PARAMETER, EINVAL);
			fclose(fp);
			return false;
		}

		if (fwrite(buffer, size, 1, fp) != 1)
		{
			record(WriteStage::Write, ::GetLastError(), errno);
			fclose(fp);
			return false;
		}

		// 这一段以前被完全忽略：磁盘写满时数据其实已经丢了，函数却返回成功，
		// 外面看到的就是"解包说成功、文件却不对"。
		if (fflush(fp) != 0)
		{
			record(WriteStage::Flush, ::GetLastError(), errno);
			fclose(fp);
			return false;
		}

		if (fclose(fp) != 0)
		{
			record(WriteStage::Close, ::GetLastError(), errno);
			return false;
		}

		return true;
	}

	void Delete(const std::string& path)
	{
		remove(path.c_str());
	}

	void Delete(const std::wstring& path)
	{
		Delete(path, nullptr);
	}

	bool Delete(const std::wstring& path, Win32Error::Info* error)
	{
		if (_wremove(path.c_str()) == 0)
		{
			return true;
		}

		// 本来就不在，按成功处理：调用方多半是"先删旧的再写新的"
		if (errno == ENOENT)
		{
			return true;
		}

		if (error != nullptr)
		{
			*error = Win32Error::CaptureCrt();
		}
		return false;
	}
}
