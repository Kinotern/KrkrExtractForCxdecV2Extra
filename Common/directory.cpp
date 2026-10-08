#include <Windows.h>
#include "directory.h"
#include "path.h"

namespace Directory
{
	bool Exists(const std::string& dirPath)
	{
		DWORD fileAttr = GetFileAttributesA(dirPath.c_str());
		if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			return false;
		}
		return true;
	}

	bool Exists(const std::wstring& dirPath)
	{
		DWORD fileAttr = GetFileAttributesW(dirPath.c_str());
		if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			return false;
		}
		return true;
	}

	void Create(const std::string& dirPath)
	{
		if (dirPath.empty())
			return;

		if (!Directory::Exists(dirPath))
		{
			if (!CreateDirectoryA(dirPath.c_str(), NULL))
			{
				Directory::Create(Path::GetDirectoryName(dirPath));
				CreateDirectoryA(dirPath.c_str(), NULL);
			}
		}
	}

	void Create(const std::wstring& dirPath)
	{
		Create(dirPath, nullptr);
	}

	bool Create(const std::wstring& dirPath, Win32Error::Info* error)
	{
		if (dirPath.empty())
		{
			if (error != nullptr)
			{
				error->code = ERROR_INVALID_NAME;
				error->message = Win32Error::DescribeCode(ERROR_INVALID_NAME);
			}
			return false;
		}

		if (Directory::Exists(dirPath))
		{
			return true;
		}

		if (::CreateDirectoryW(dirPath.c_str(), NULL))
		{
			return true;
		}

		// 第一次失败多半是父目录还不存在：先递归建父目录，再重试一次。
		// 第一次的码先留着——重试的码往往只是 ERROR_ALREADY_EXISTS 之类，没有信息量。
		const Win32Error::Info first = Win32Error::Capture();

		const std::wstring parent = Path::GetDirectoryName(dirPath);
		if (!parent.empty() && parent != dirPath)
		{
			Win32Error::Info parentError;
			if (!Create(parent, &parentError))
			{
				// 父目录都建不成，那就是根因，直接报它
				if (error != nullptr)
				{
					*error = parentError;
				}
				return false;
			}
		}

		if (::CreateDirectoryW(dirPath.c_str(), NULL))
		{
			return true;
		}

		// 竞态：别的线程/进程刚刚建好了，也算成功
		if (Directory::Exists(dirPath))
		{
			return true;
		}

		if (error != nullptr)
		{
			*error = Win32Error::Capture();
			if (error->code == ERROR_ALREADY_EXISTS || error->code == ERROR_SUCCESS)
			{
				*error = first;
			}
		}
		return false;
	}
}
