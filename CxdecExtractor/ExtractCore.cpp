#include "ExtractCore.h"
#include "pe.h"
#include "file.h"
#include "directory.h"
#include "path.h"
#include "stringhelper.h"
#include "ExtendUtils.h"

#include <cstdarg>

namespace
{
    bool IsAbsolutePath(const std::wstring& path)
    {
        if (path.length() >= 2 && path[1] == L':')
        {
            return true;
        }

        return path.length() >= 2 && path[0] == L'\\' && path[1] == L'\\';
    }

    bool IsKnownPlaceholderEntry(const Engine::FileEntry& entry)
    {
        static constexpr unsigned __int8 PlaceholderDirectoryHash[8] =
        {
            0x94, 0xD4, 0xA9, 0x7C, 0x61, 0x49, 0x86, 0x21
        };
        static constexpr unsigned __int8 PlaceholderFileHash[32] =
        {
            0x2E, 0xA4, 0xAA, 0xEC, 0x6A, 0x09, 0xF9, 0xD1,
            0x7E, 0x2A, 0x5A, 0x7A, 0xC4, 0x22, 0xFB, 0x64,
            0xB6, 0xA4, 0x21, 0x95, 0xC5, 0x5C, 0xF6, 0x77,
            0x2F, 0xB3, 0x0C, 0x0F, 0xA0, 0x12, 0x0C, 0x8D
        };

        return memcmp(entry.DirectoryPathHash, PlaceholderDirectoryHash, sizeof(PlaceholderDirectoryHash)) == 0
            && memcmp(entry.FileNameHash, PlaceholderFileHash, sizeof(PlaceholderFileHash)) == 0;
    }
}

namespace Engine
{
	//**********ExtractCore***********//
	ExtractCore::ExtractCore()
        : mCreateStreamFunc(nullptr),
          mCreateIndexFunc(nullptr),
          mProgressCallback(nullptr),
          mProgressContext(nullptr)
	{
	}

	ExtractCore::~ExtractCore()
	{
	}

	void ExtractCore::SetOutputDirectory(const std::wstring& directory)
	{
		this->mExtractDirectoryPath = Path::Combine(directory, ExtractCore::ExtractorOutFolderName);
	}

	void ExtractCore::SetLoggerDirectory(const std::wstring& directory)
	{
		std::wstring path = Path::Combine(directory, ExtractCore::ExtractorLogFileName);

		File::Delete(path);
		this->mLogger.Open(path.c_str());
	}

    void ExtractCore::SetProgressCallback(tExtractProgressCallback callback, void* context)
    {
        this->mProgressCallback = callback;
        this->mProgressContext = context;
    }

	void ExtractCore::Initialize(PVOID codeVa, DWORD codeSize)
	{
		PVOID createStream = PE::SearchPattern(codeVa, codeSize, ExtractCore::CreateStreamSignature, sizeof(ExtractCore::CreateStreamSignature) - 1u);
		PVOID createIndex = PE::SearchPattern(codeVa, codeSize, ExtractCore::CreateIndexSignature, sizeof(ExtractCore::CreateIndexSignature) - 1u);

		if (createStream && createIndex)
		{
			this->mCreateStreamFunc = (tCreateStream)createStream;
			this->mCreateIndexFunc = (tCreateIndex)createIndex;
		}
	}

	bool ExtractCore::IsInitialized()
	{
		return this->mCreateStreamFunc && this->mCreateIndexFunc;
	}

    bool ExtractCore::ExtractPackage(const std::wstring& packageFileName, unsigned int taskId)
    {
        return this->ExtractPackageTo(packageFileName, this->mExtractDirectoryPath, taskId);
    }

    bool ExtractCore::ExtractPackageTo(const std::wstring& packagePath, const std::wstring& outputDirectory, unsigned int taskId)
	{
        std::wstring packageDisplayName = Path::GetFileName(packagePath);
        if (packageDisplayName.empty())
        {
            packageDisplayName = packagePath;
        }

        this->NotifyProgress(taskId, packagePath, ExtractTaskPreparing, 0u, 0u, L"准备解包");

		if (!this->IsInitialized())
		{
            const std::wstring detail = L"未初始化CxdecV2接口，请检查是否为无DRM的Wamsoft Hxv4加密游戏";
            this->WriteLog(L"Extract Failed: %s | %s", packageDisplayName.c_str(), detail.c_str());
            this->NotifyProgress(taskId, packagePath, ExtractTaskFailed, 0u, 0u, detail);
			return false;
		}

        tTJSString tjsXp3PackagePath = ExtractCore::ResolvePackageStoragePath(packagePath);
        if (tjsXp3PackagePath.IsEmpty())
        {
            const std::wstring detail = L"封包路径无效";
            this->WriteLog(L"Extract Failed: %s | %s", packageDisplayName.c_str(), detail.c_str());
            this->NotifyProgress(taskId, packagePath, ExtractTaskFailed, 0u, 0u, detail);
            return false;
        }

		std::vector<FileEntry> entries = std::vector<FileEntry>();
		this->GetEntries(tjsXp3PackagePath, entries);
		if (entries.empty())
		{
            const std::wstring detail = L"请选择正确的XP3封包";
            this->WriteLog(L"Extract Failed: %s | %s", packageDisplayName.c_str(), detail.c_str());
            this->NotifyProgress(taskId, packagePath, ExtractTaskFailed, 0u, 0u, detail);
            return false;
		}

        const std::wstring effectiveOutputDirectory = outputDirectory.empty() ? this->mExtractDirectoryPath : outputDirectory;
        Directory::Create(effectiveOutputDirectory);

        std::wstring packageName = Path::GetFileNameWithoutExtension(packageDisplayName);
        std::wstring extractOutput = Path::Combine(effectiveOutputDirectory, packageName);
        std::wstring fileTableOutput = extractOutput + L".alst";

        this->NotifyProgress(taskId, packagePath, ExtractTaskIndexLoaded, 0u, (unsigned int)entries.size(), L"索引读取完成");
        this->WriteLog(L"Extract Start: %s -> %s", packageDisplayName.c_str(), extractOutput.c_str());

        File::Delete(fileTableOutput);
        Log::Logger fileTable = Log::Logger(fileTableOutput.c_str());

        WORD bom = 0xFEFF;
        fileTable.WriteData(&bom, sizeof(bom));

        bool allSucceeded = true;
        unsigned int skippedPlaceholderCount = 0u;
        const unsigned int totalCount = (unsigned int)entries.size();

        for (unsigned int index = 0u; index < totalCount; ++index)
        {
            FileEntry& entry = entries[index];

            std::wstring dirHash = StringHelper::BytesToHexStringW(entry.DirectoryPathHash, sizeof(entry.DirectoryPathHash));
            std::wstring fileNameHash = StringHelper::BytesToHexStringW(entry.FileNameHash, sizeof(entry.FileNameHash));
            std::wstring relativePath = packageName + L"\\" + dirHash + L"\\" + fileNameHash;
            std::wstring arcOutputPath = Path::Combine(effectiveOutputDirectory, relativePath);

            this->NotifyProgress(taskId, packagePath, ExtractTaskExtracting, index, totalCount, relativePath);

            bool currentSucceeded = false;
            if (IStream* stream = this->CreateStream(entry, tjsXp3PackagePath))
            {
                fileTable.WriteUnicode(L"%s%s%s%s%s%s%s\r\n",
                                       dirHash.c_str(),
                                       ExtractCore::Split,
                                       dirHash.c_str(),
                                       ExtractCore::Split,
                                       fileNameHash.c_str(),
                                       ExtractCore::Split,
                                       fileNameHash.c_str());

                currentSucceeded = this->ExtractFile(stream, arcOutputPath, relativePath);
                stream->Release();
            }
            else
            {
                currentSucceeded = false;
                this->WriteLog(L"File Not Exist: %s", relativePath.c_str());
            }

            if (!currentSucceeded && IsKnownPlaceholderEntry(entry))
            {
                currentSucceeded = true;
                ++skippedPlaceholderCount;
                this->WriteLog(L"Skip Placeholder Entry: %s", relativePath.c_str());
            }

            if (!currentSucceeded)
            {
                allSucceeded = false;
            }

            this->NotifyProgress(taskId,
                                 packagePath,
                                 ExtractTaskExtracting,
                                 index + 1u,
                                 totalCount,
                                 currentSucceeded ? relativePath : (relativePath + L" | 失败"));
        }

        fileTable.Close();

        if (allSucceeded)
        {
            if (skippedPlaceholderCount > 0u)
            {
                this->WriteLog(L"Skipped Placeholder Entries: %s | %u",
                               packageDisplayName.c_str(),
                               skippedPlaceholderCount);
            }

            this->WriteLog(L"Extract Completed: %s", packageDisplayName.c_str());
            this->NotifyProgress(taskId, packagePath, ExtractTaskCompleted, totalCount, totalCount, L"解包完成");
        }
        else
        {
            this->WriteLog(L"Extract Completed With Errors: %s", packageDisplayName.c_str());
            this->NotifyProgress(taskId, packagePath, ExtractTaskFailed, totalCount, totalCount, L"解包完成，但存在失败条目");
        }

        return allSucceeded;
	}

	void ExtractCore::GetEntries(const tTJSString& xp3PackagePath, std::vector<FileEntry>& retValue)
	{
		retValue.clear();

		tTJSVariant tjsEntries;
		tTJSVariant tjsPackagePath(xp3PackagePath);
		this->mCreateIndexFunc(&tjsEntries, &tjsPackagePath);

		if (tjsEntries.Type() != tvtObject)
        {
            return;
        }

		tTJSVariantClosure& dirEntriesObj = tjsEntries.AsObjectClosureNoAddRef();

		tTJSVariant tjsCount;
		tjs_int count = 0;
		dirEntriesObj.PropGet(TJS_MEMBERMUSTEXIST, L"count", NULL, &tjsCount, nullptr);
		count = (tjs_int)tjsCount.AsInteger();

		constexpr tjs_int DirectoryItemSize = 2;
		tjs_int dirCount = count / DirectoryItemSize;

		for (tjs_int di = 0; di < dirCount; ++di)
		{
			tTJSVariant tjsDirHash;
			tTJSVariant tjsFileEntries;
			dirEntriesObj.PropGetByNum(TJS_CII_GET, di * DirectoryItemSize + 0, &tjsDirHash, nullptr);
			dirEntriesObj.PropGetByNum(TJS_CII_GET, di * DirectoryItemSize + 1, &tjsFileEntries, nullptr);

			tTJSVariantOctet* dirHash = tjsDirHash.AsOctetNoAddRef();
            if (dirHash == nullptr || dirHash->GetLength() != 8u)
            {
                this->WriteLog(L"Skip Entry: invalid directory hash length");
                continue;
            }

			tTJSVariantClosure& fileEntries = tjsFileEntries.AsObjectClosureNoAddRef();
			tjsCount.Clear();
			fileEntries.PropGet(TJS_MEMBERMUSTEXIST, L"count", NULL, &tjsCount, nullptr);
			count = (tjs_int)tjsCount.AsInteger();

			constexpr tjs_int FileItemSize = 2;
			tjs_int fileCount = count / FileItemSize;

			for (tjs_int fi = 0; fi < fileCount; ++fi)
			{
				tTJSVariant tjsFileNameHash;
				tTJSVariant tjsFileInfo;
				fileEntries.PropGetByNum(TJS_CII_GET, fi * FileItemSize + 0, &tjsFileNameHash, nullptr);
				fileEntries.PropGetByNum(TJS_CII_GET, fi * FileItemSize + 1, &tjsFileInfo, nullptr);

				tTJSVariantOctet* fileNameHash = tjsFileNameHash.AsOctetNoAddRef();
                if (fileNameHash == nullptr || fileNameHash->GetLength() != 32u)
                {
                    this->WriteLog(L"Skip Entry: invalid file hash length");
                    continue;
                }

				tTJSVariantClosure& fileInfo = tjsFileInfo.AsObjectClosureNoAddRef();

				__int64 ordinal = 0i64;
				__int64 key = 0i64;

				tTJSVariant tjsValue;
				fileInfo.PropGetByNum(TJS_CII_GET, 0, &tjsValue, nullptr);
				ordinal = tjsValue.AsInteger();

				tjsValue.Clear();
				fileInfo.PropGetByNum(TJS_CII_GET, 1, &tjsValue, nullptr);
				key = tjsValue.AsInteger();

				FileEntry entry{ };
				memcpy(entry.DirectoryPathHash, dirHash->GetData(), sizeof(entry.DirectoryPathHash));
				memcpy(entry.FileNameHash, fileNameHash->GetData(), sizeof(entry.FileNameHash));
				entry.Key = key;
				entry.Ordinal = ordinal;

                if (!entry.IsVaild())
                {
                    this->WriteLog(L"Skip Entry: invalid ordinal");
                    continue;
                }

				retValue.push_back(entry);
			}
		}
	}

	IStream* ExtractCore::CreateStream(const FileEntry& entry, const tTJSString& packageStoragePath)
	{
		tjs_char fakeName[4]{ };
		entry.GetFakeName(fakeName);

		tTJSString tjsArcPath = packageStoragePath;
		tjsArcPath += L">";
		tjsArcPath += fakeName;
		tjsArcPath = TVPNormalizeStorageName(tjsArcPath);

		return this->mCreateStreamFunc(&tjsArcPath, entry.Key, entry.GetEncryptMode());
	}

	bool ExtractCore::ExtractFile(IStream* stream, const std::wstring& extractPath, const std::wstring& relativePath)
	{
		unsigned long long size = StreamUtils::IStreamEx::Length(stream);
		if (size == 0)
		{
            this->WriteLog(L"Empty File: %s", relativePath.c_str());
            return false;
		}

        std::wstring outputDir = Path::GetDirectoryName(extractPath);
        if (!outputDir.empty())
        {
            Directory::Create(outputDir.c_str());
        }

		std::vector<uint8_t> buffer;
		bool success = false;

		if (ExtractCore::TryDecryptText(stream, buffer))
		{
			success = true;
		}
		else
		{
			buffer.resize((size_t)size);

			stream->Seek(LARGE_INTEGER{ }, STREAM_SEEK_SET, nullptr);
					if (StreamUtils::IStreamEx::Read(stream, buffer.data(), (ULONG)size) == (ULONG)size)
			{
				success = true;
			}
		}

		if (success && !buffer.empty())
		{
			if (File::WriteAllBytes(extractPath, buffer.data(), buffer.size()))
			{
                this->WriteLog(L"Extract Successed: %s", relativePath.c_str());
                stream->Seek(LARGE_INTEGER{ }, STREAM_SEEK_SET, nullptr);
                return true;
			}

            this->WriteLog(L"Write Error: %s", relativePath.c_str());
		}
		else
		{
            this->WriteLog(L"Invaild File: %s", relativePath.c_str());
		}

		stream->Seek(LARGE_INTEGER{ }, STREAM_SEEK_SET, nullptr);
        return false;
	}

	bool ExtractCore::TryDecryptText(IStream* stream, std::vector<uint8_t>& output)
	{
		uint8_t mark[2]{ };
		StreamUtils::IStreamEx::Read(stream, mark, 2ul);

		if (mark[0] == 0xfe && mark[1] == 0xfe)
		{
			uint8_t mode;
			StreamUtils::IStreamEx::Read(stream, &mode, 1ul);

			if (mode != 0 && mode != 1 && mode != 2)
			{
				return false;
			}

			ZeroMemory(mark, sizeof(mark));
			StreamUtils::IStreamEx::Read(stream, mark, 2ul);

			if (mark[0] != 0xff || mark[1] != 0xfe)
			{
				return false;
			}

			if (mode == 2)
			{
				long long compressed = 0;
				long long uncompressed = 0;
				StreamUtils::IStreamEx::Read(stream, &compressed, sizeof(long long));
				StreamUtils::IStreamEx::Read(stream, &uncompressed, sizeof(long long));

				if (compressed <= 0 || compressed >= INT_MAX || uncompressed <= 0 || uncompressed >= INT_MAX)
				{
					return false;
				}

				std::vector<uint8_t> data = std::vector<uint8_t>((size_t)compressed);

				if (StreamUtils::IStreamEx::Read(stream, data.data(), (ULONG)compressed) != compressed)
				{
					return false;
				}

				std::vector<uint8_t> buffer = std::vector<uint8_t>((size_t)uncompressed + 2u);

				buffer[0] = mark[0];
				buffer[1] = mark[1];

				uint8_t* dest = buffer.data() + 2;
				unsigned long destLen = (unsigned long)uncompressed;

				if (ZLIB_uncompress(dest, &destLen, data.data(), (unsigned long)compressed) || destLen != (unsigned long)uncompressed)
				{
					return false;
				}

				output = std::move(buffer);
				return true;
			}

			long long startpos = StreamUtils::IStreamEx::Position(stream);
			long long endpos = StreamUtils::IStreamEx::Length(stream);

			StreamUtils::IStreamEx::Seek(stream, startpos, STREAM_SEEK_SET);

			long long size = endpos - startpos;
			if (size <= 0 || size >= INT_MAX)
			{
				return false;
			}

			size_t count = (size_t)(size / sizeof(wchar_t));
			if (count == 0)
			{
				return false;
			}

			std::vector<wchar_t> buffer(count);
			StreamUtils::IStreamEx::Read(stream, buffer.data(), (ULONG)size);

			if (mode == 0)
			{
				for (size_t i = 0; i < count; i++)
				{
					wchar_t ch = buffer[i];
					if (ch >= 0x20)
                    {
                        buffer[i] = ch ^ (((ch & 0xfe) << 8) ^ 1);
                    }
				}
			}
			else if (mode == 1)
			{
				for (size_t i = 0; i < count; i++)
				{
					wchar_t ch = buffer[i];
					ch = ((ch & 0xaaaaaaaa) >> 1) | ((ch & 0x55555555) << 1);
					buffer[i] = ch;
				}
			}

			size_t sizeToCopy = count * sizeof(wchar_t);
			output.resize(sizeToCopy + 2u);
			output[0] = mark[0];
			output[1] = mark[1];
			memcpy(output.data() + 2, buffer.data(), sizeToCopy);
			return true;
		}
		return false;
	}

    tTJSString ExtractCore::ResolvePackageStoragePath(const std::wstring& packagePath)
    {
        if (packagePath.empty())
        {
            return tTJSString();
        }

        if (!IsAbsolutePath(packagePath))
        {
            tTJSString relativePath = TVPGetAppPath();
            relativePath += packagePath.c_str();
            return TVPNormalizeStorageName(relativePath);
        }

        std::wstring fullPath = Path::GetFullPath(packagePath);
        if (fullPath.empty())
        {
            fullPath = packagePath;
        }
        return TVPNormalizeStorageName(fullPath.c_str());
    }

    void ExtractCore::WriteLog(const wchar_t* format, ...)
    {
        va_list ap;
        va_start(ap, format);
        std::wstring message = StringHelper::VFormat(format, ap);
        va_end(ap);
        this->mLogger.WriteLine(L"%s", message.c_str());
    }

    void ExtractCore::NotifyProgress(unsigned int taskId,
                                     const std::wstring& packagePath,
                                     unsigned int state,
                                     unsigned int current,
                                     unsigned int total,
                                     const std::wstring& detail) const
    {
        if (this->mProgressCallback)
        {
            this->mProgressCallback(taskId,
                                    packagePath.c_str(),
                                    state,
                                    current,
                                    total,
                                    detail.c_str(),
                                    this->mProgressContext);
        }
    }
	//================================//
}
