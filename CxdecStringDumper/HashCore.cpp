#include "HashCore.h"
#include "pe.h"
#include "file.h"
#include "directory.h"
#include "path.h"
#include "stringhelper.h"
#include "ExtendUtils.h"

#include <cstdio>

namespace
{
    bool IsFileEmptyOrMissing(const std::wstring& path)
    {
        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return true;
        }

        bool empty = true;
        if (_fseeki64(fp, 0, SEEK_END) == 0)
        {
            empty = _ftelli64(fp) <= 0;
        }

        fclose(fp);
        return empty;
    }

    void LoadUnicodeHashLines(const std::wstring& path, std::unordered_set<std::wstring>& lines)
    {
        lines.clear();

        FILE* fp = nullptr;
        if (_wfopen_s(&fp, path.c_str(), L"rb") != 0 || fp == nullptr)
        {
            return;
        }

        if (_fseeki64(fp, 0, SEEK_END) != 0)
        {
            fclose(fp);
            return;
        }

        const long long size = _ftelli64(fp);
        if (size <= 0 || (size % sizeof(wchar_t)) != 0)
        {
            fclose(fp);
            return;
        }

        if (_fseeki64(fp, 0, SEEK_SET) != 0)
        {
            fclose(fp);
            return;
        }

        std::wstring content;
        content.resize(static_cast<size_t>(size / sizeof(wchar_t)));
        if (fread(content.data(), sizeof(wchar_t), content.size(), fp) != content.size())
        {
            fclose(fp);
            return;
        }

        fclose(fp);

        if (!content.empty() && content[0] == 0xFEFF)
        {
            content.erase(content.begin());
        }

        size_t start = 0;
        while (start < content.size())
        {
            size_t end = content.find_first_of(L"\r\n", start);
            if (end == std::wstring::npos)
            {
                end = content.size();
            }

            if (end > start)
            {
                lines.insert(content.substr(start, end - start));
            }

            start = end;
            while (start < content.size() && (content[start] == L'\r' || content[start] == L'\n'))
            {
                ++start;
            }
        }
    }
}

namespace Engine
{
    //**********IStringHasher***********//
    tjs_int IStringHasher::GetSaltLength() const
    {
        return this->mSaltSize;
    }

    const tjs_uint8* IStringHasher::GetSaltBytes() const
    {
        return this->mSalt;
    }

    IStringHasher::VptrTable* IStringHasher::GetVptrTable()
    {
        return *(IStringHasher::VptrTable**)this;
    }

    void IStringHasher::SetVptrTable(const VptrTable* vt)
    {
        *(const IStringHasher::VptrTable**)this = vt;
    }
    //================================//


    //*****************Dumper******************//

    static HashCore* g_Instance = nullptr;      //单实例
    HashCore::tCreateCompoundStorageMedia g_CreateStorageMediaFunc = nullptr;     //TVPStorageMedia[Cxdec]接口

    const CompoundStorageMedia* g_StorageMedia = nullptr;                        //封包管理媒体
    const IStringHasher::VptrTable* g_PathNameHasherOriginalVtPtr = nullptr;     //文件夹路径Hash原虚表指针
    const IStringHasher::VptrTable* g_FileNameHasherOriginalVtPtr = nullptr;     //文件名Hash原虚表指针

    IStringHasher::VptrTable g_PathNameHasherHookVt;         //文件夹路径Hash Hook虚表
    IStringHasher::VptrTable g_FileNameHasherHookVt;         //文件名Hash Hook虚表

    tjs_int __fastcall HookPathNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed);
    tjs_int __fastcall HookFileNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed);

    //创建Media Hook
    tjs_error __cdecl HookCreateCompoundStorageMedia(CompoundStorageMedia** retTVPStorageMedia, tTJSVariant* tjsVarPrefix, int argc, void* argv)
    {
        tjs_error result = g_CreateStorageMediaFunc(retTVPStorageMedia, tjsVarPrefix, argc, argv);
        if (TJS_SUCCEEDED(result))
        {
            //Unhook
            HookUtils::InlineHook::UnHook(g_CreateStorageMediaFunc, HookCreateCompoundStorageMedia);

            //获取媒体对象
            CompoundStorageMedia* storageMedia = *retTVPStorageMedia;
            g_StorageMedia = storageMedia;

            //打印Hash参数
            {
                HashCore* dumper = g_Instance;
                Log::Logger& uniLogger = dumper->mUniversalLogger;
                
                uniLogger.WriteUnicode(L"Hash Seed:%s\r\n", storageMedia->HasherSeed.c_str());
                uniLogger.WriteUnicode(L"PathNameHasherSalt:%s\r\n", StringHelper::BytesToHexStringW(storageMedia->PathNameHasher->GetSaltBytes(), storageMedia->PathNameHasher->GetSaltLength()).c_str());
                uniLogger.WriteUnicode(L"FileNameHasherSalt:%s\r\n", StringHelper::BytesToHexStringW(storageMedia->FileNameHasher->GetSaltBytes(), storageMedia->FileNameHasher->GetSaltLength()).c_str());
            }

            //文件夹路径Hash虚表Hook
            {
                IStringHasher::VptrTable* pnHasherVt = storageMedia->PathNameHasher->GetVptrTable();
                g_PathNameHasherOriginalVtPtr = pnHasherVt;

                g_PathNameHasherHookVt = *pnHasherVt;
                g_PathNameHasherHookVt.Calculate = HookPathNameHasherCalcute;
                storageMedia->PathNameHasher->SetVptrTable(&g_PathNameHasherHookVt);
            }

            //文件名Hash虚表Hook
            {
                IStringHasher::VptrTable* fnHasherVt = storageMedia->FileNameHasher->GetVptrTable();
                g_FileNameHasherOriginalVtPtr = fnHasherVt;

                g_FileNameHasherHookVt = *fnHasherVt;
                g_FileNameHasherHookVt.Calculate = HookFileNameHasherCalcute;
                storageMedia->FileNameHasher->SetVptrTable(&g_FileNameHasherHookVt);
            }
        }
        return result;
    }

    //文件夹路径Hash计算Hook fastcall模拟thiscall
    tjs_int __fastcall HookPathNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed)
    {
        tjs_int len = g_PathNameHasherOriginalVtPtr->Calculate(thisObj, nullptr, hashValueRet, str, seed);

        const wchar_t* relativeDirPath = str->c_str();
        //空文件夹替换
        if (*relativeDirPath == L'\0')
        {
            relativeDirPath = L"%EmptyString%";
        }

        tTJSVariantOctet* hashValue = hashValueRet->AsOctetNoAddRef();
        //打印 String[Sign]Hash[NewLine]
        g_Instance->WriteDirectoryHash(relativeDirPath, StringHelper::BytesToHexStringW(hashValue->GetData(), hashValue->GetLength()));

        return len;
    }

    //文件名Hash计算Hook fastcall模拟thiscall
    tjs_int __fastcall HookFileNameHasherCalcute(IStringHasher* thisObj, void* unusedEdx, tTJSVariant* hashValueRet, const tTJSString* str, const tTJSString* seed)
    {
        tjs_int len = g_FileNameHasherOriginalVtPtr->Calculate(thisObj, nullptr, hashValueRet, str, seed);

        const wchar_t* fileName = str->c_str();

        tTJSVariantOctet* hashValue = hashValueRet->AsOctetNoAddRef();
        //打印 String[Sign]Hash[NewLine]
        g_Instance->WriteFileNameHash(fileName, StringHelper::BytesToHexStringW(hashValue->GetData(), hashValue->GetLength()));

        return len;
    }

    //================================//


    //**********HashCore***********//
    HashCore::HashCore()
    {
        InitializeCriticalSection(&this->mHashLineLock);
    }

    HashCore::~HashCore()
    {
        DeleteCriticalSection(&this->mHashLineLock);
    }

    void HashCore::SetOutputDirectory(const std::wstring& directory)
    {
        std::wstring dumpOutDirectory = Path::Combine(directory, HashCore::FolderName);
        this->mDumperDirectoryPath = dumpOutDirectory;

        //创建输出目录
        Directory::Create(dumpOutDirectory);

        //日志初始化。Hash日志作为长期映射库追加写入，不再删除旧记录。
        std::wstring directoryHashLogPath = Path::Combine(dumpOutDirectory, HashCore::DirectoryHashFileName);
        std::wstring fileNameHashLogPath = Path::Combine(dumpOutDirectory, HashCore::FileNameHashFileName);
        std::wstring universalLogPath = Path::Combine(dumpOutDirectory, HashCore::UniversalFileName);

        this->mDirectoryHashLogger.Close();
        this->mFileNameHashLogger.Close();
        this->mUniversalLogger.Close();

        const bool writeDirectoryBom = IsFileEmptyOrMissing(directoryHashLogPath);
        const bool writeFileNameBom = IsFileEmptyOrMissing(fileNameHashLogPath);

        LoadUnicodeHashLines(directoryHashLogPath, this->mKnownDirectoryHashLines);
        LoadUnicodeHashLines(fileNameHashLogPath, this->mKnownFileNameHashLines);

        File::Delete(universalLogPath);
        this->mDirectoryHashLogger.Open(directoryHashLogPath.c_str());
        this->mFileNameHashLogger.Open(fileNameHashLogPath.c_str());
        this->mUniversalLogger.Open(universalLogPath.c_str());

        //写UTF-16LE bom头。追加已有Hash日志时不能在中间再次写BOM。
        {
            WORD bom = 0xFEFF;
            if (writeDirectoryBom)
            {
                this->mDirectoryHashLogger.WriteData(&bom, sizeof(bom));
            }

            if (writeFileNameBom)
            {
                this->mFileNameHashLogger.WriteData(&bom, sizeof(bom));
            }

            this->mUniversalLogger.WriteData(&bom, sizeof(bom));
        }
    }

    void HashCore::WriteDirectoryHash(const std::wstring& relativeDirPath, const std::wstring& hash)
    {
        std::wstring line = relativeDirPath + HashCore::Split + hash;

        EnterCriticalSection(&this->mHashLineLock);
        if (this->mKnownDirectoryHashLines.insert(line).second)
        {
            this->mDirectoryHashLogger.WriteUnicode(L"%s\r\n", line.c_str());
        }
        LeaveCriticalSection(&this->mHashLineLock);
    }

    void HashCore::WriteFileNameHash(const std::wstring& fileName, const std::wstring& hash)
    {
        std::wstring line = fileName + HashCore::Split + hash;

        EnterCriticalSection(&this->mHashLineLock);
        if (this->mKnownFileNameHashLines.insert(line).second)
        {
            this->mFileNameHashLogger.WriteUnicode(L"%s\r\n", line.c_str());
        }
        LeaveCriticalSection(&this->mHashLineLock);
    }

    void HashCore::Initialize(PVOID codeVa, DWORD codeSize)
    {
        PVOID createMedia = PE::SearchPattern(codeVa, codeSize, HashCore::CreateCompoundStorageMediaSignature, sizeof(HashCore::CreateCompoundStorageMediaSignature) - 1);
        if (createMedia)
        {
            g_CreateStorageMediaFunc = (tCreateCompoundStorageMedia)createMedia;

            //Hook创建媒体接口
            HookUtils::InlineHook::Hook(g_CreateStorageMediaFunc, HookCreateCompoundStorageMedia);
        }
    }

    bool HashCore::IsInitialized()
    {
        return g_CreateStorageMediaFunc != nullptr;
    }

    //************=====Static=====************//

    HashCore* HashCore::GetInstance()
    {
        if (g_Instance == nullptr)
        {
            g_Instance = new HashCore();
        }
        return g_Instance;
    }

    void HashCore::Release()
    {
        if (g_Instance)
        {
            delete g_Instance;
            g_Instance = nullptr;
        }
    }
    //================================//
}
