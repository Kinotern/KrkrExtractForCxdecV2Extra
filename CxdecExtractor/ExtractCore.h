#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include "tp_stub.h"
#include "log.h"
#include "ExtractApi.h"

namespace Engine
{
    // Hxv4 索引中的单个文件条目。 这里保留的是哈希路径和序号信息，真实文件名并不在纯哈希封包中。
    class FileEntry
    {
    public:
        // 文件夹Hash
        unsigned __int8 DirectoryPathHash[8];
        // 文件名Hash
        unsigned __int8 FileNameHash[32];
        // 文件Key
        __int64 Key;
        // 文件序号
        __int64 Ordinal;

        // 获取合法性
        bool IsVaild() const
        {
            return this->Ordinal >= 0i64;
        }

        // 获取加密模式
        unsigned __int32 GetEncryptMode() const
        {
            return ((this->Ordinal & 0x0000FFFF00000000i64) >> 32);
        }

        // 将 ordinal 的低位编码成 TVP 可接受的伪文件名。 封包内部是按 ordinal 取流，因此这里不需要真实文件名。 <para>最多8字节 4个字符 3个Unicode字符 + 0结束符</para>
        // retValue：字符返回值指针
        void GetFakeName(wchar_t* retValue) const
        {
            wchar_t* fakeName = retValue;

            *(__int64*)fakeName = 0i64;      //清空8字节

            unsigned __int32 ordinalLow32 = this->Ordinal & 0x00000000FFFFFFFFi64;

            int charIndex = 0;
            do
            {
                unsigned __int32 temp = ordinalLow32;
                temp &= 0x00003FFFu;
                temp += 0x00005000u;

                fakeName[charIndex] = temp & 0x0000FFFFu;
                ++charIndex;

                ordinalLow32 >>= 0x0E;
            } while (ordinalLow32 != 0u);
        }
    };

	class ExtractCore
	{
    private:
        static constexpr const wchar_t ExtractorOutFolderName[] = L"Extractor_Output";    //提取器输出文件夹名
        static constexpr const wchar_t ExtractorLogFileName[] = L"Extractor.log";        //提取器日志文件名

	private:
        // 运行时通过签名扫描宿主插件，定位实际负责建索引和开流的内部函数。
		static constexpr const char CreateStreamSignature[] = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x51\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x32\x68\xB0\x30\x00\x00";
        static constexpr const char CreateIndexSignature[] = "\x55\x8B\xEC\x6A\xFF\x68\x2A\x2A\x2A\x2A\x64\xA1\x00\x00\x00\x00\x50\x83\xEC\x14\x57\xA1\x2A\x2A\x2A\x2A\x33\xC5\x50\x8D\x45\xF4\x64\xA3\x00\x00\x00\x00\x83\x7D\x08\x00\x0F\x84\x2A\x2A\x00\x00\xA1\x2A\x2A\x2A\x2A\x85\xC0\x75\x12\x68\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x83\xC4\x04\xA3\x2A\x2A\x2A\x2A\xFF\x75\x0C\x8D\x4D\xF0\x51\xFF\xD0\xA1\x2A\x2A\x2A\x2A\xC7\x45\xFC\x00\x00\x00\x00\x85\xC0";
        static constexpr const wchar_t Split[] = L"##YSig##";           //格式分割字符串

		using tCreateStream = IStream* (__cdecl*)(const tTJSString* fakeName, tjs_int64 key, tjs_uint32 encryptMode);
		using tCreateIndex = tjs_error (__cdecl*)(tTJSVariant* retValue, const tTJSVariant* tjsXP3Name);

		tCreateStream mCreateStreamFunc;		//CxCreateStream打开文件流接口
		tCreateIndex mCreateIndexFunc;			//CxCreateIndex获取文件表接口

		std::wstring mExtractDirectoryPath;		//默认解包输出文件夹
        Log::Logger mLogger;                    //解包日志
        tExtractProgressCallback mProgressCallback; //进度回调
        void* mProgressContext;                //进度回调上下文

	public:
		ExtractCore();
		ExtractCore(const ExtractCore&) = delete;
		ExtractCore(ExtractCore&&) = delete;
        ExtractCore& operator=(const ExtractCore&) = delete;
        ExtractCore& operator=(ExtractCore&&) = delete;
        ~ExtractCore();

		// 设置资源输出路径
		// directory：文件夹绝对路径
		void SetOutputDirectory(const std::wstring& directory);

        // 设置日志输出路径
        // directory：文件夹绝对路径
        void SetLoggerDirectory(const std::wstring& directory);

        // 设置进度回调
        // callback：回调函数；context：回调上下文
        void SetProgressCallback(tExtractProgressCallback callback, void* context);

		// 初始化 (特征码找接口)
		// codeVa：代码起始地址；codeSize：代码大小
		void Initialize(PVOID codeVa, DWORD codeSize);
		// 检查是否已经初始化
		// 返回 True已初始化 False未初始化
		bool IsInitialized();
		// 使用默认输出目录解包
		// packageFileName：封包名称
		bool ExtractPackage(const std::wstring& packageFileName, unsigned int taskId = 0u);
        // 使用指定输出目录解包
        // packagePath：封包路径；outputDirectory：输出目录；taskId：任务编号
        bool ExtractPackageTo(const std::wstring& packagePath, const std::wstring& outputDirectory, unsigned int taskId);

	private:
		// 获取Hxv4文件表
		// xp3PackagePath：封包绝对路径；retValue：文件表数组
		void GetEntries(const tTJSString& xp3PackagePath, std::vector<FileEntry>& retValue);

        // 创建资源流
        // entry：文件表；packageName：封包名；返回 IStream对象
        IStream* CreateStream(const FileEntry& entry, const tTJSString& packageStoragePath);

        // 提取文件
        // stream：流；extractPath：提取路径；relativePath：相对路径；返回 True提取成功 False失败
        bool ExtractFile(IStream* stream, const std::wstring& extractPath, const std::wstring& relativePath);

        // 尝试解密文本
        // stream：资源流；output：输出缓冲区；返回 True解密成功 False不是文本加密
        static bool TryDecryptText(IStream* stream, std::vector<uint8_t>& output);

        // 解析封包为标准TVP存储路径
        // packagePath：封包路径；返回 标准存储路径
        static tTJSString ResolvePackageStoragePath(const std::wstring& packagePath);

        // 写日志
        // format：格式
        void WriteLog(const wchar_t* format, ...);

        // 通知进度
        void NotifyProgress(unsigned int taskId,
                            const std::wstring& packagePath,
                            unsigned int state,
                            unsigned int current,
                            unsigned int total,
                            const std::wstring& detail) const;
	};
}
