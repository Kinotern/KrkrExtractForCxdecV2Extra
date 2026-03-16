#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include "tp_stub.h"
#include "log.h"
#include "ExtractApi.h"

namespace Engine
{
    /// <summary>
    /// 文件表
    /// </summary>
    class FileEntry
    {
    public:
        /// <summary>
        /// 文件夹Hash
        /// </summary>
        unsigned __int8 DirectoryPathHash[8];
        /// <summary>
        /// 文件名Hash
        /// </summary>
        unsigned __int8 FileNameHash[32];
        /// <summary>
        /// 文件Key
        /// </summary>
        __int64 Key;
        /// <summary>
        /// 文件序号
        /// </summary>
        __int64 Ordinal;

        /// <summary>
        /// 获取合法性
        /// </summary>
        bool IsVaild() const
        {
            return this->Ordinal >= 0i64;
        }

        /// <summary>
        /// 获取加密模式
        /// </summary>
        unsigned __int32 GetEncryptMode() const
        {
            return ((this->Ordinal & 0x0000FFFF00000000i64) >> 32);
        }

        /// <summary>
        /// 获取封包的名字
        /// <para>最多8字节 4个字符 3个Unicode字符 + 0结束符</para>
        /// </summary>
        /// <param name="retValue">字符返回值指针</param>
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

		/// <summary>
		/// 设置资源输出路径
		/// </summary>
		/// <param name="directory">文件夹绝对路径</param>
		void SetOutputDirectory(const std::wstring& directory);

        /// <summary>
        /// 设置日志输出路径
        /// </summary>
        /// <param name="directory">文件夹绝对路径</param>
        void SetLoggerDirectory(const std::wstring& directory);

        /// <summary>
        /// 设置进度回调
        /// </summary>
        /// <param name="callback">回调函数</param>
        /// <param name="context">回调上下文</param>
        void SetProgressCallback(tExtractProgressCallback callback, void* context);

		/// <summary>
		/// 初始化 (特征码找接口)
		/// </summary>
		/// <param name="codeVa">代码起始地址</param>
		/// <param name="codeSize">代码大小</param>
		void Initialize(PVOID codeVa, DWORD codeSize);
		/// <summary>
		/// 检查是否已经初始化
		/// </summary>
		/// <returns>True已初始化 False未初始化</returns>
		bool IsInitialized();
		/// <summary>
		/// 使用默认输出目录解包
		/// </summary>
		/// <param name="packageFileName">封包名称</param>
		bool ExtractPackage(const std::wstring& packageFileName, unsigned int taskId = 0u);
        /// <summary>
        /// 使用指定输出目录解包
        /// </summary>
        /// <param name="packagePath">封包路径</param>
        /// <param name="outputDirectory">输出目录</param>
        /// <param name="taskId">任务编号</param>
        bool ExtractPackageTo(const std::wstring& packagePath, const std::wstring& outputDirectory, unsigned int taskId);

	private:
		/// <summary>
		/// 获取Hxv4文件表
		/// </summary>
		/// <param name="xp3PackagePath">封包绝对路径</param>
		/// <param name="retValue">文件表数组</param>
		void GetEntries(const tTJSString& xp3PackagePath, std::vector<FileEntry>& retValue);

        /// <summary>
        /// 创建资源流
        /// </summary>
        /// <param name="entry">文件表</param>
        /// <param name="packageName">封包名</param>
        /// <returns>IStream对象</returns>
        IStream* CreateStream(const FileEntry& entry, const tTJSString& packageStoragePath);

        /// <summary>
        /// 提取文件
        /// </summary>
        /// <param name="stream">流</param>
        /// <param name="extractPath">提取路径</param>
        /// <param name="relativePath">相对路径</param>
        /// <returns>True提取成功 False失败</returns>
        bool ExtractFile(IStream* stream, const std::wstring& extractPath, const std::wstring& relativePath);

        /// <summary>
        /// 尝试解密文本
        /// </summary>
        /// <param name="stream">资源流</param>
        /// <param name="output">输出缓冲区</param>
        /// <returns>True解密成功 False不是文本加密</returns>
        static bool TryDecryptText(IStream* stream, std::vector<uint8_t>& output);

        /// <summary>
        /// 解析封包为标准TVP存储路径
        /// </summary>
        /// <param name="packagePath">封包路径</param>
        /// <returns>标准存储路径</returns>
        static tTJSString ResolvePackageStoragePath(const std::wstring& packagePath);

        /// <summary>
        /// 写日志
        /// </summary>
        /// <param name="format">格式</param>
        void WriteLog(const wchar_t* format, ...);

        /// <summary>
        /// 通知进度
        /// </summary>
        void NotifyProgress(unsigned int taskId,
                            const std::wstring& packagePath,
                            unsigned int state,
                            unsigned int current,
                            unsigned int total,
                            const std::wstring& detail) const;
	};
}
