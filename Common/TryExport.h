#pragma once

#include <windows.h>

#include <cstring>
#include <exception>
#include <string>

// DLL 导出边界的异常兜底。
//
// 让 C++ 异常穿出导出函数的后果是宿主进程直接消失：异常穿过 CreateThread 起的
// 线程 -> std::terminate -> abort() -> __fastfail，连错误框都来不及弹。
// 封包大目录时抛的那次 bad_alloc 就是这么把 Loader 闪退掉的。
//
// 所以每个导出体都套一层 Run()，把异常转成错误串按各模块自己的约定返回。
namespace ExportGuard
{
	// 用 &x[0] 而不是 x.data()：本仓库各工程的 C++ 标准不一致，
	// C++14 下 data() 返回的还是 const 指针，传给 Win32 输出参数会编译不过。
	// 两处调用点都已经把长度撑到 >0，取首元素是安全的。

	// UTF-8 -> ANSI(CP_ACP)。导出约定里 char* 出参就是 ANSI，
	// 异常消息得先转过去，否则宿主 MessageBoxA 出来是乱码。
	inline std::string AnsiFromUtf8(const std::string& utf8)
	{
		if (utf8.empty()) return std::string();

		const int w = ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
		if (w <= 0) return std::string();
		std::wstring wide(static_cast<size_t>(w), L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], w);

		const int a =
		    ::WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
		if (a <= 0) return std::string();
		std::string ansi(static_cast<size_t>(a), '\0');
		::WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, &ansi[0], a, nullptr, nullptr);
		if (!ansi.empty() && ansi.back() == '\0') ansi.pop_back();
		return ansi;
	}

	inline std::wstring WideFromUtf8(const std::string& utf8)
	{
		if (utf8.empty()) return std::wstring();

		const int w = ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
		if (w <= 0) return std::wstring();
		std::wstring wide(static_cast<size_t>(w), L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wide[0], w);
		if (!wide.empty() && wide.back() == L'\0') wide.pop_back();
		return wide;
	}

	// 写进定长的 ANSI 错误缓冲；越界一律截断，绝不写穿
	inline void WriteAnsi(const std::string& utf8, char* out, int outSize)
	{
		if (out == nullptr || outSize <= 0) return;
		out[0] = '\0';
		const std::string ansi = AnsiFromUtf8(utf8);
		if (ansi.empty()) return;
		::strncpy_s(out, static_cast<size_t>(outSize), ansi.c_str(),
		            static_cast<size_t>(outSize) - 1);
	}

	// 连错误消息都构造不出来时（往往就是内存不够了）也不能让它再抛一次
	template <typename ReportFn>
	void ReportFailure(const ReportFn& report, const char* what)
	{
		try
		{
			report(std::string("内部错误：") + (what != nullptr ? what : ""));
		}
		catch (...)
		{
		}
	}

	// report 收一条 UTF-8 消息，由调用方决定往哪写：ANSI 错误缓冲、MessageBoxW、
	// 或者模块内的静态错误串。body 返回 false 表示这次调用失败了（原因由 body 自己报）。
	template <typename ReportFn, typename BodyFn>
	bool Run(const ReportFn& report, const BodyFn& body)
	{
		try
		{
			return body();
		}
		catch (const std::exception& e)
		{
			ReportFailure(report, e.what());
			return false;
		}
		catch (...)
		{
			ReportFailure(report, "未知异常");
			return false;
		}
	}
}
