#pragma once

#include <Windows.h>

#include <array>
#include <string>

#include "tp_stub.h"
#include "log.h"

namespace Engine
{
    class KeyCore
    {
    public:
        enum class ProbeType : unsigned int
        {
            Hx = 0u,
            Cx = 1u,
            Verify = 2u,
            Count = 3u
        };

        using tRawProbeProc = void(*)();

        struct ProbeRegisterFrame
        {
            DWORD EFlags;
            DWORD Edi;
            DWORD Esi;
            DWORD Ebp;
            DWORD Esp;
            DWORD Ebx;
            DWORD Edx;
            DWORD Ecx;
            DWORD Eax;
        };

        struct Probe
        {
            ProbeType Type;
            BYTE* Address;
            tRawProbeProc OriginalProc;
            tRawProbeProc DetourProc;
            bool Hooked;
            bool Triggered;
        };

    private:
        static constexpr const wchar_t FolderName[] = L"ExtractKey_Output";
        static constexpr const wchar_t LogFileName[] = L"KeyInfo.log";
        static constexpr const wchar_t JsonFileName[] = L"KeyInfo.json";
        static constexpr const wchar_t TextFileName[] = L"key_output.txt";
        static constexpr const wchar_t ControlBlockFileName[] = L"control_block.bin";

        static constexpr const char HxPointSignature[] = "\x8B\x45\x14\x53\x56\x8B\x75\x08\x57\x50";
        static constexpr const char CxPointSignature[] = "\x89\x45\xFC\x80\x7D\x10\x00";
        static constexpr const char VerifyPointSignature[] = "\xFF\x75\x24\x8D\x45\x8C\x53\xFF\x75\x1C\x57\x50\x8D\x45\xEC\x50";

        std::wstring mOutputDirectoryPath;
        std::wstring mLogPath;
        std::wstring mJsonPath;
        std::wstring mTextPath;
        std::wstring mControlBlockPath;
        std::wstring mTargetModulePath;

        HMODULE mTargetModule;
        Log::Logger mLogger;
        std::array<Probe, static_cast<size_t>(ProbeType::Count)> mProbes;

        bool mScanCompleted;
        bool mCompletionNotified;
        bool mHasHxData;
        bool mHasCxData;
        bool mHasVerifyData;

        std::array<unsigned __int8, 32> mHxKey;
        std::array<unsigned __int8, 16> mHxNonce;
        std::array<unsigned __int8, 8> mCxFilterKey;
        unsigned __int32 mCxMask;
        unsigned __int32 mCxOffset;
        unsigned __int8 mCxRandType;
        std::array<unsigned __int8, 0x1000> mControlBlock;
        std::array<unsigned __int8, 0x11> mCxOrder;
        std::array<int, 3> mGarbroPrologOrder;
        std::array<int, 6> mGarbroOddBranchOrder;
        std::array<int, 8> mGarbroEvenBranchOrder;
        std::array<unsigned __int8, 32> mVerifyBytes;

    public:
        KeyCore();
        KeyCore(const KeyCore&) = delete;
        KeyCore(KeyCore&&) = delete;
        KeyCore& operator=(const KeyCore&) = delete;
        KeyCore& operator=(KeyCore&&) = delete;
        ~KeyCore();

        void SetOutputDirectory(const std::wstring& directory);
        void Initialize(HMODULE targetModule, PVOID codeVa, DWORD codeSize);
        bool IsInitialized() const;
        void OnProbeHit(ProbeType type, const ProbeRegisterFrame* frame);

    private:
        bool InstallProbe(ProbeType type, PVOID address);
        void RestoreProbe(Probe& probe);
        bool CaptureHx(const ProbeRegisterFrame* frame);
        bool CaptureCx(const ProbeRegisterFrame* frame);
        bool CaptureVerify(const ProbeRegisterFrame* frame);
        void UpdateGarbroOrders();
        unsigned int GetCaptureProgressPercent() const;
        void NotifyLoaderProgress() const;
        void NotifyLoaderCompleted() const;
        void WriteSnapshot();
        void WriteTextSnapshot();
        void MaybeNotifyCompletion();
    };
}
