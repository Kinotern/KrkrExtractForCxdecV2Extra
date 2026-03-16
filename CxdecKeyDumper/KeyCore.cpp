#include "KeyCore.h"

#include "detours.h"
#include "directory.h"
#include "encoding.h"
#include "file.h"
#include "loaderipc.h"
#include "path.h"
#include "pe.h"
#include "stringhelper.h"
#include "util.h"

#include <cstdlib>
#include <cstring>
#include <string>

extern "C" void __stdcall ProbeEnterDispatcher(unsigned int probeTypeValue, const Engine::KeyCore::ProbeRegisterFrame* frame);
extern "C" void HxProbeDetour();
extern "C" void CxProbeDetour();
extern "C" void VerifyProbeDetour();

namespace
{
    Engine::KeyCore* g_KeyCoreInstance = nullptr;

    using ProbeType = Engine::KeyCore::ProbeType;
    using ProbeRegisterFrame = Engine::KeyCore::ProbeRegisterFrame;
    using tRawProbeProc = Engine::KeyCore::tRawProbeProc;

    tRawProbeProc g_HxOriginal = nullptr;
    tRawProbeProc g_CxOriginal = nullptr;
    tRawProbeProc g_VerifyOriginal = nullptr;

    template<typename T>
    bool SafeReadValue(const void* address, T& value)
    {
        __try
        {
            value = *(const T*)address;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ZeroMemory(&value, sizeof(value));
            return false;
        }
    }

    bool SafeReadBytes(const void* address, void* buffer, size_t size)
    {
        __try
        {
            memcpy(buffer, address, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (buffer && size > 0u)
            {
                ZeroMemory(buffer, size);
            }
            return false;
        }
    }

    std::wstring BytesToHex(const void* buffer, size_t size)
    {
        return StringHelper::BytesToHexStringW((const unsigned __int8*)buffer, (unsigned __int32)size);
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        return Encoding::UnicodeToAnsi(value, Encoding::CodePage::UTF_8);
    }

    std::string BytesToHexUtf8(const void* buffer, size_t size)
    {
        return WideToUtf8(BytesToHex(buffer, size));
    }

    std::string BytesToHexLowerAscii(const void* buffer, size_t size, const char* separator = "")
    {
        static constexpr char HexDigits[] = "0123456789abcdef";

        const unsigned char* bytes = (const unsigned char*)buffer;
        const size_t separatorLength = separator ? strlen(separator) : 0u;
        std::string output;
        output.reserve(size == 0u ? 0u : (size * 2u) + ((size - 1u) * separatorLength));

        for (size_t index = 0; index < size; ++index)
        {
            if (index > 0u && separatorLength > 0u)
            {
                output.append(separator, separatorLength);
            }

            unsigned char value = bytes[index];
            output.push_back(HexDigits[(value >> 4u) & 0x0Fu]);
            output.push_back(HexDigits[value & 0x0Fu]);
        }

        return output;
    }

    std::string UInt32ToHexLowerAscii(unsigned int value)
    {
        return StringHelper::Format("0x%08x", value);
    }

    std::string UInt32ToHexCompactLowerAscii(unsigned int value)
    {
        return StringHelper::Format("0x%x", value);
    }

    std::string PointerToHexLowerAscii(ULONG_PTR value)
    {
        return StringHelper::Format("0x%08x", (unsigned int)value);
    }

    template<size_t N>
    std::string IntArrayToText(const std::array<int, N>& values)
    {
        std::string output;
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index > 0u)
            {
                output += ", ";
            }

            output += StringHelper::Format("%d", values[index]);
        }
        return output;
    }

    std::string JsonEscape(const std::string& value)
    {
        std::string output;
        output.reserve(value.size() + 16u);
        for (unsigned char ch : value)
        {
            switch (ch)
            {
                case '\\': output += "\\\\"; break;
                case '\"': output += "\\\""; break;
                case '\r': output += "\\r"; break;
                case '\n': output += "\\n"; break;
                case '\t': output += "\\t"; break;
                default:
                {
                    if (ch < 0x20u)
                    {
                        output += StringHelper::Format("\\u%04X", (unsigned int)ch);
                    }
                    else
                    {
                        output.push_back((char)ch);
                    }
                    break;
                }
            }
        }
        return output;
    }

    PVOID SearchUniquePattern(PVOID start, DWORD searchLength, const char* pattern, DWORD patternLength, unsigned int& matchCount)
    {
        matchCount = 0u;
        if (!start || !pattern || patternLength == 0u || searchLength < patternLength)
        {
            return nullptr;
        }

        PBYTE searchStart = (PBYTE)start;
        PVOID uniqueResult = nullptr;

        while ((DWORD)(searchStart - (PBYTE)start) + patternLength <= searchLength)
        {
            DWORD remaining = searchLength - (DWORD)(searchStart - (PBYTE)start);
            PVOID found = PE::SearchPattern(searchStart, remaining, pattern, patternLength);
            if (!found)
            {
                break;
            }

            ++matchCount;
            if (matchCount == 1u)
            {
                uniqueResult = found;
            }
            else
            {
                uniqueResult = nullptr;
            }

            searchStart = (PBYTE)found + 1u;
        }

        return matchCount == 1u ? uniqueResult : nullptr;
    }

    tRawProbeProc& GetOriginalProcSlot(ProbeType type)
    {
        switch (type)
        {
            case ProbeType::Hx:
                return g_HxOriginal;
            case ProbeType::Cx:
                return g_CxOriginal;
            case ProbeType::Verify:
            default:
                return g_VerifyOriginal;
        }
    }

    tRawProbeProc GetDetourProc(ProbeType type)
    {
        switch (type)
        {
            case ProbeType::Hx:
                return (tRawProbeProc)HxProbeDetour;
            case ProbeType::Cx:
                return (tRawProbeProc)CxProbeDetour;
            case ProbeType::Verify:
            default:
                return (tRawProbeProc)VerifyProbeDetour;
        }
    }

    LONG AttachDetour(tRawProbeProc& originalProc, tRawProbeProc detourProc)
    {
        LONG error = DetourTransactionBegin();
        if (error != NO_ERROR)
        {
            return error;
        }

        error = DetourUpdateThread(::GetCurrentThread());
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
            return error;
        }

        error = DetourAttach(&(PVOID&)originalProc, (PVOID&)detourProc);
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
            return error;
        }

        error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
        }
        return error;
    }

    LONG DetachDetour(tRawProbeProc& originalProc, tRawProbeProc detourProc)
    {
        LONG error = DetourTransactionBegin();
        if (error != NO_ERROR)
        {
            return error;
        }

        error = DetourUpdateThread(::GetCurrentThread());
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
            return error;
        }

        error = DetourDetach(&(PVOID&)originalProc, (PVOID&)detourProc);
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
            return error;
        }

        error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            DetourTransactionAbort();
        }
        return error;
    }
}

extern "C" void __stdcall ProbeEnterDispatcher(unsigned int probeTypeValue, const Engine::KeyCore::ProbeRegisterFrame* frame)
{
    if (!g_KeyCoreInstance)
    {
        return;
    }

    g_KeyCoreInstance->OnProbeHit((ProbeType)probeTypeValue, frame);
}

extern "C" void __declspec(naked) HxProbeDetour()
{
    __asm
    {
        pushad
        pushfd
        mov eax, esp
        push eax
        push 0
        call ProbeEnterDispatcher
        popfd
        popad
        mov eax, dword ptr [g_HxOriginal]
        jmp eax
    }
}

extern "C" void __declspec(naked) CxProbeDetour()
{
    __asm
    {
        pushad
        pushfd
        mov eax, esp
        push eax
        push 1
        call ProbeEnterDispatcher
        popfd
        popad
        mov eax, dword ptr [g_CxOriginal]
        jmp eax
    }
}

extern "C" void __declspec(naked) VerifyProbeDetour()
{
    __asm
    {
        pushad
        pushfd
        mov eax, esp
        push eax
        push 2
        call ProbeEnterDispatcher
        popfd
        popad
        mov eax, dword ptr [g_VerifyOriginal]
        jmp eax
    }
}

namespace Engine
{
    KeyCore::KeyCore()
        : mTargetModule(nullptr),
          mScanCompleted(false),
          mCompletionNotified(false),
          mHasHxData(false),
          mHasCxData(false),
          mHasVerifyData(false),
          mCxMask(0u),
          mCxOffset(0u),
          mCxRandType(0u)
    {
        for (size_t index = 0; index < mProbes.size(); ++index)
        {
            mProbes[index] = Probe{ (ProbeType)index, nullptr, nullptr, nullptr, false, false };
        }

        mHxKey.fill(0u);
        mHxNonce.fill(0u);
        mCxFilterKey.fill(0u);
        mControlBlock.fill(0u);
        mCxOrder.fill(0u);
        mGarbroPrologOrder.fill(0);
        mGarbroOddBranchOrder.fill(0);
        mGarbroEvenBranchOrder.fill(0);
        mVerifyBytes.fill(0u);
    }

    KeyCore::~KeyCore()
    {
        this->WriteSnapshot();
        this->mLogger.Close();

        if (g_KeyCoreInstance == this)
        {
            g_KeyCoreInstance = nullptr;
        }
    }

    void KeyCore::SetOutputDirectory(const std::wstring& directory)
    {
        this->mOutputDirectoryPath = Path::Combine(directory, KeyCore::FolderName);
        this->mLogPath = Path::Combine(this->mOutputDirectoryPath, KeyCore::LogFileName);
        this->mJsonPath = Path::Combine(this->mOutputDirectoryPath, KeyCore::JsonFileName);
        this->mTextPath = Path::Combine(this->mOutputDirectoryPath, KeyCore::TextFileName);
        this->mControlBlockPath = Path::Combine(this->mOutputDirectoryPath, KeyCore::ControlBlockFileName);

        Directory::Create(this->mOutputDirectoryPath);
        File::Delete(this->mLogPath);
        File::Delete(this->mJsonPath);
        File::Delete(this->mTextPath);
        File::Delete(this->mControlBlockPath);

        this->mLogger.Open(this->mLogPath.c_str());
        this->mLogger.WriteLine(L"Key dumper output directory: %s", this->mOutputDirectoryPath.c_str());
    }

    void KeyCore::Initialize(HMODULE targetModule, PVOID codeVa, DWORD codeSize)
    {
        if (this->mScanCompleted)
        {
            return;
        }

        this->mScanCompleted = true;
        this->mTargetModule = targetModule;
        this->mTargetModulePath = Util::GetModulePathW(targetModule);
        g_KeyCoreInstance = this;

        this->mLogger.WriteLine(L"Target module: %s", this->mTargetModulePath.c_str());
        this->mLogger.WriteLine(L"Target base: 0x%08X", (unsigned int)(ULONG_PTR)targetModule);

        if (!targetModule || !codeVa || codeSize == 0u)
        {
            this->mLogger.WriteLine(L"Signature scan skipped: invalid module or code section.");
            this->WriteSnapshot();
            return;
        }

        unsigned int hxMatches = 0u;
        unsigned int cxMatches = 0u;
        unsigned int verifyMatches = 0u;
        PVOID hxPoint = SearchUniquePattern(codeVa,
                                            codeSize,
                                            KeyCore::HxPointSignature,
                                            sizeof(KeyCore::HxPointSignature) - 1u,
                                            hxMatches);
        PVOID cxPoint = SearchUniquePattern(codeVa,
                                            codeSize,
                                            KeyCore::CxPointSignature,
                                            sizeof(KeyCore::CxPointSignature) - 1u,
                                            cxMatches);
        PVOID verifyPoint = SearchUniquePattern(codeVa,
                                                codeSize,
                                                KeyCore::VerifyPointSignature,
                                                sizeof(KeyCore::VerifyPointSignature) - 1u,
                                                verifyMatches);

        this->mLogger.WriteLine(L"Hx probe matches: %u", hxMatches);
        this->mLogger.WriteLine(L"Cx probe matches: %u", cxMatches);
        this->mLogger.WriteLine(L"Verify probe matches: %u", verifyMatches);

        if (hxPoint)
        {
            this->mLogger.WriteLine(L"Hx probe: 0x%08X", (unsigned int)(ULONG_PTR)hxPoint);
        }
        if (cxPoint)
        {
            this->mLogger.WriteLine(L"Cx probe: 0x%08X", (unsigned int)(ULONG_PTR)cxPoint);
        }
        if (verifyPoint)
        {
            this->mLogger.WriteLine(L"Verify probe: 0x%08X", (unsigned int)(ULONG_PTR)verifyPoint);
        }

        this->InstallProbe(ProbeType::Hx, hxPoint);
        this->InstallProbe(ProbeType::Cx, cxPoint);
        this->InstallProbe(ProbeType::Verify, verifyPoint);
        this->WriteSnapshot();
    }

    bool KeyCore::IsInitialized() const
    {
        return this->mScanCompleted;
    }

    bool KeyCore::InstallProbe(ProbeType type, PVOID address)
    {
        Probe& probe = this->mProbes[(size_t)type];
        probe.Type = type;
        probe.Address = (BYTE*)address;
        probe.OriginalProc = nullptr;
        probe.DetourProc = nullptr;
        probe.Hooked = false;
        probe.Triggered = false;

        if (!address)
        {
            this->mLogger.WriteLine(L"Probe %u not installed: signature not found or ambiguous.", (unsigned int)type);
            return false;
        }

        probe.DetourProc = GetDetourProc(type);
        tRawProbeProc& originalSlot = GetOriginalProcSlot(type);
        originalSlot = (tRawProbeProc)address;

        LONG error = AttachDetour(originalSlot, probe.DetourProc);
        if (error != NO_ERROR)
        {
            this->mLogger.WriteLine(L"Probe %u not installed: DetourAttach failed with %ld at 0x%08X.",
                                    (unsigned int)type,
                                    error,
                                    (unsigned int)(ULONG_PTR)address);
            originalSlot = nullptr;
            probe.DetourProc = nullptr;
            return false;
        }

        probe.OriginalProc = originalSlot;
        probe.Hooked = true;
        this->mLogger.WriteLine(L"Probe %u armed at 0x%08X.", (unsigned int)type, (unsigned int)(ULONG_PTR)address);
        return true;
    }

    void KeyCore::RestoreProbe(Probe& probe)
    {
        if (!probe.Hooked || !probe.DetourProc)
        {
            return;
        }

        tRawProbeProc& originalSlot = GetOriginalProcSlot(probe.Type);
        if (!originalSlot)
        {
            probe.Hooked = false;
            probe.OriginalProc = nullptr;
            probe.DetourProc = nullptr;
            return;
        }

        LONG error = DetachDetour(originalSlot, probe.DetourProc);
        if (error != NO_ERROR)
        {
            this->mLogger.WriteLine(L"Probe %u detach failed with %ld.", (unsigned int)probe.Type, error);
            return;
        }

        probe.Hooked = false;
        probe.OriginalProc = nullptr;
        probe.DetourProc = nullptr;
        originalSlot = nullptr;
    }

    bool KeyCore::CaptureHx(const ProbeRegisterFrame* frame)
    {
        ULONG_PTR keyPointer = 0u;
        ULONG_PTR noncePointer = 0u;
        if (!SafeReadValue((const void*)(frame->Ebp + 0x14u), keyPointer) ||
            !SafeReadValue((const void*)(frame->Ebp + 0x18u), noncePointer))
        {
            this->mLogger.WriteLine(L"Hx capture failed: cannot read key/nonce pointers.");
            return false;
        }

        if (!SafeReadBytes((const void*)keyPointer, this->mHxKey.data(), this->mHxKey.size()) ||
            !SafeReadBytes((const void*)noncePointer, this->mHxNonce.data(), this->mHxNonce.size()))
        {
            this->mLogger.WriteLine(L"Hx capture failed: cannot read key/nonce data.");
            return false;
        }

        this->mHasHxData = true;
        this->mLogger.WriteLine(L"Hx key: %s", BytesToHex(this->mHxKey.data(), this->mHxKey.size()).c_str());
        this->mLogger.WriteLine(L"Hx nonce: %s", BytesToHex(this->mHxNonce.data(), this->mHxNonce.size()).c_str());
        return true;
    }

    bool KeyCore::CaptureCx(const ProbeRegisterFrame* frame)
    {
        ULONG_PTR base = frame->Ecx;
        if (base == 0u)
        {
            this->mLogger.WriteLine(L"Cx capture failed: ECX is null.");
            return false;
        }

        bool okay =
            SafeReadBytes((const void*)(base + 0x08u), this->mCxFilterKey.data(), this->mCxFilterKey.size()) &&
            SafeReadValue((const void*)(base + 0x10u), this->mCxMask) &&
            SafeReadValue((const void*)(base + 0x14u), this->mCxOffset) &&
            SafeReadValue((const void*)(base + 0x18u), this->mCxRandType) &&
            SafeReadBytes((const void*)(base + 0x20u), this->mControlBlock.data(), this->mControlBlock.size()) &&
            SafeReadBytes((const void*)(base + 0x3020u), this->mCxOrder.data(), this->mCxOrder.size());

        if (!okay)
        {
            this->mLogger.WriteLine(L"Cx capture failed: cannot read one or more fields.");
            return false;
        }

        this->UpdateGarbroOrders();
        this->mHasCxData = true;
        this->mLogger.WriteLine(L"Cx filterkey: %s", BytesToHex(this->mCxFilterKey.data(), this->mCxFilterKey.size()).c_str());
        this->mLogger.WriteLine(L"Cx mask: 0x%08X", this->mCxMask);
        this->mLogger.WriteLine(L"Cx offset: 0x%08X", this->mCxOffset);
        this->mLogger.WriteLine(L"Cx randtype: %u", (unsigned int)this->mCxRandType);
        this->mLogger.WriteLine(L"Cx order: %s", BytesToHex(this->mCxOrder.data(), this->mCxOrder.size()).c_str());
        this->mLogger.WriteLine(L"control_block.bin saved to: %s", this->mControlBlockPath.c_str());
        return true;
    }

    bool KeyCore::CaptureVerify(const ProbeRegisterFrame* frame)
    {
        if (!SafeReadBytes((const void*)(frame->Ebp - 0x74u), this->mVerifyBytes.data(), this->mVerifyBytes.size()))
        {
            this->mLogger.WriteLine(L"Verify capture failed: cannot read verify bytes.");
            return false;
        }

        this->mHasVerifyData = true;
        this->mLogger.WriteLine(L"Verify: %s", BytesToHex(this->mVerifyBytes.data(), this->mVerifyBytes.size()).c_str());
        return true;
    }

    unsigned int KeyCore::GetCaptureProgressPercent() const
    {
        unsigned int completed = 0u;
        completed += this->mHasHxData ? 1u : 0u;
        completed += this->mHasCxData ? 1u : 0u;
        completed += this->mHasVerifyData ? 1u : 0u;
        return (completed * 100u) / 3u;
    }

    void KeyCore::NotifyLoaderProgress() const
    {
        wchar_t loaderWindowValue[64]{};
        DWORD valueLength = ::GetEnvironmentVariableW(LoaderIpc::LoaderWindowHandleEnvName,
                                                      loaderWindowValue,
                                                      (DWORD)(sizeof(loaderWindowValue) / sizeof(loaderWindowValue[0])));
        if (valueLength == 0u || valueLength >= (DWORD)(sizeof(loaderWindowValue) / sizeof(loaderWindowValue[0])))
        {
            return;
        }

        HWND loaderWindow = (HWND)(ULONG_PTR)_wcstoui64(loaderWindowValue, nullptr, 10);
        if (!loaderWindow || !::IsWindow(loaderWindow))
        {
            return;
        }

        ::PostMessageW(loaderWindow, LoaderIpc::ProgressMessage(), (WPARAM)this->GetCaptureProgressPercent(), 0u);
    }

    void KeyCore::NotifyLoaderCompleted() const
    {
        wchar_t loaderWindowValue[64]{};
        DWORD valueLength = ::GetEnvironmentVariableW(LoaderIpc::LoaderWindowHandleEnvName,
                                                      loaderWindowValue,
                                                      (DWORD)(sizeof(loaderWindowValue) / sizeof(loaderWindowValue[0])));
        if (valueLength == 0u || valueLength >= (DWORD)(sizeof(loaderWindowValue) / sizeof(loaderWindowValue[0])))
        {
            return;
        }

        HWND loaderWindow = (HWND)(ULONG_PTR)_wcstoui64(loaderWindowValue, nullptr, 10);
        if (!loaderWindow || !::IsWindow(loaderWindow))
        {
            return;
        }

        ::PostMessageW(loaderWindow, LoaderIpc::CompletedMessage(), 0u, 0u);
    }

    void KeyCore::OnProbeHit(ProbeType type, const ProbeRegisterFrame* frame)
    {
        if (!frame)
        {
            return;
        }

        Probe& probe = this->mProbes[(size_t)type];
        bool captured = false;

        switch (type)
        {
            case ProbeType::Hx:
                if (!this->mHasHxData)
                {
                    captured = this->CaptureHx(frame);
                }
                break;
            case ProbeType::Cx:
                if (!this->mHasCxData)
                {
                    captured = this->CaptureCx(frame);
                }
                break;
            case ProbeType::Verify:
                if (!this->mHasVerifyData)
                {
                    captured = this->CaptureVerify(frame);
                }
                break;
            default:
                break;
        }

        if (!captured)
        {
            return;
        }

        if (!probe.Triggered)
        {
            probe.Triggered = true;
            this->mLogger.WriteLine(L"Probe %u captured successfully.", (unsigned int)type);
        }

        this->WriteSnapshot();
        this->NotifyLoaderProgress();
        this->MaybeNotifyCompletion();
    }

    void KeyCore::UpdateGarbroOrders()
    {
        static constexpr int Source3[3] = { 0, 1, 2 };
        static constexpr int Source6[6] = { 2, 5, 3, 4, 1, 0 };
        static constexpr int Source8[8] = { 0, 2, 3, 1, 5, 6, 7, 4 };

        this->mGarbroPrologOrder = { 0, 1, 2 };
        this->mGarbroOddBranchOrder = { 0, 1, 2, 3, 4, 5 };
        this->mGarbroEvenBranchOrder = { 0, 1, 2, 3, 4, 5, 6, 7 };

        for (int index = 0; index < 3; ++index)
        {
            unsigned int target = this->mCxOrder[14 + index];
            if (target < this->mGarbroPrologOrder.size())
            {
                this->mGarbroPrologOrder[target] = Source3[index];
            }
        }

        for (int index = 0; index < 6; ++index)
        {
            unsigned int target = this->mCxOrder[8 + index];
            if (target < this->mGarbroOddBranchOrder.size())
            {
                this->mGarbroOddBranchOrder[target] = Source6[index];
            }
        }

        for (int index = 0; index < 8; ++index)
        {
            unsigned int target = this->mCxOrder[index];
            if (target < this->mGarbroEvenBranchOrder.size())
            {
                this->mGarbroEvenBranchOrder[target] = Source8[index];
            }
        }
    }

    void KeyCore::WriteSnapshot()
    {
        if (this->mOutputDirectoryPath.empty() || this->mJsonPath.empty())
        {
            return;
        }

        if (this->mHasCxData)
        {
            File::WriteAllBytes(this->mControlBlockPath, this->mControlBlock.data(), this->mControlBlock.size());
        }

        auto appendIntArray = [](std::string& json, const auto& values)
        {
            json.push_back('[');
            for (size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0u)
                {
                    json += ", ";
                }
                json += StringHelper::Format("%d", values[index]);
            }
            json.push_back(']');
        };

        std::string json;
        json += "{\n";
        json += "  \"module_path\": \"" + JsonEscape(WideToUtf8(this->mTargetModulePath)) + "\",\n";
        json += "  \"module_base\": \"" + StringHelper::Format("0x%08X", (unsigned int)(ULONG_PTR)this->mTargetModule) + "\",\n";
        json += "  \"output_directory\": \"" + JsonEscape(WideToUtf8(this->mOutputDirectoryPath)) + "\",\n";

        if (this->mHasHxData)
        {
            json += "  \"hx\": {\n";
            json += "    \"key\": \"" + BytesToHexUtf8(this->mHxKey.data(), this->mHxKey.size()) + "\",\n";
            json += "    \"nonce\": \"" + BytesToHexUtf8(this->mHxNonce.data(), this->mHxNonce.size()) + "\"\n";
            json += "  },\n";
        }
        else
        {
            json += "  \"hx\": null,\n";
        }

        if (this->mHasCxData)
        {
            json += "  \"cx\": {\n";
            json += "    \"filterkey\": \"" + BytesToHexUtf8(this->mCxFilterKey.data(), this->mCxFilterKey.size()) + "\",\n";
            json += "    \"mask\": \"" + StringHelper::Format("0x%08X", this->mCxMask) + "\",\n";
            json += "    \"offset\": \"" + StringHelper::Format("0x%08X", this->mCxOffset) + "\",\n";
            json += "    \"randtype\": " + StringHelper::Format("%u", (unsigned int)this->mCxRandType) + ",\n";
            json += "    \"order\": \"" + BytesToHexUtf8(this->mCxOrder.data(), this->mCxOrder.size()) + "\",\n";
            json += "    \"control_block\": \"" + JsonEscape(WideToUtf8(this->mControlBlockPath)) + "\",\n";
            json += "    \"garbro\": {\n";
            json += "      \"prolog_order\": ";
            appendIntArray(json, this->mGarbroPrologOrder);
            json += ",\n";
            json += "      \"odd_branch_order\": ";
            appendIntArray(json, this->mGarbroOddBranchOrder);
            json += ",\n";
            json += "      \"even_branch_order\": ";
            appendIntArray(json, this->mGarbroEvenBranchOrder);
            json += "\n";
            json += "    }\n";
            json += "  },\n";
        }
        else
        {
            json += "  \"cx\": null,\n";
        }

        if (this->mHasVerifyData)
        {
            json += "  \"verify\": \"" + BytesToHexUtf8(this->mVerifyBytes.data(), this->mVerifyBytes.size()) + "\",\n";
        }
        else
        {
            json += "  \"verify\": null,\n";
        }

        json += "  \"capture_complete\": ";
        json += (this->mHasHxData && this->mHasCxData && this->mHasVerifyData) ? "true\n" : "false\n";
        json += "}\n";

        File::WriteAllBytes(this->mJsonPath, json.data(), json.size());
        this->WriteTextSnapshot();
    }

    void KeyCore::WriteTextSnapshot()
    {
        if (this->mTextPath.empty())
        {
            return;
        }

        std::string text;

        if (!this->mTargetModulePath.empty() && this->mTargetModule)
        {
            text += "load ";
            text += WideToUtf8(this->mTargetModulePath);
            text += " at ";
            text += PointerToHexLowerAscii((ULONG_PTR)this->mTargetModule);
            text += "\r\n";
        }

        if (this->mProbes[(size_t)ProbeType::Hx].Address)
        {
            text += "hxpoint at ";
            text += PointerToHexLowerAscii((ULONG_PTR)this->mProbes[(size_t)ProbeType::Hx].Address);
            text += "\r\n";
        }

        if (this->mProbes[(size_t)ProbeType::Cx].Address)
        {
            text += "cxpoint at ";
            text += PointerToHexLowerAscii((ULONG_PTR)this->mProbes[(size_t)ProbeType::Cx].Address);
            text += "\r\n";
        }

        if (this->mHasHxData)
        {
            text += "* key : ";
            text += BytesToHexLowerAscii(this->mHxKey.data(), this->mHxKey.size());
            text += "\r\n";
            text += "* nonce : ";
            text += BytesToHexLowerAscii(this->mHxNonce.data(), this->mHxNonce.size());
            text += "\r\n";
        }

        if (this->mHasVerifyData)
        {
            text += "* verify : ";
            text += BytesToHexLowerAscii(this->mVerifyBytes.data(), this->mVerifyBytes.size());
            text += "\r\n";
        }

        if (this->mHasCxData)
        {
            text += "* filterkey : ";
            text += BytesToHexLowerAscii(this->mCxFilterKey.data(), this->mCxFilterKey.size());
            text += "\r\n";
            text += "* mask : ";
            text += UInt32ToHexCompactLowerAscii(this->mCxMask);
            text += "\r\n";
            text += "* offset : ";
            text += UInt32ToHexCompactLowerAscii(this->mCxOffset);
            text += "\r\n";
            text += "* randtype : ";
            text += StringHelper::Format("%u", (unsigned int)this->mCxRandType);
            text += "\r\n";
            text += "* order : ";
            text += BytesToHexLowerAscii(this->mCxOrder.data(), this->mCxOrder.size(), " ");
            text += "\r\n";
            text += "* PrologOrder (garbro) : ";
            text += IntArrayToText(this->mGarbroPrologOrder);
            text += "\r\n";
            text += "* OddBranchOrder (garbro) : ";
            text += IntArrayToText(this->mGarbroOddBranchOrder);
            text += "\r\n";
            text += "* EvenBranchOrder (garbro) : ";
            text += IntArrayToText(this->mGarbroEvenBranchOrder);
            text += "\r\n";
        }

        File::WriteAllBytes(this->mTextPath, text.data(), text.size());
    }

    void KeyCore::MaybeNotifyCompletion()
    {
        if (this->mCompletionNotified || !this->mHasHxData || !this->mHasCxData || !this->mHasVerifyData)
        {
            return;
        }

        this->mCompletionNotified = true;
        this->mLogger.WriteLine(L"Key capture completed.");
        this->NotifyLoaderCompleted();
    }
}
