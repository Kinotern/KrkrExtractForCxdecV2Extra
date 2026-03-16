#include "BatchExtractorUI.h"
#include "resource.h"

#include <CommCtrl.h>
#include <CommDlg.h>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <strsafe.h>

#include <algorithm>
#include <cstdarg>
#include <string>
#include <vector>
#include <deque>
#include <new>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace
{
    constexpr size_t MaxUiPath = 1024u;
    constexpr UINT WM_APP_TASK_UPDATE = WM_APP + 0x101u;
    constexpr UINT WM_APP_WATCHDOG_TICK = WM_APP + 0x102u;

    enum class UiTaskState
    {
        Queued,
        Preparing,
        IndexLoaded,
        Extracting,
        Completed,
        Failed
    };

    struct TaskRecord
    {
        unsigned int Id;
        std::wstring PackagePath;
        std::wstring DisplayName;
        std::wstring OutputDirectory;
        UiTaskState State;
        unsigned int Current;
        unsigned int Total;
        std::wstring Detail;
        bool Finished;
        bool Succeeded;
        ULONGLONG LastTick;
    };

    struct PendingTask
    {
        unsigned int Id;
        std::wstring PackagePath;
        std::wstring OutputDirectory;
    };

    struct TaskUpdateMessage
    {
        unsigned int TaskId;
        unsigned int State;
        unsigned int Current;
        unsigned int Total;
        wchar_t PackagePath[MaxUiPath];
        wchar_t Detail[MaxUiPath];
    };

    struct UiContext
    {
        UI::StartupContext Startup;
        HWND Window;
        HWND TaskList;
        HWND OutputEdit;
        HWND OverallProgress;
        HWND StatusText;
        HWND NotifyPopup;
        HWND NotifySound;
        HWND WorkerInfo;
        CRITICAL_SECTION QueueLock;
        CRITICAL_SECTION LogLock;
        HANDLE QueueEvent;
        HANDLE StopEvent;
        HANDLE WatchdogThread;
        std::vector<HANDLE> Workers;
        std::deque<PendingTask> Queue;
        std::vector<TaskRecord> Tasks;
        std::wstring DefaultOutputDirectory;
        std::wstring ModuleDirectory;
        std::wstring UiLogPath;
        unsigned int NextTaskId;
        LONG ActiveWorkers;
        bool CompletionNotified;
    };

    std::wstring FormatString(const wchar_t* format, ...)
    {
        wchar_t buffer[1024];
        va_list ap;
        va_start(ap, format);
        int count = _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, ap);
        va_end(ap);
        if (count <= 0)
        {
            return std::wstring();
        }
        return std::wstring(buffer, count);
    }

    std::wstring CombinePath(const std::wstring& directory, const std::wstring& fileName)
    {
        if (directory.empty())
        {
            return fileName;
        }

        if (directory.back() == L'\\' || directory.back() == L'/')
        {
            return directory + fileName;
        }
        return directory + L'\\' + fileName;
    }

    std::wstring GetModulePath(HMODULE module)
    {
        wchar_t buffer[MaxUiPath];
        DWORD length = ::GetModuleFileNameW(module, buffer, (DWORD)_countof(buffer));
        if (length == 0 || length >= _countof(buffer))
        {
            return std::wstring();
        }
        return std::wstring(buffer, length);
    }

    std::wstring GetDirectoryName(const std::wstring& fullPath)
    {
        if (fullPath.empty())
        {
            return std::wstring();
        }

        wchar_t buffer[MaxUiPath];
        StringCchCopyW(buffer, _countof(buffer), fullPath.c_str());
        if (::PathRemoveFileSpecW(buffer))
        {
            return std::wstring(buffer);
        }
        return std::wstring();
    }

    std::wstring GetWindowTextString(HWND control)
    {
        int length = ::GetWindowTextLengthW(control);
        if (length <= 0)
        {
            return std::wstring();
        }

        std::wstring text((size_t)length + 1u, L'\0');
        int copied = ::GetWindowTextW(control, text.data(), length + 1);
        if (copied <= 0)
        {
            return std::wstring();
        }
        text.resize((size_t)copied);
        return text;
    }

    void AppendUtf8Line(const std::wstring& filePath, const std::wstring& line)
    {
        HANDLE file = ::CreateFileW(filePath.c_str(),
                                    FILE_APPEND_DATA,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }

        int utf8Length = ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), nullptr, 0, nullptr, nullptr);
        if (utf8Length > 0)
        {
            std::string utf8((size_t)utf8Length, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, line.c_str(), (int)line.length(), utf8.data(), utf8Length, nullptr, nullptr);
            DWORD written = 0u;
            ::WriteFile(file, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        }

        ::CloseHandle(file);
    }

    void WriteUiLog(UiContext* context, const wchar_t* format, ...)
    {
        if (!context)
        {
            return;
        }

        wchar_t message[1024];
        va_list ap;
        va_start(ap, format);
        int count = _vsnwprintf_s(message, _countof(message), _TRUNCATE, format, ap);
        va_end(ap);
        if (count <= 0)
        {
            return;
        }

        SYSTEMTIME st{};
        ::GetLocalTime(&st);
        std::wstring line = FormatString(L"%04u-%02u-%02u %02u:%02u:%02u | %s\r\n",
                                         st.wYear,
                                         st.wMonth,
                                         st.wDay,
                                         st.wHour,
                                         st.wMinute,
                                         st.wSecond,
                                         message);

        ::EnterCriticalSection(&context->LogLock);
        AppendUtf8Line(context->UiLogPath, line);
        ::LeaveCriticalSection(&context->LogLock);
    }

    const wchar_t* ToStateText(UiTaskState state)
    {
        switch (state)
        {
            case UiTaskState::Queued: return L"排队中";
            case UiTaskState::Preparing: return L"准备中";
            case UiTaskState::IndexLoaded: return L"读取索引";
            case UiTaskState::Extracting: return L"处理中";
            case UiTaskState::Completed: return L"已完成";
            case UiTaskState::Failed: return L"失败";
        }
        return L"未知";
    }

    std::wstring ToProgressText(const TaskRecord& task)
    {
        if (task.Finished)
        {
            return task.Succeeded ? L"100%" : L"完成(含失败)";
        }

        if (task.Total == 0u)
        {
            return task.State == UiTaskState::Queued ? L"等待中" : L"准备中";
        }

        unsigned int percent = task.Current >= task.Total ? 100u : (task.Current * 100u) / task.Total;
        return FormatString(L"%u%% (%u/%u)", percent, task.Current, task.Total);
    }

    int FindTaskIndex(const UiContext* context, unsigned int taskId)
    {
        for (size_t index = 0; index < context->Tasks.size(); ++index)
        {
            if (context->Tasks[index].Id == taskId)
            {
                return (int)index;
            }
        }
        return -1;
    }

    int FindListItemByTaskId(HWND listView, unsigned int taskId)
    {
        LVFINDINFOW info{};
        info.flags = LVFI_PARAM;
        info.lParam = (LPARAM)taskId;
        return ListView_FindItem(listView, -1, &info);
    }

    void RefreshTaskRow(UiContext* context, int taskIndex)
    {
        if (!context || taskIndex < 0 || taskIndex >= (int)context->Tasks.size())
        {
            return;
        }

        const TaskRecord& task = context->Tasks[(size_t)taskIndex];
        int listIndex = FindListItemByTaskId(context->TaskList, task.Id);
        if (listIndex < 0)
        {
            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = ListView_GetItemCount(context->TaskList);
            item.pszText = const_cast<LPWSTR>(task.DisplayName.c_str());
            item.lParam = (LPARAM)task.Id;
            listIndex = ListView_InsertItem(context->TaskList, &item);
        }

        ListView_SetItemText(context->TaskList, listIndex, 0, const_cast<LPWSTR>(task.DisplayName.c_str()));
        ListView_SetItemText(context->TaskList, listIndex, 1, const_cast<LPWSTR>(ToStateText(task.State)));

        std::wstring progress = ToProgressText(task);
        ListView_SetItemText(context->TaskList, listIndex, 2, progress.data());
        ListView_SetItemText(context->TaskList, listIndex, 3, const_cast<LPWSTR>(task.Detail.c_str()));
    }

    bool IsSupportedPackage(const std::wstring& path)
    {
        if (path.empty())
        {
            return false;
        }

        DWORD attr = ::GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            return false;
        }

        const wchar_t* extension = ::PathFindExtensionW(path.c_str());
        return extension != nullptr && _wcsicmp(extension, L".xp3") == 0;
    }

    std::wstring BrowseFolder(HWND owner, const std::wstring& title)
    {
        wchar_t display[MaxUiPath]{};
        BROWSEINFOW info{};
        info.hwndOwner = owner;
        info.pszDisplayName = display;
        info.lpszTitle = title.c_str();
        info.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS;

        LPITEMIDLIST idList = ::SHBrowseForFolderW(&info);
        if (!idList)
        {
            return std::wstring();
        }

        wchar_t folder[MaxUiPath]{};
        std::wstring result;
        if (::SHGetPathFromIDListW(idList, folder))
        {
            result = folder;
        }
        ::CoTaskMemFree(idList);
        return result;
    }

    std::vector<std::wstring> BrowsePackageFiles(HWND owner)
    {
        wchar_t buffer[32768]{};
        OPENFILENAMEW ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = owner;
        ofn.lpstrFilter = L"XP3 Files (*.xp3)\0*.xp3\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = buffer;
        ofn.nMaxFile = (DWORD)_countof(buffer);
        ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_HIDEREADONLY;

        std::vector<std::wstring> files;
        if (!::GetOpenFileNameW(&ofn))
        {
            return files;
        }

        const wchar_t* first = buffer;
        const wchar_t* second = first + wcslen(first) + 1;
        if (*second == L'\0')
        {
            files.emplace_back(first);
            return files;
        }

        std::wstring directory = first;
        while (*second != L'\0')
        {
            files.push_back(CombinePath(directory, second));
            second += wcslen(second) + 1;
        }
        return files;
    }

    bool PopPendingTask(UiContext* context, PendingTask& task)
    {
        bool hasTask = false;

        ::EnterCriticalSection(&context->QueueLock);
        if (!context->Queue.empty())
        {
            task = context->Queue.front();
            context->Queue.pop_front();
            hasTask = true;
        }

        if (context->Queue.empty())
        {
            ::ResetEvent(context->QueueEvent);
        }
        ::LeaveCriticalSection(&context->QueueLock);

        return hasTask;
    }

    void EnqueueTask(UiContext* context, const std::wstring& packagePath, const std::wstring& outputDirectory)
    {
        TaskRecord task{};
        task.Id = context->NextTaskId++;
        task.PackagePath = packagePath;
        task.DisplayName = ::PathFindFileNameW(packagePath.c_str());
        task.OutputDirectory = outputDirectory;
        task.State = UiTaskState::Queued;
        task.Current = 0u;
        task.Total = 0u;
        task.Detail = outputDirectory;
        task.Finished = false;
        task.Succeeded = false;
        task.LastTick = ::GetTickCount64();

        context->Tasks.push_back(task);
        RefreshTaskRow(context, (int)context->Tasks.size() - 1);

        ::EnterCriticalSection(&context->QueueLock);
        context->Queue.push_back(PendingTask{ task.Id, packagePath, outputDirectory });
        ::SetEvent(context->QueueEvent);
        ::LeaveCriticalSection(&context->QueueLock);

        context->CompletionNotified = false;
        WriteUiLog(context, L"Task queued: #%u %s -> %s", task.Id, packagePath.c_str(), outputDirectory.c_str());
    }

    void AddPackageFiles(UiContext* context, const std::vector<std::wstring>& paths)
    {
        if (!context)
        {
            return;
        }

        std::wstring outputDirectory = GetWindowTextString(context->OutputEdit);
        if (outputDirectory.empty())
        {
            outputDirectory = context->DefaultOutputDirectory;
            ::SetWindowTextW(context->OutputEdit, outputDirectory.c_str());
        }

        unsigned int acceptedCount = 0u;
        for (const std::wstring& path : paths)
        {
            if (!IsSupportedPackage(path))
            {
                WriteUiLog(context, L"Skip unsupported file: %s", path.c_str());
                continue;
            }

            EnqueueTask(context, path, outputDirectory);
            ++acceptedCount;
        }

        if (acceptedCount == 0u)
        {
            ::SetWindowTextW(context->StatusText, L"没有可处理的 XP3 文件。");
        }
    }

    void MaybeNotifyFinished(UiContext* context)
    {
        if (!context || context->CompletionNotified)
        {
            return;
        }

        bool hasTask = !context->Tasks.empty();
        bool hasRunning = context->ActiveWorkers > 0;
        bool hasQueued = false;

        ::EnterCriticalSection(&context->QueueLock);
        hasQueued = !context->Queue.empty();
        ::LeaveCriticalSection(&context->QueueLock);

        if (!hasTask || hasRunning || hasQueued)
        {
            return;
        }

        bool allFinished = true;
        bool allSucceeded = true;
        for (const TaskRecord& task : context->Tasks)
        {
            allFinished = allFinished && task.Finished;
            if (task.Finished)
            {
                allSucceeded = allSucceeded && task.Succeeded;
            }
        }

        if (!allFinished)
        {
            return;
        }

        context->CompletionNotified = true;

        if (::SendMessageW(context->NotifySound, BM_GETCHECK, 0, 0) == BST_CHECKED)
        {
            ::MessageBeep(allSucceeded ? MB_ICONINFORMATION : MB_ICONWARNING);
        }

        if (::SendMessageW(context->NotifyPopup, BM_GETCHECK, 0, 0) == BST_CHECKED)
        {
            ::MessageBoxW(context->Window,
                          allSucceeded ? L"所有解包任务已完成。" : L"解包队列已结束，但存在失败任务，请查看列表和日志。",
                          L"批量解包完成",
                          MB_OK | (allSucceeded ? MB_ICONINFORMATION : MB_ICONWARNING));
        }
    }

    void UpdateSummary(UiContext* context)
    {
        if (!context)
        {
            return;
        }

        unsigned int queuedCount = 0u;
        unsigned int finishedCount = 0u;
        unsigned int failedCount = 0u;
        unsigned int progressCurrent = 0u;
        unsigned int progressTotal = 0u;

        ::EnterCriticalSection(&context->QueueLock);
        queuedCount = (unsigned int)context->Queue.size();
        ::LeaveCriticalSection(&context->QueueLock);

        for (const TaskRecord& task : context->Tasks)
        {
            if (task.Finished)
            {
                ++finishedCount;
                if (!task.Succeeded)
                {
                    ++failedCount;
                }
            }

            if (task.Total > 0u)
            {
                progressCurrent += std::min(task.Current, task.Total);
                progressTotal += task.Total;
            }
            else
            {
                progressTotal += 1u;
                if (task.Finished)
                {
                    progressCurrent += 1u;
                }
            }
        }

        unsigned int percent = 0u;
        if (progressTotal > 0u)
        {
            percent = (progressCurrent * 100u) / progressTotal;
        }

        SendMessageW(context->OverallProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessageW(context->OverallProgress, PBM_SETPOS, percent, 0);

        std::wstring status = FormatString(L"总任务 %u | 运行中 %ld | 排队 %u | 完成 %u | 失败 %u",
                                           (unsigned int)context->Tasks.size(),
                                           context->ActiveWorkers,
                                           queuedCount,
                                           finishedCount,
                                           failedCount);
        ::SetWindowTextW(context->StatusText, status.c_str());

        std::wstring title = FormatString(L"Cxdec Batch Extractor - 运行中 %ld / 排队 %u / 完成 %u",
                                          context->ActiveWorkers,
                                          queuedCount,
                                          finishedCount);
        ::SetWindowTextW(context->Window, title.c_str());

        MaybeNotifyFinished(context);
    }

    void ClearFinishedTasks(UiContext* context)
    {
        if (!context)
        {
            return;
        }

        context->Tasks.erase(std::remove_if(context->Tasks.begin(),
                                            context->Tasks.end(),
                                            [](const TaskRecord& task) { return task.Finished; }),
                             context->Tasks.end());

        ListView_DeleteAllItems(context->TaskList);
        for (size_t index = 0; index < context->Tasks.size(); ++index)
        {
            RefreshTaskRow(context, (int)index);
        }

        WriteUiLog(context, L"Cleared finished tasks");
    }

    void PostTaskUpdate(UiContext* context,
                        unsigned int taskId,
                        unsigned int state,
                        unsigned int current,
                        unsigned int total,
                        const wchar_t* packagePath,
                        const wchar_t* detail)
    {
        if (!context || !context->Window)
        {
            return;
        }

        TaskUpdateMessage* message = (TaskUpdateMessage*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TaskUpdateMessage));
        if (!message)
        {
            return;
        }

        message->TaskId = taskId;
        message->State = state;
        message->Current = current;
        message->Total = total;
        ::StringCchCopyW(message->PackagePath, _countof(message->PackagePath), packagePath ? packagePath : L"");
        ::StringCchCopyW(message->Detail, _countof(message->Detail), detail ? detail : L"");

        if (!::PostMessageW(context->Window, WM_APP_TASK_UPDATE, 0, (LPARAM)message))
        {
            ::HeapFree(::GetProcessHeap(), 0, message);
        }
    }

    DWORD WINAPI WorkerThreadProc(LPVOID parameter)
    {
        UiContext* context = (UiContext*)parameter;
        HANDLE waitHandles[2]{ context->StopEvent, context->QueueEvent };

        while (true)
        {
            PendingTask task{};
            if (!PopPendingTask(context, task))
            {
                DWORD waitResult = ::WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0)
                {
                    break;
                }
                continue;
            }

            ::InterlockedIncrement(&context->ActiveWorkers);
            ::PostMessageW(context->Window, WM_APP_WATCHDOG_TICK, 0, 0);

            if (context->Startup.Api.ExtractPackageEx && context->Startup.Api.SetExtractProgressCallback)
            {
                context->Startup.Api.ExtractPackageEx(task.PackagePath.c_str(), task.OutputDirectory.c_str(), task.Id);
            }
            else
            {
                PostTaskUpdate(context, task.Id, Engine::ExtractTaskFailed, 0u, 0u, task.PackagePath.c_str(), L"核心接口未初始化");
                WriteUiLog(context, L"Task failed: #%u core API unavailable", task.Id);
            }

            ::InterlockedDecrement(&context->ActiveWorkers);
            ::PostMessageW(context->Window, WM_APP_WATCHDOG_TICK, 0, 0);
        }

        return 0u;
    }

    DWORD WINAPI WatchdogThreadProc(LPVOID parameter)
    {
        UiContext* context = (UiContext*)parameter;
        while (::WaitForSingleObject(context->StopEvent, 1000u) == WAIT_TIMEOUT)
        {
            if (context->Window)
            {
                ::PostMessageW(context->Window, WM_APP_WATCHDOG_TICK, 0, 0);
            }
        }
        return 0u;
    }

    void WINAPI ExtractProgressThunk(unsigned int taskId,
                                     const wchar_t* packagePath,
                                     unsigned int state,
                                     unsigned int current,
                                     unsigned int total,
                                     const wchar_t* detail,
                                     void* context)
    {
        PostTaskUpdate((UiContext*)context, taskId, state, current, total, packagePath, detail);
    }

    void InitializeListViewColumns(HWND listView)
    {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        column.pszText = const_cast<LPWSTR>(L"文件");
        column.cx = 120;
        ListView_InsertColumn(listView, 0, &column);

        column.pszText = const_cast<LPWSTR>(L"状态");
        column.cx = 70;
        column.iSubItem = 1;
        ListView_InsertColumn(listView, 1, &column);

        column.pszText = const_cast<LPWSTR>(L"进度");
        column.cx = 85;
        column.iSubItem = 2;
        ListView_InsertColumn(listView, 2, &column);

        column.pszText = const_cast<LPWSTR>(L"详细信息");
        column.cx = 125;
        column.iSubItem = 3;
        ListView_InsertColumn(listView, 3, &column);

        ListView_SetExtendedListViewStyle(listView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    }

    unsigned int ResolveWorkerCount()
    {
        // The underlying TVP/Cxdec runtime is not stable under concurrent archive extraction.
        // Keep a single extraction worker and let the watchdog/UI threads handle responsiveness.
        return 1u;
    }

    INT_PTR CALLBACK ExtractorDialogWindProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        UiContext* context = (UiContext*)::GetWindowLongPtrW(hwnd, GWLP_USERDATA);

        switch (msg)
        {
            case WM_INITDIALOG:
            {
                context = (UiContext*)lParam;
                context->Window = hwnd;
                context->TaskList = ::GetDlgItem(hwnd, IDC_TaskList);
                context->OutputEdit = ::GetDlgItem(hwnd, IDC_OutputPath);
                context->OverallProgress = ::GetDlgItem(hwnd, IDC_OverallProgress);
                context->StatusText = ::GetDlgItem(hwnd, IDC_StatusText);
                context->NotifyPopup = ::GetDlgItem(hwnd, IDC_NotifyPopup);
                context->NotifySound = ::GetDlgItem(hwnd, IDC_NotifySound);
                context->WorkerInfo = ::GetDlgItem(hwnd, IDC_WorkerInfo);

                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)context);
                ::SendMessageW(context->NotifyPopup, BM_SETCHECK, BST_CHECKED, 0);
                ::SendMessageW(context->NotifySound, BM_SETCHECK, BST_CHECKED, 0);
                ::SetWindowTextW(context->OutputEdit, context->DefaultOutputDirectory.c_str());
                ::SetWindowTextW(context->WorkerInfo, FormatString(L"工作线程: %u", (unsigned int)context->Workers.size()).c_str());
                ::DragAcceptFiles(hwnd, TRUE);
                InitializeListViewColumns(context->TaskList);
                UpdateSummary(context);
                return TRUE;
            }
            case WM_DROPFILES:
            {
                HDROP drop = (HDROP)wParam;
                UINT fileCount = ::DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0u);
                std::vector<std::wstring> paths;
                paths.reserve(fileCount);

                for (UINT index = 0; index < fileCount; ++index)
                {
                    wchar_t path[MaxUiPath]{};
                    if (::DragQueryFileW(drop, index, path, (UINT)_countof(path)) > 0u)
                    {
                        paths.emplace_back(path);
                    }
                }

                ::DragFinish(drop);
                AddPackageFiles(context, paths);
                UpdateSummary(context);
                return TRUE;
            }
            case WM_COMMAND:
            {
                switch (LOWORD(wParam))
                {
                    case IDC_AddFiles:
                        AddPackageFiles(context, BrowsePackageFiles(hwnd));
                        UpdateSummary(context);
                        return TRUE;
                    case IDC_BrowseOutput:
                    {
                        std::wstring folder = BrowseFolder(hwnd, L"选择解包输出目录");
                        if (!folder.empty())
                        {
                            ::SetWindowTextW(context->OutputEdit, folder.c_str());
                        }
                        return TRUE;
                    }
                    case IDC_ClearCompleted:
                        ClearFinishedTasks(context);
                        UpdateSummary(context);
                        return TRUE;
                }
                break;
            }
            case WM_APP_TASK_UPDATE:
            {
                TaskUpdateMessage* message = (TaskUpdateMessage*)lParam;
                if (message)
                {
                    int taskIndex = FindTaskIndex(context, message->TaskId);
                    if (taskIndex >= 0)
                    {
                        TaskRecord& task = context->Tasks[(size_t)taskIndex];
                        task.Current = message->Current;
                        task.Total = message->Total;
                        task.Detail = message->Detail;
                        task.LastTick = ::GetTickCount64();

                        switch ((Engine::ExtractTaskState)message->State)
                        {
                            case Engine::ExtractTaskPreparing:
                                task.State = UiTaskState::Preparing;
                                break;
                            case Engine::ExtractTaskIndexLoaded:
                                task.State = UiTaskState::IndexLoaded;
                                break;
                            case Engine::ExtractTaskExtracting:
                                task.State = UiTaskState::Extracting;
                                break;
                            case Engine::ExtractTaskCompleted:
                                task.State = UiTaskState::Completed;
                                task.Finished = true;
                                task.Succeeded = true;
                                break;
                            case Engine::ExtractTaskFailed:
                                task.State = UiTaskState::Failed;
                                task.Finished = true;
                                task.Succeeded = false;
                                break;
                            default:
                                task.State = UiTaskState::Queued;
                                break;
                        }

                        RefreshTaskRow(context, taskIndex);
                        WriteUiLog(context,
                                   L"Task update: #%u state=%u current=%u total=%u detail=%s",
                                   task.Id,
                                   message->State,
                                   message->Current,
                                   message->Total,
                                   message->Detail);
                    }

                    ::HeapFree(::GetProcessHeap(), 0, message);
                }
                UpdateSummary(context);
                return TRUE;
            }
            case WM_APP_WATCHDOG_TICK:
                UpdateSummary(context);
                return TRUE;
            case WM_CLOSE:
                ::DestroyWindow(hwnd);
                return TRUE;
            case WM_DESTROY:
                ::PostQuitMessage(0);
                return TRUE;
        }
        return FALSE;
    }
}

namespace UI
{
    DWORD WINAPI RunBatchExtractorUi(LPVOID parameter)
    {
        StartupContext startup = *(StartupContext*)parameter;

        INITCOMMONCONTROLSEX initControls{};
        initControls.dwSize = sizeof(initControls);
        initControls.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
        ::InitCommonControlsEx(&initControls);

        UiContext* context = new (std::nothrow) UiContext{};
        if (!context)
        {
            return 0u;
        }

        context->Startup = startup;
        context->QueueEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        context->StopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        context->WatchdogThread = nullptr;
        context->NextTaskId = 1u;
        context->ActiveWorkers = 0;
        context->CompletionNotified = false;
        ::InitializeCriticalSection(&context->QueueLock);
        ::InitializeCriticalSection(&context->LogLock);

        context->ModuleDirectory = GetDirectoryName(GetModulePath(startup.ModuleInstance));
        context->UiLogPath = CombinePath(context->ModuleDirectory, L"ExtractorUI.log");

        std::wstring gameDirectory = GetDirectoryName(GetModulePath(::GetModuleHandleW(nullptr)));
        context->DefaultOutputDirectory = CombinePath(gameDirectory, L"Extractor_Output");

        if (context->Startup.Api.SetExtractProgressCallback)
        {
            context->Startup.Api.SetExtractProgressCallback(ExtractProgressThunk, context);
        }

        unsigned int workerCount = ResolveWorkerCount();
        for (unsigned int index = 0u; index < workerCount; ++index)
        {
            HANDLE worker = ::CreateThread(nullptr, 0u, WorkerThreadProc, context, 0u, nullptr);
            if (worker)
            {
                context->Workers.push_back(worker);
            }
        }

        context->WatchdogThread = ::CreateThread(nullptr, 0u, WatchdogThreadProc, context, 0u, nullptr);

        WriteUiLog(context, L"Batch extractor UI started with %u workers", (unsigned int)context->Workers.size());

        HWND hwnd = ::CreateDialogParamW(startup.ModuleInstance,
                                         MAKEINTRESOURCEW(IDD_MainForm),
                                         nullptr,
                                         ExtractorDialogWindProc,
                                         (LPARAM)context);
        if (!hwnd)
        {
            WriteUiLog(context, L"CreateDialogParamW failed");
            if (context->Startup.Api.SetExtractProgressCallback)
            {
                context->Startup.Api.SetExtractProgressCallback(nullptr, nullptr);
            }
            ::SetEvent(context->StopEvent);
            if (context->QueueEvent)
            {
                ::SetEvent(context->QueueEvent);
            }

            for (HANDLE worker : context->Workers)
            {
                ::WaitForSingleObject(worker, INFINITE);
                ::CloseHandle(worker);
            }
            context->Workers.clear();

            if (context->WatchdogThread)
            {
                ::WaitForSingleObject(context->WatchdogThread, INFINITE);
                ::CloseHandle(context->WatchdogThread);
            }

            if (context->QueueEvent)
            {
                ::CloseHandle(context->QueueEvent);
            }
            if (context->StopEvent)
            {
                ::CloseHandle(context->StopEvent);
            }

            ::DeleteCriticalSection(&context->LogLock);
            ::DeleteCriticalSection(&context->QueueLock);
            delete context;
            return 0u;
        }
        ::ShowWindow(hwnd, SW_NORMAL);

        MSG msg{};
        while (BOOL ret = ::GetMessageW(&msg, nullptr, 0u, 0u))
        {
            if (ret == -1)
            {
                break;
            }

            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }

        if (context->Startup.Api.SetExtractProgressCallback)
        {
            context->Startup.Api.SetExtractProgressCallback(nullptr, nullptr);
        }

        ::SetEvent(context->StopEvent);
        if (context->QueueEvent)
        {
            ::SetEvent(context->QueueEvent);
        }

        for (HANDLE worker : context->Workers)
        {
            ::WaitForSingleObject(worker, INFINITE);
            ::CloseHandle(worker);
        }
        context->Workers.clear();

        if (context->WatchdogThread)
        {
            ::WaitForSingleObject(context->WatchdogThread, INFINITE);
            ::CloseHandle(context->WatchdogThread);
        }

        WriteUiLog(context, L"Batch extractor UI stopped");

        if (context->QueueEvent)
        {
            ::CloseHandle(context->QueueEvent);
        }
        if (context->StopEvent)
        {
            ::CloseHandle(context->StopEvent);
        }

        ::DeleteCriticalSection(&context->LogLock);
        ::DeleteCriticalSection(&context->QueueLock);
        delete context;
        return 0u;
    }
}
