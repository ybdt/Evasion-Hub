#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

// get pid by process name
DWORD GetPidByName(const wchar_t* processName) {
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

// Confirm PPID Spoof
void PPIDSpoofConfirm(DWORD parentPid, PROCESS_INFORMATION pi) {
    // undocumented API, need define manually
    typedef struct _MY_PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;  // get real parent pid from this field
    } MY_PROCESS_BASIC_INFORMATION;

    // undocumented API, need defiine manually
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,  // the prototype of this field is PROCESSINFOCLASS, it's a Enum, use ULONG avoid type check
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    MY_PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQueryInfo) {
            NTSTATUS status = NtQueryInfo(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLength);
            if (status == 0) {
                std::cout << "\n--- Confirm from Windows Kernel ---\n";
                printf("Process PID: %zu\n", (size_t)pbi.UniqueProcessId);
                printf("Parent process PID: %zu\n", (size_t)pbi.InheritedFromUniqueProcessId);
                if (pbi.InheritedFromUniqueProcessId == parentPid) {
                    printf("Query NtQueryInformationProcess show the parent pid is the spoofed pid.\n");
                }
                else {
                    printf("Query NtQueryInformationProcess show the parent pid is not the spoofed pid.\n");
                }
            }
            else {
                printf("NtQueryInformationProcess failed, error code: 0x%X\n", status);
            }
        }
    }
}

int main() {
    // find the pid of process
    DWORD parentPid = GetPidByName(L"code.exe");
    if (parentPid == 0) {
        std::cout << "Please run Visual Studio Code.exe first !!!\n";
        return 1;
    }

    // open parent process and get handle, need PROCESS_CREATE_PROCESS privilege
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (hParent == NULL) return 1;

    // initialize startupinfoex
    STARTUPINFOEXW siex = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize;
    // first call, get attribute list size
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    siex.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    // second call, initialize attribute list
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attributeSize);
    // update attribute list, set parent handle
    UpdateProcThreadAttribute(
        siex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent,
        sizeof(HANDLE),
        NULL,
        NULL
    );
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    // use EXTENDED_STARTUPINFO_PRESENT to enable extended function
    BOOL success = CreateProcessW(
        L"C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &siex.StartupInfo,
        &pi
    );
    if (success) {
        std::cout << "Cmd.exe has started, pid: " << pi.dwProcessId << ", and spoofed parent process pid: " << parentPid << "\n";

        // check ppid spoof
        PPIDSpoofConfirm(parentPid, pi);

        // ensure parent process PPID-Spoof.exe not exist
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cout << "process create failed, error code: " << GetLastError();
    }

    // cleanup
    DeleteProcThreadAttributeList(siex.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
    CloseHandle(hParent);

    system("pause");

    return 0;
}