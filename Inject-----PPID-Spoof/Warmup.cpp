#include <Windows.h>
#include <iostream>

int main()
{
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    BOOL success = CreateProcess(
        L"C:\\Windows\\System32\\cmd.exe",  // full path pe file name
        NULL,  // command line argument
        NULL,  // process security attribute
        NULL,  // thread security attribute
        FALSE,  // if inherit handle
        NULL,  // create flag, CREATE_NEW_CONSOLE ensure popup new window
        NULL,  // environment variable
        NULL,  // current directory
        &si,  // the pointer of STARTUPINFO or STARTUPINFOEX
        &pi  // the pointer of PROCESS_INFORMATION
    );

    if (success)
    {
        std::cout << "cmd has started，PID: \n" << pi.dwProcessId;
        WaitForSingleObject(pi.hProcess, INFINITE);  // ensure parent process PPID-Spoof.exe not exist
        // system("pause");  // ensure parent process PPID-Spoof.exe not exist
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        std::cout << "process create failed, error code: " << GetLastError();
    }

    return 0;
}