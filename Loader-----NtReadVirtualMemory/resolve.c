#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef enum   _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } ANSI_STRING, * PANSI_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* RtlUnicodeStringToAnsiStringFn)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);

NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
RtlUnicodeStringToAnsiStringFn RtlUnicodeStringToAnsiString;


// Read 8-bytes remotely: NtReadVirtualMemory
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


// Read Unicode string remotely: NtReadVirtualMemory + RtlUnicodeStringToAnsiString
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    // Read Unicode string
    if (!hProcess || !mem_address) {
        return (char*)"";
    }
    BYTE buff[512] = { 0 };
    SIZE_T bytesRead = 0;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) { // if (ntstatus != 0) {
        printf("[-] NtReadVirtualMemory failed (0x%X) at 0x%p\n", ntstatus, mem_address);
        return (char*)"<unknown>";
    }
    if (bytesRead < 2) {
        return (char*)"<unknown>";
    }

    // Convert wide char to multi-byte
    static char output[256];
    UNICODE_STRING uniStr;
    ANSI_STRING ansiStr;
    uniStr.Length = (USHORT)wcsnlen((wchar_t*)buff, 256) * sizeof(wchar_t);
    uniStr.MaximumLength = uniStr.Length + sizeof(wchar_t);
    uniStr.Buffer = (wchar_t*)buff;
    ansiStr.Length = 0;
    ansiStr.MaximumLength = sizeof(output);
    ansiStr.Buffer = output;
    NTSTATUS status = RtlUnicodeStringToAnsiString(&ansiStr, &uniStr, FALSE);
    if (status == 0) {
        if (ansiStr.Length < sizeof(output)) {
            output[ansiStr.Length] = '\0';
        }
        else {
            output[sizeof(output) - 1] = '\0';
        }
    }
    return output;
}


// Read remote 16-bytes address - NtReadVirtualMemory
uintptr_t ReadRemoteUintptr_t(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[16];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(uintptr_t), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteUintptr_t). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return 0;
    }

    uintptr_t value = *(uintptr_t*)buff;
    return value;
}


// Custom implementation for GetModuleHandle - NtQueryInformationProcess + NtReadVirtualMemory + RtlUnicodeStringToAnsiString
uintptr_t CustomGetModuleHandle(HANDLE hProcess, const char* dll_name) {
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;

    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
    if ((long long)ldr_adress == 0) {
        printf("[-] PEB structure is not readable.\n");
        exit(0);
    }
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    uintptr_t dll_base = (uintptr_t)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        dll_base = (uintptr_t)ReadRemoteUintptr_t(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);

        if (stricmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


// Custom implementation for GetProcAddress - NtReadVirtualMemory
void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    // printf("[*] CustomGetProcAddress called with pDosHdr = 0x%p, func_name = %s\n", pDosHdr, func_name);
    int exportrva_offset = 136;
    HANDLE hProcess = (HANDLE)-1;
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);

    if (e_lfanew_value == 0) {
        return NULL;
    }

    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    if (exportTableRVA_value != 0) {
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, strlen(func_name) + 1, &aux);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


void* get_ntdll_base_address(const char* input) {
    char full_address_str[32];
    int len = strlen(input);
    char prefix[32] = { 0 };
    strncpy(prefix, input, len - 6);
    prefix[len - 6] = '\0';

    char last6[7] = { 0 };
    strncpy(last6, input + len - 6, 6);

    unsigned int last6_val = (unsigned int)strtoul(last6, NULL, 16);
    unsigned int first_nibble = (last6_val >> 20) & 0xF;
    unsigned int second_nibble = (last6_val >> 16) & 0xF;
    unsigned int lower_16bits = 0;

    // Combinaciones con segundo nibble variando de 0x0 a 0xF con primer nibble fijo
    for (unsigned int i = 0; i <= 0xF; i++) {
        unsigned int new_val = (first_nibble << 20) | (i << 16) | lower_16bits;
        snprintf(full_address_str, sizeof(full_address_str), "%s%06X", prefix, new_val);
        // printf("%s\n", full_address_str);

        void* base_address_test = (void*)strtoull(full_address_str, NULL, 16);
        void* pFunc = CustomGetProcAddress(base_address_test, "NtClose");
        if (pFunc != NULL) {
            return base_address_test;
        }
    }

    // Now the second batch: first nibble decreased by 1
    // Combinaciones con segundo nibble variando de 0x0 a 0xF con primer nibble decrecido
    if (first_nibble > 0) {
        unsigned int prev_first_nibble = first_nibble - 1;

        for (unsigned int i = 0; i <= 0xF; i++) {
            unsigned int new_val = (prev_first_nibble << 20) | (i << 16) | lower_16bits;
            snprintf(full_address_str, sizeof(full_address_str), "%s%06X", prefix, new_val);
            // printf("%s\n", full_address_str);

            void* base_address_test = (void*)strtoull(full_address_str, NULL, 16);
            void* pFunc = CustomGetProcAddress(base_address_test, "NtClose");

            if (pFunc != NULL) {
                return base_address_test;
            }
        }
    }

    return NULL;
}


int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <ntrvm_addr> <dll_name> <function_name>\n", argv[0]);
        return 1;
    }

    // uintptr_t ntdll_address = (uintptr_t)strtoull(argv[1], NULL, 16);
    uintptr_t func_address = (uintptr_t)strtoull(argv[1], NULL, 16);

    NtReadVirtualMemory = (NtReadVirtualMemoryFn)func_address;
    HMODULE hNtdll = (HMODULE)get_ntdll_base_address(argv[1]);
    printf("[+] Ntdll.dll Address:\t0x%p\n", hNtdll);

    if (stricmp(argv[2], "ntdll.dll") == 0) {
        const char* func_name = argv[3];

        void* pFunc = CustomGetProcAddress(hNtdll, func_name);
        printf("[+] NTAPI address: \t0x%p\n", pFunc);
    }

    else {
        const char* dll_name = argv[2];
        const char* func_name = argv[3];

        NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
        RtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiStringFn)CustomGetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
        HANDLE currentProcess = (HANDLE)(-1);
        uintptr_t hDLL = CustomGetModuleHandle(currentProcess, dll_name);
        void* pFunction = CustomGetProcAddress(hDLL, func_name);
        printf("[+] DLL Address: \t0x%p\n", hDLL);
        printf("[+] Function Address: \t0x%p\n", pFunction);
    }

    FreeLibrary(hNtdll);
    return 0;
}