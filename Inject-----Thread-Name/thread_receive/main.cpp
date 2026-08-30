#include <windows.h>
#include <psapi.h>
#include <subauth.h> // for UNICODE_STRING
#include <iostream>

bool create_attributes(STARTUPINFOEX& siex)
{
    memset(&siex, 0, sizeof(STARTUPINFOEX));
    siex.StartupInfo.cb = sizeof(STARTUPINFOEX);

    SIZE_T cbAttributeListSize = 0;
    DWORD64 MitgFlags = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON
#ifndef USE_ROP
        | PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
#endif
        | PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
        | PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON
        ;

    // turn off the MITIGATION_POLICY CFG for child process
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);// cannot be used to check return error -> MSDN (This initial call will return an error by design. This is expected behavior.)
    if (!cbAttributeListSize)
    {
        std::cerr << "[ERROR] InitializeProcThreadAttributeList failed to get the necessary size of the attribute list, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(cbAttributeListSize);
    if (!siex.lpAttributeList)
    {
        std::cerr << "[ERROR] Malloc failed to allocate memory for attribute list, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }

    if (!InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &cbAttributeListSize))
    {
        std::cerr << "[ERROR] InitializeProcThreadAttributeList failed to initialize the attribute list, Error = " << std::hex << GetLastError() << "\n";
        free(siex.lpAttributeList);
        siex.lpAttributeList = NULL;
        return false;
    }

    if (!UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &MitgFlags, sizeof(DWORD64), NULL, NULL))
    {
        std::cerr << "[ERROR] UpdateProcThreadAttribute failed, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }
    return true;
}

void free_attributes(STARTUPINFOEX& siex)
{
    if (siex.lpAttributeList) {
        DeleteProcThreadAttributeList(siex.lpAttributeList);
        free(siex.lpAttributeList);
        siex.lpAttributeList = NULL;
    }
}

bool restart_updated(IN const char* path)
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOEX siex = { 0 };
    LPSTARTUPINFO siex_ptr = NULL;
    DWORD process_flags = EXTENDED_STARTUPINFO_PRESENT;
    if (!create_attributes(siex)) {
        free_attributes(siex);
        return false;
    }
    siex_ptr = (LPSTARTUPINFO)&siex;

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    std::cout << "Trying to start application: " << path << "\n";

    if (!CreateProcessA(
        path,
        NULL,
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        process_flags, //dwCreationFlags
        NULL, //lpEnvironment 
        NULL, //lpCurrentDirectory
        siex_ptr, //lpStartupInfo
        &pi //lpProcessInformation
    ))
    {
        std::cerr << "[ERROR] CreateProcess failed, Error = " << std::hex << GetLastError() << "\n";
        return false;
    }
    free_attributes(siex);
    return true;
}

int main(int argc, char* argv[])
{
    char lpImageFileName[MAX_PATH] = { 0 };
    DWORD res = GetProcessImageFileNameA(
        GetCurrentProcess(),
        lpImageFileName,
        MAX_PATH
    );
    char my_name[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, my_name, MAX_PATH);
    
    char expected_val[] = "restarted";
    char env_str[100] = { 0 };
    if (!GetEnvironmentVariableA("RES", env_str, 100) || strcmp(env_str, expected_val)) {
        std::cout << "Restarting...\n";
        SetEnvironmentVariableA("RES", expected_val);
        return restart_updated(my_name);
    }
    std::cout << "PID: " << std::dec << GetCurrentProcessId() << std::endl;
    while (true) {
        std::cout << "Waiting...\n";
        SleepEx(1000, true);
    }
    system("pause");
    return 0;
}
