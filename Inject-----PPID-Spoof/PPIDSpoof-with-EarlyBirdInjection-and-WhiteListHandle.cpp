#include <Windows.h>
#include <stdio.h>

int main() {
    // 资源定义
    HANDLE hSecretFile = INVALID_HANDLE_VALUE;
    HANDLE hPublicFile = INVALID_HANDLE_VALUE;
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    SIZE_T attributeSize = 0;
    STARTUPINFOEXA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 安全属性：允许句柄被继承
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    do {
        // 1. 创建第一个文件：秘密文件 (我们不想让子进程关联到这个)
        hSecretFile = CreateFileA("secret.txt", GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hSecretFile == INVALID_HANDLE_VALUE) break;
        WriteFile(hSecretFile, "This is secret data", 19, NULL, NULL);
        printf("[+] 秘密文件句柄已创建: %p\n", hSecretFile);

        // 2. 创建第二个文件：公共文件 (只允许继承这个)
        hPublicFile = CreateFileA("public.txt", GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hPublicFile == INVALID_HANDLE_VALUE) break;
        printf("[+] 公共文件句柄已创建: %p\n", hPublicFile);

        // 3. 初始化属性列表：准备白名单
        // 我们只打算把 hPublicFile 放入白名单
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        if (!lpAttributeList) break;
        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize)) break;

        // 4. 【核心点】：设置 PROC_THREAD_ATTRIBUTE_HANDLE_LIST 
        // 只有出现在这个数组里的句柄才会被子进程继承
        HANDLE hInheritList[] = { hPublicFile };
        if (!UpdateProcThreadAttribute(
            lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            hInheritList,
            sizeof(hInheritList),
            NULL,
            NULL)) {
            printf("[-] 无法更新属性列表: %d\n", GetLastError());
            break;
        }
        si.lpAttributeList = lpAttributeList;

        // 5. 创建子进程
        // 注意：bInheritHandles 必须为 TRUE，否则属性列表中的句柄设置无效
        printf("[*] 正在启动子进程 (cmd.exe)...\n");
        if (!CreateProcessA(
            NULL,
            (LPSTR)"C:\\Windows\\System32\\cmd.exe /c \"timeout 120\"",
            NULL,
            NULL,
            TRUE, // 必须为 TRUE
            EXTENDED_STARTUPINFO_PRESENT,
            NULL,
            NULL,
            &si.StartupInfo,
            &pi)) {
            printf("[-] 进程创建失败: %d\n", GetLastError());
            break;
        }

        printf("[+] 子进程 PID: %d 已启动\n", pi.dwProcessId);
        printf("[!] 现在请使用 Process Hacker 或 Handle.exe 查看子进程的句柄表。\n");
        printf("[!] 你会发现子进程只继承了 public.txt 的句柄，而没有 secret.txt。\n");

        // 等待子进程结束
        WaitForSingleObject(pi.hProcess, INFINITE);

    } while (0);

    // 清理
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (hSecretFile != INVALID_HANDLE_VALUE) CloseHandle(hSecretFile);
    if (hPublicFile != INVALID_HANDLE_VALUE) CloseHandle(hPublicFile);
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }

    return 0;
}