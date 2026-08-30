#include <windows.h>
#include <stdio.h>

typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

int main()
{
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32)
    {
        hUser32 = LoadLibraryW(L"user32.dll");
        if (!hUser32)
        {
            printf("Failed to load user32.dll !!!\n");
            return -1;
        }
    }
    MESSAGEBOXW pMessageBoxW = (MESSAGEBOXW)GetProcAddress(hUser32, "MessageBoxW");
    if (!pMessageBoxW)
    {
        printf("Failed to get MessageBoxW address !!!\n");
        return -1;
    }
    else
    {
        pMessageBoxW(NULL, L"Windows API Dynamic Call", L"Title", MB_OK | MB_ICONINFORMATION);
    }
    
    return 0;
}