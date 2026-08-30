#include <pch.h>
#include <windows.h>
//==========================================================
#pragma comment(linker, "/EXPORT:beNotified=original-NppExport.beNotified,@1")
#pragma comment(linker, "/EXPORT:getFuncsArray=original-NppExport.getFuncsArray,@2")
#pragma comment(linker, "/EXPORT:getName=original-NppExport.getName,@3")
#pragma comment(linker, "/EXPORT:isUnicode=original-NppExport.isUnicode,@4")
#pragma comment(linker, "/EXPORT:messageProc=original-NppExport.messageProc,@5")
#pragma comment(linker, "/EXPORT:setInfo=original-NppExport.setInfo,@6")
//==========================================================
//==========================================================
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        MessageBoxA(0, "DLL hijacking test", "DLL hijacking test", 0);
    }
    else if (dwReason == DLL_THREAD_ATTACH)
    {

    }
    else if (dwReason == DLL_THREAD_DETACH)
    {

    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {

    }
    return TRUE;
}