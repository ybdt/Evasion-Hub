@echo off
cd /d %~dp0
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
echo [*] Building vss_simple_freeze.exe (x64) ...
cl.exe /nologo /O2 /W3 /EHsc /Fe:vss_simple_freeze.exe vss_simple_freeze.cpp ^
    /link /SUBSYSTEM:CONSOLE ntdll.lib Rpcrt4.lib Shlwapi.lib CldApi.lib advapi32.lib user32.lib
if errorlevel 1 (
    echo [-] Build failed.
    exit /b 1
)
echo [+] vss_simple_freeze.exe OK
