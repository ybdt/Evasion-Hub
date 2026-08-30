#include "common.h"
#include "ntdll_undoc.h"
#include "ntdll_wrappers.h"

#include <processthreadsapi.h>
#include <TlHelp32.h>

#include <iostream>
#include <vector>

#ifdef USE_OLD_APC_API
#include "check_alertable.h"
#endif

HANDLE open_process(DWORD processId)
{
	DWORD access = PROCESS_QUERY_LIMITED_INFORMATION // required for reading the PEB address
		| PROCESS_VM_READ // required for reading back the pointer to the created buffer
		;
#ifndef USE_ROP
		access |= PROCESS_VM_OPERATION; // to set memory area executable and/or allocate a new executable memory
#endif
#ifdef USE_OLD_APC_API
		access |= PROCESS_DUP_HANDLE; // to search for alertable threads (using events)
#endif
#ifdef USE_NEW_THREADS
		access |= PROCESS_CREATE_THREAD; // to create a new thread where we can pass APC
#endif
	return OpenProcess(access, FALSE, processId);
}

HANDLE open_thread_from_list(std::vector<DWORD>& threads, DWORD access)
{
	for (auto itr = threads.begin(); itr != threads.end(); ++itr) {
		DWORD threadId = *itr;
		HANDLE hThread = OpenThread(access, FALSE, threadId);
		if (!hThread || hThread == INVALID_HANDLE_VALUE) {
			continue;
		}
		std::cout << "Using thread TID=" << std::dec << threadId << std::endl;
		return hThread;
	}
	return NULL;
}

size_t list_threads(HANDLE hProcess, std::vector<DWORD> &threads)
{
	DWORD targetPid = GetProcessId(hProcess);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 thEntry = { sizeof(THREADENTRY32) };

	GUITHREADINFO gui = { 0 };
	gui.cbSize = sizeof(GUITHREADINFO);

	if (Thread32First(snapshot, &thEntry)) {
		do {
			if (thEntry.th32OwnerProcessID == targetPid) {
				threads.push_back(thEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &thEntry));
	}
	CloseHandle(snapshot);
	return threads.size();
}

HANDLE find_thread(HANDLE hProcess, DWORD min_access)
{
	std::vector<DWORD> threads;
	if (!list_threads(hProcess, threads)) {
		return NULL;
	}
	HANDLE hThread = NULL;
#ifdef USE_OLD_APC_API
	hThread = find_alertable_by_event(hProcess, threads);
#else
	hThread = open_thread_from_list(threads, SYNCHRONIZE | min_access);
#endif
	return hThread;
}

HANDLE create_alertable_thread(HANDLE hProcess)
{
	DWORD thAccess = SYNCHRONIZE | THREAD_ALL_ACCESS;
	auto pNtCreateThreadEx = reinterpret_cast<decltype(&NtCreateThreadEx)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
	if (pNtCreateThreadEx == NULL)
	{
		return NULL;
	}
	HANDLE hThread2 = INVALID_HANDLE_VALUE;
	if (pNtCreateThreadEx(&hThread2, thAccess, NULL, hProcess, (LPVOID)Sleep, (LPVOID)10, NT_CREATE_THREAD_EX_SUSPENDED, NULL, 0, 0, NULL) != 0) {
		return NULL;
	}
	return hThread2;
}

void* read_remote_ptr(HANDLE hProcess2, const void* remotePtr, bool& isRead)
{
	void* wPtr = nullptr;
	if (!read_remote(hProcess2, remotePtr, &wPtr, sizeof(void*))) {
		std::cerr << "Failed to read remote address!\n";
		isRead = false;
		return nullptr;
	}
	isRead = true;
	return wPtr;
}

ULONG_PTR remote_peb_addr(IN HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pi = { 0 };
	DWORD ReturnLength = 0;

	auto pNtQueryInformationProcess = reinterpret_cast<decltype(&NtQueryInformationProcess)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess"));
	if (!pNtQueryInformationProcess) {
		return NULL;
	}
	NTSTATUS status = pNtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&ReturnLength
	);
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtQueryInformationProcess failed" << std::endl;
		return NULL;
	}
	return (ULONG_PTR)pi.PebBaseAddress;
}

void* get_peb_unused(HANDLE hProcess)
{
	ULONG_PTR peb_addr = remote_peb_addr(hProcess);
	if (!peb_addr) {
		std::cerr << "Cannot retrieve PEB address!\n";
		return nullptr;
	}
	const ULONG_PTR UNUSED_OFFSET = 0x340;
	const ULONG_PTR remotePtr = peb_addr + UNUSED_OFFSET;
	return (void*)remotePtr;
}

void* pass_via_thread_name(HANDLE hProcess, const BYTE* buf, size_t buf_size, const void* remotePtr)
{
	if (!remotePtr) {
		std::cerr << "Return pointer not set!\n";
		return nullptr;
	}

#ifdef USE_NEW_THREADS
	HANDLE hThread = create_alertable_thread(hProcess);
#else
	DWORD access = SYNCHRONIZE;
	access |= THREAD_SET_CONTEXT; // required for the APC queue
	access |= THREAD_SET_LIMITED_INFORMATION; // required for setting thread description

	HANDLE hThread = find_thread(hProcess, access);
#endif

	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		std::cerr << "Invalid thread handle!\n";
		return nullptr;
	}
#ifdef USE_DEFAULT_SET_THREAD_DESC
	std::cout << "WARNING: Using default SetThreadDescription: the buffer must not have double NULL bytes!\n";
	HRESULT hr = SetThreadDescription(hThread, (PCWSTR)buf);
#else
	HRESULT hr = mySetThreadDescription(hThread, buf, buf_size);
#endif
	if (FAILED(hr)) {
		std::cout << "Failed to set thread desc" << std::endl;
		return nullptr;
	}
	if (!queue_apc_thread(hThread, GetThreadDescription, (void*)NtCurrentThread(), (void*)remotePtr, 0)) {
		CloseHandle(hThread);
		return nullptr;
	}

#ifdef USE_NEW_THREADS
	ResumeThread(hThread);
#endif
	// close thread handle
	CloseHandle(hThread);

	void* wPtr = nullptr;
	bool isRead = false;
	while ((wPtr = read_remote_ptr(hProcess, remotePtr, isRead)) == nullptr) {
		if (!isRead) return nullptr;
		Sleep(1000); // waiting for the pointer to be written;
	}
	std::cout << "Written to the Thread\n";
	return wPtr;
}
