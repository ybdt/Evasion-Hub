#include "ntdll_wrappers.h"

#include "ntddk.h"
#include "ntdll_undoc.h"

#include <iostream>

HRESULT mySetThreadDescription(HANDLE hThread, const BYTE* buf, size_t buf_size)
{
	UNICODE_STRING DestinationString = { 0 };
	BYTE* padding = (BYTE*)::calloc(buf_size + sizeof(WCHAR), 1);
	::memset(padding, 'A', buf_size);

	auto pRtlInitUnicodeStringEx = reinterpret_cast<decltype(&RtlInitUnicodeStringEx)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlInitUnicodeStringEx"));
	pRtlInitUnicodeStringEx(&DestinationString, (PCWSTR)padding);
	// fill with our real content:
	::memcpy(DestinationString.Buffer, buf, buf_size);

	auto pNtSetInformationThread = reinterpret_cast<decltype(&NtSetInformationThread)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationThread"));
	NTSTATUS status = pNtSetInformationThread(hThread, (THREADINFOCLASS)ThreadNameInformation, &DestinationString, sizeof(UNICODE_STRING));
	::free(padding);
	return HRESULT_FROM_NT(status);
}


bool read_remote(HANDLE hProcess, IN const void* remote_addr, OUT void* buffer, size_t buffer_size)
{
	if (!buffer || !buffer_size) return false;

	::memset(buffer, 0, buffer_size);
	auto pNtReadVirtualMemory = reinterpret_cast<decltype(&NtReadVirtualMemory)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtReadVirtualMemory"));
	if (pNtReadVirtualMemory == NULL)
	{
		return false;
	}
	SIZE_T read_size = 0;
	NTSTATUS status = pNtReadVirtualMemory(hProcess, (PVOID)remote_addr, buffer, buffer_size, &read_size);
	if (status != STATUS_SUCCESS || read_size != buffer_size)
	{
		std::cerr << "Cannot read remote address: " << GetLastError() << std::endl;
		return false;
	}
	return true;
}

bool _NtQueueApcThreadEx2(HANDLE hThread, void* func, void* arg0, void* arg1, void* arg2)
{
	auto pZwQueueApcThreadEx2 = reinterpret_cast<decltype(&NtQueueApcThreadEx2)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueueApcThreadEx2"));
	if (pZwQueueApcThreadEx2 == NULL)
	{
		std::cout << "API not found: NtQueueApcThreadEx2\n";
		return false;
	}
	std::cout << "Using NtQueueApcThreadEx2...\n";
	if (pZwQueueApcThreadEx2(hThread, nullptr, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, func, (void*)arg0, (void*)arg1, arg2) != NT_SUCCESS) {
		return false;
	}
	return true;
}

bool _NtQueueApcThread(HANDLE hThread, void* func, void* arg0, void* arg1, void* arg2)
{
	auto pNtQueueApcThread = reinterpret_cast<decltype(&NtQueueApcThread)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueueApcThread"));
	if (pNtQueueApcThread == NULL)
	{
		return false;
	}
	std::cout << "Using NtQueueApcThread...\n";
	if (pNtQueueApcThread(hThread, func, (void*)arg0, (void*)arg1, arg2) != 0) {
		return false;
	}
	return true;
}

bool queue_apc_thread(HANDLE hThread, void* func, void* arg0, void* arg1, void* arg2)
{
#ifdef USE_OLD_APC_API
	return _NtQueueApcThread(hThread, func, arg0, arg1, arg2);
#else
	return _NtQueueApcThreadEx2(hThread, func, arg0, arg1, arg2);
#endif
}
