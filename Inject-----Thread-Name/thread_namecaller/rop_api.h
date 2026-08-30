#pragma once
#include <Windows.h>
#include "../ntdll_wrappers.h"
#include <iostream>

#define WAIT_UNIT 1000
#define TIMEOUT (30 * WAIT_UNIT)

ULONG_PTR EBFE_VA = NULL;

// search the ROP gadgets:

BYTE* find_pattern(BYTE* sec_start, size_t sec_size, BYTE* pattern, size_t pattern_size)
{
	if (!sec_start || (sec_size < pattern_size)) return NULL;

	for (size_t i = 0; i < sec_size; i++) {

		if (pattern_size > (sec_size - i)) return NULL;
		BYTE* ptr = sec_start + i;
		if (::memcmp(ptr, pattern, pattern_size) == 0) {
			return ptr;
		}
	}
	return NULL;
}

LPVOID find_rop_gadget(LPSTR moduleName, BYTE* pattern, size_t pattern_size)
{
	HANDLE mod = GetModuleHandleA(moduleName);
	if (!mod) {
		return NULL;
	}
	//get header
	IMAGE_DOS_HEADER* DOSHeader = PIMAGE_DOS_HEADER(mod);
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS((char*)(mod)+DOSHeader->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	if (!section) return NULL;

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && section[i].VirtualAddress && section[i].Misc.VirtualSize) {
			BYTE* ptr = find_pattern((BYTE*)(mod)+section[i].VirtualAddress, section[i].Misc.VirtualSize, pattern, pattern_size);
			if (ptr) return ptr;
		}
	}
	return NULL;
}

size_t find_NtdllFunctionEndings(LPSTR funcName, DWORD64 funcRets[], size_t maxRets)
{
	BYTE ret_pattern[] = { 0xc3 };
	FARPROC funcStart = GetProcAddress(GetModuleHandle("ntdll.dll"), funcName);
	if (!funcStart) return 0;

	size_t i = 0;
	ULONG_PTR start = (ULONG_PTR)funcStart;
	for (i = 0; i < maxRets; i++) {
		void* func_ret = find_pattern((BYTE*)start, 0x100, ret_pattern, sizeof(ret_pattern));
		if (!func_ret) {
			std::cerr << "Pattern not found\n";
			return 0;
		}
		funcRets[i] = (DWORD64)func_ret;
		start = (ULONG_PTR)func_ret + 1;
#ifdef _DEBUG
		std::cerr << "Pattern found #:" << std::dec << i << " : " << std::hex << func_ret << "\n";
#endif
	}
	return i;
}


// manipulate the context:

bool contains(DWORD64 list[], SIZE_T listSize, DWORD64 searchedVal)
{
	if (!list || !listSize) return false;

	for (size_t i = 0; i < listSize; i++) {
		if (list[i] == searchedVal) return true;
	}
	return false;
}

bool wait_for_execution(HANDLE hThread, DWORD64 desiredRipList[], SIZE_T desiredRipListSize, DWORD64* result, const DWORD timeout)
{
	if (!desiredRipList || !desiredRipListSize) return false;

	DWORD attempts = 0;
	const DWORD wait_unit = WAIT_UNIT;

	bool isExecuted = false;
	// wait for context to change:
	while ((timeout == INFINITE) || (wait_unit * attempts) < timeout) {

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		if (!GetThreadContext(hThread, &ctx)) {
			std::cerr << "Failed to get context!\n";
			return false;
		}
		// after the function finished, it should return to the infinite loop...
		if (contains(desiredRipList, desiredRipListSize, ctx.Rip)) {
			isExecuted = true;
			if (result) (*result) = ctx.Rax;
#ifdef _DEBUG
			std::cout << "Executed! Registers: "
				<< std::hex
				<< "RIP: " << ctx.Rip
				<< " RAX: " << ctx.Rax
				<< " RCX: " << ctx.Rcx
				<< " RDX: " << ctx.Rdx
				<< " R8: " << ctx.R8
				<< " R9: " << ctx.R9
				<< std::endl;
#endif
			break;
		}
		Sleep(wait_unit);
		attempts++;

	}
	if (isExecuted) {
		std::cout << "Executed in: " << std::dec << attempts << " attempts\n";
	}
	return isExecuted;
}

bool wait_for_execution(HANDLE hThread, DWORD64 desiredRip, DWORD64* result, const DWORD timeout)
{
	return wait_for_execution(hThread, &desiredRip, 1, result, timeout);
}

bool set_context(HANDLE hThread, CONTEXT& dest_context)
{
	bool isOk = false;
	SuspendThread(hThread);
	if (SetThreadContext(hThread, &dest_context)) {
		isOk = true;
	}
	ResumeThread(hThread);
	return isOk;
}

bool execute_context(HANDLE hThread, CONTEXT* storedContext, LPVOID func, LPVOID stack, DWORD64* arg0, DWORD64* arg1, DWORD64* arg2, DWORD64* arg3, DWORD64* result)
{
	SuspendThread(hThread);
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &context)) {
		return false;
	}
	if (storedContext) {
		::memcpy(storedContext, &context, sizeof(CONTEXT));
	}
#ifdef _DEBUG
	std::cout << "Context retrieved!\n";
#endif
	bool isOk = false;

	if (context.Rip != (DWORD64)EBFE_VA) {
		// set the return address to EBFE_VA:
		context.Rsp = (DWORD64)stack;
		if (SetThreadContext(hThread, &context)) {
#ifdef _DEBUG
			std::cout << "Context set! Stack: " << std::hex << stack << "\n";
#endif
			isOk = true;
		}
		ResumeThread(hThread);

		if (!isOk || !wait_for_execution(hThread, EBFE_VA, nullptr, TIMEOUT)) {
			return false;
		}
		std::cout << "Thread redirected to the infinite loop...\n";
		SuspendThread(hThread);
	}
	std::cout << "Thread waiting...\n";

	context.Rip = (DWORD64)func;
	context.Rsp = (DWORD64)stack;

	//arguments for the next function:
	if (arg0) context.Rcx = *arg0;
	if (arg1) context.Rdx = *arg1;
	if (arg2) context.R8 = *arg2;
	if (arg3) context.R9 = *arg3;

	if (SetThreadContext(hThread, &context)) {
#ifdef _DEBUG
		std::cout << "Context set!\n";
#endif
		isOk = true;
	}
	ResumeThread(hThread);
	if (!isOk) {
		return false;
	}
	return wait_for_execution(hThread, EBFE_VA, result, TIMEOUT);
}

bool init_gadgets()
{
	BYTE pattern[] = { 0xEB, 0xFE };
	LPVOID pos = find_rop_gadget("ntdll", pattern, sizeof(pattern));
	if (!pos) {
		std::cout << "Gadget NOT found\n";
		return false;
	}

	EBFE_VA = (ULONG_PTR)pos;
	return true;
}

bool set_thread_sleep(HANDLE hThread, DWORD sleepTime, size_t timeout = INFINITE)
{
	if (sleepTime < WAIT_UNIT) {
		sleepTime = WAIT_UNIT * 2;
	}

	DWORD64 NtDelayExecution_rets[2] = { 0 };
	size_t patternsCount = find_NtdllFunctionEndings("NtDelayExecution", NtDelayExecution_rets, 2);
	if (!patternsCount) {
		std::cout << "Patterns not found!\n";
		return false;
	}
	if (!queue_apc_thread(hThread, (void*)Sleep, (void*)sleepTime)) {
		std::cout << "Apc failed!\n";
		return false;
	}

	std::cout << "Sleep requested!\n";
	if (!wait_for_execution(hThread, NtDelayExecution_rets, patternsCount, nullptr, timeout)) {
		std::cerr << "Timeout passed!\n";
		return false;
	}
	return true;
}


//---
// Remote API

BOOL
WINAPI
remote_VirtualProtect(
	_In_ HANDLE hThread,
	LPVOID data,
	CONTEXT* storedContext,
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD flNewProtect,
	_In_ PDWORD lpflOldProtect
)
{
	FARPROC _VirtualProtect = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualProtect");
	CONTEXT context = { 0 };
	//arguments for the next function:
	context.Rcx = (DWORD64)lpAddress; //lpAddress
	context.Rdx = (DWORD64)dwSize; //dwSize
	context.R8 = (DWORD64)flNewProtect; //flNewProtect
	context.R9 = (DWORD64)lpflOldProtect; //lpflOldProtect

	DWORD64 result = 0;
	if (!execute_context(hThread, storedContext, _VirtualProtect, data, &context.Rcx, &context.Rdx, &context.R8, &context.R9, &result)) {
		return FALSE;
	}
	return (BOOL)result;
}

LPVOID
WINAPI
remote_VirtualAlloc(
	_In_ HANDLE hThread,
	LPVOID data,
	CONTEXT* storedContext,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
)
{
	FARPROC _VirtualAlloc = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualAlloc");
	CONTEXT context = { 0 };
	//arguments for the next function:
	context.Rcx = (DWORD64)lpAddress; //lpAddress
	context.Rdx = (DWORD64)dwSize; //dwSize
	context.R8 = (DWORD64)flAllocationType;
	context.R9 = (DWORD64)flProtect;

	DWORD64 result = NULL;
	if (!execute_context(hThread, storedContext, _VirtualAlloc, data, &context.Rcx, &context.Rdx, &context.R8, &context.R9, &result)) {
		return NULL;
	}
	return (LPVOID)result;
}
