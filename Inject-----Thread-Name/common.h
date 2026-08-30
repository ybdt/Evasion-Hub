#pragma once

#include <windows.h>

HANDLE open_process(DWORD processId);

HANDLE find_thread(HANDLE hProcess, DWORD min_access);

HANDLE create_alertable_thread(HANDLE hProcess);

void* get_peb_unused(HANDLE hProcess);

void* pass_via_thread_name(HANDLE hProcess, const BYTE* buf, size_t buf_size, const void* remotePtr);
