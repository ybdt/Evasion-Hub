#pragma once
#include <windows.h>

bool read_remote(HANDLE hProcess, IN const void* remote_addr, OUT void* buffer, size_t buffer_size);

bool queue_apc_thread(HANDLE hThread, void* func, void* arg0 = NULL, void* arg1 = NULL, void* arg2 = NULL);

HRESULT mySetThreadDescription(HANDLE hThread, const BYTE* buf, size_t buf_size);
