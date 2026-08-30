#pragma once
#include <windows.h>
#include <vector>

// Required hProcess with PROCESS_DUP_HANDLE privilege
HANDLE find_alertable_by_event(HANDLE hProcess, std::vector<DWORD>& threads);

