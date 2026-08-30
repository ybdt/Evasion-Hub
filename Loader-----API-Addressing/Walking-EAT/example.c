#include <stdio.h>

#include "resolve.h"

// Our typedefs
typedef INT(WINAPI *_MessageBox)(HWND, LPCSTR, LPCSTR, UINT);
typedef BOOL(WINAPI *_Beep)(DWORD, DWORD);

int main(int argc, char** argv)
{
	RESOLVE_TABLE rtExampleTbl = {
		{
			{0x8B2A35F2, L"user32.dll", NULL},   // MessageBoxA
			{0xBE01F6EF, L"kernel32.dll", NULL}, // Beep
			{0xDEADBEEF, L"ntdll.dll", NULL}	 // RtlCreateUserThread
		}
	};

	// resolve a single entry using resolve_find
	if (resolve_find(&rtExampleTbl.reEntries[0]))
	{
		_MessageBox MessageBoxA = (_MessageBox)rtExampleTbl.reEntries[0].lpAddr;
		MessageBoxA(NULL, "Title", "Body", MB_OKCANCEL);
	}

	// resolve the entire table
	if (resolve_init(&rtExampleTbl, 2))
	{
		_Beep pBeep = (_Beep)rtExampleTbl.reEntries[1].lpAddr;
		pBeep(750, 500);
	}

	// create a hash for RtlCreateUserThread
	UINT32 u32Hash = 0;
	if ((u32Hash = resolve_hash_name("RtlCreateUserThread")) != 0)
	{
		printf("RtlCreateUserThread: 0x%X\n", u32Hash);
	}

	getchar();
}
