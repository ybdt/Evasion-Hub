#pragma once

#include <Windows.h>

#define RESOLVE_NAME_MAX 4096
#define RESOLVE_REL_CALC(x,y) ((LPBYTE)x + y)

typedef struct RESOLVE_ENTRY {
	CONST UINT32 u32Hash;
	LPCWSTR cszwMod;
	PVOID lpAddr;
} RESOLVE_ENTRY, *PRESOLVE_ENTRY;

typedef struct RESOLVE_TABLE {
	RESOLVE_ENTRY reEntries[];
} RESOLVE_TABLE, *PRESOLVE_TABLE;

BOOL resolve_find(PRESOLVE_ENTRY pEntry);
BOOL resolve_init(PRESOLVE_TABLE pTbl, SIZE_T uCount);
UINT32 resolve_hash_name(LPCSTR cszName);
