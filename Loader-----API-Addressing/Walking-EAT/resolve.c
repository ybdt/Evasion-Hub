#include "resolve.h"

/*
	resolve_hash_name
	uses the SuperFastHash algorithm to create an unsigned 32-bit hash
*/
UINT32 resolve_hash_name(LPCSTR cszName)
{
	if (cszName == NULL)
	{
		return 0;
	}

	SIZE_T uNameLen = strnlen_s(cszName, RESOLVE_NAME_MAX);
	if (uNameLen == 0)
	{
		return 0;
	}

	UINT32 u32Hash = 0, u32Buf = 0;
	PBYTE pbData = (PBYTE)cszName;
	INT iRemain = (uNameLen & 3);

	uNameLen >>= 2;

	for (SIZE_T i = uNameLen; i > 0; i--)
	{
		u32Hash += *(const UINT16*)pbData;
		u32Buf = (*(const UINT16*)(pbData + 2) << 11) ^ u32Hash;
		u32Hash = (u32Hash << 16) ^ u32Buf;
		pbData += (2 * sizeof(UINT16));
		u32Hash += u32Hash >> 11;
	}

	switch (iRemain)
	{
		case 1:
			u32Hash += *pbData;
			u32Hash ^= u32Hash << 10;
			u32Hash += u32Hash >> 1;
		break;

		case 2:	
			u32Hash += *(const UINT16*)pbData;
			u32Hash ^= u32Hash << 11;
			u32Hash += u32Hash >> 17;
		break;

		case 3:
			u32Hash += *(const UINT16*)pbData;
			u32Hash ^= u32Hash << 16;
			u32Hash ^= pbData[sizeof(UINT16)] << 18;
			u32Hash += u32Hash >> 11;
		break;
	}

	u32Hash ^= u32Hash << 3;
	u32Hash += u32Hash >> 5;
	u32Hash ^= u32Hash << 4;
	u32Hash += u32Hash >> 17;
	u32Hash ^= u32Hash << 25;
	u32Hash += u32Hash >> 6;

	return u32Hash;
}

/*
	resolve_find finds the entry by walking the EAT
*/
BOOL resolve_find(PRESOLVE_ENTRY pEntry)
{
	if (pEntry->lpAddr != NULL)
	{
		return TRUE;
	}

	HMODULE hLibrary = LoadLibrary(pEntry->cszwMod);
	if (hLibrary == NULL)
	{
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)hLibrary;
	if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)RESOLVE_REL_CALC(hLibrary, pDOSHdr->e_lfanew);
	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	if (
		(pNTHdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0
	)
	{
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)RESOLVE_REL_CALC(hLibrary, 
				pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddress = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfFunctions);
	PDWORD pdwNames = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNames);
	PWORD pwOrd = (PWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pIED->AddressOfFunctions; i++)
	{
		UINT32 u32FuncHash = resolve_hash_name((LPCSTR)RESOLVE_REL_CALC(hLibrary, pdwNames[i]));
		if (u32FuncHash == pEntry->u32Hash)
		{
			pEntry->lpAddr = (PVOID)RESOLVE_REL_CALC(hLibrary, pdwAddress[pwOrd[i]]);
			return TRUE;
		}
	}

	return FALSE;
}

/*
	resolve_init populates the given table
*/
BOOL resolve_init(PRESOLVE_TABLE pTbl, SIZE_T uCount)
{
	for (SIZE_T i = 0; i < uCount; i++)
	{
		if (!resolve_find((PRESOLVE_ENTRY)&pTbl->reEntries[i]))
			return FALSE;
	}

	return TRUE;
}
