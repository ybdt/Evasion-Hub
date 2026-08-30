#pragma once
// fr2system - Crypto module
// AES-128-CBC, DES-ECB, SHA256, MD4 via Windows CryptoAPI
// Zero external dependencies

#include "common.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// ── SHA-256 ──
static BOOL FR2S_SHA256(const BYTE* data, DWORD dataLen, BYTE outHash[32]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ret = FALSE;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;

    DWORD hashLen = 32;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto cleanup;

    if (!CryptHashData(hHash, data, dataLen, 0))
        goto cleanup;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashLen, 0))
        goto cleanup;

    ret = TRUE;
cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ret;
}

// ── MD5 ──
static BOOL FR2S_MD5(const BYTE* data, DWORD dataLen, BYTE outHash[16]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ret = FALSE;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;

    DWORD hashLen = 16;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        goto cleanup;

    if (!CryptHashData(hHash, data, dataLen, 0))
        goto cleanup;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashLen, 0))
        goto cleanup;

    ret = TRUE;
cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ret;
}

// ── MD4 (NTLM hash) ──
static BOOL FR2S_MD4(const BYTE* data, DWORD dataLen, BYTE outHash[16]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ret = FALSE;

    DWORD hashLen = 16;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;

    if (!CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash))
        goto cleanup;

    if (!CryptHashData(hHash, data, dataLen, 0))
        goto cleanup;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashLen, 0))
        goto cleanup;

    ret = TRUE;
cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ret;
}

// ── AES-128-CBC decrypt ──
static BYTE* FR2S_AES128_CBC_Decrypt(const BYTE* key, const BYTE* iv, const BYTE* ciphertext, DWORD cipherLen, DWORD* outLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE* output = NULL;

    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return NULL;

    struct {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE keyBytes[16];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_128;
    keyBlob.keySize = 16;
    memcpy(keyBlob.keyBytes, key, 16);

    DWORD mode = CRYPT_MODE_CBC;
    DWORD decLen = cipherLen;

    if (!CryptImportKey(hProv, (const BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey))
        goto cleanup;

    CryptSetKeyParam(hKey, KP_MODE, (const BYTE*)&mode, 0);
    CryptSetKeyParam(hKey, KP_IV, iv, 0);

    output = (BYTE*)malloc(cipherLen);
    if (!output) goto cleanup;
    memcpy(output, ciphertext, cipherLen);

    CryptDecrypt(hKey, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, output, &decLen);

    if (outLen) *outLen = decLen;

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return output;
}

// ── DES-ECB decrypt (single 8-byte block) via BCrypt ──
// Legacy CryptoAPI DES is broken/deprecated on Win11 (NTE_BAD_DATA).
// BCrypt is the modern replacement that works on all Windows versions.
static BYTE* FR2S_DES_ECB_Decrypt(const BYTE* key8, const BYTE* ciphertext, DWORD cipherLen, DWORD* outLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE* output = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DES_ALGORITHM, NULL, 0);
    if (st != 0) return NULL;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t), 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

    // BCrypt DES key is 8 bytes but only uses 7 bytes (56 bits) + parity
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key8, 8, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

    output = (BYTE*)malloc(cipherLen);
    if (!output) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

    ULONG resultLen = 0;
    st = BCryptDecrypt(hKey, (PUCHAR)ciphertext, cipherLen, NULL, NULL, 0,
        output, cipherLen, &resultLen, 0);

    if (st != 0) {
        // If no-padding fails, try with BCRYPT_BLOCK_PADDING
        st = BCryptDecrypt(hKey, (PUCHAR)ciphertext, cipherLen, NULL, NULL, 0,
            output, cipherLen, &resultLen, BCRYPT_BLOCK_PADDING);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st != 0) {
        free(output);
        return NULL;
    }

    if (outLen) *outLen = 8;
    return output;
}

// ── DES key derivation from 7-byte input → 8-byte DES key with parity ──
// Must use little-endian packing (same as Windows/BlueHammer)
static void FR2S_DeriveDESKey(const BYTE input[7], BYTE output[8]) {
    // Little-endian pack: input[0] at LSB, matching Windows internal behavior
    UINT64 k = 0;
    memcpy(&k, input, 7);

    for (int i = 0; i < 8; i++) {
        int j = 7 - i;
        int curr = (int)((k >> (7 * j)) & 0x7F);
        int b = curr;
        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        output[i] = (BYTE)((curr << 1) ^ (b & 1) ^ 1);
    }
}

// ── RID-based DES key pair derivation ──
static void FR2S_DeriveRIDKeys(ULONG rid, BYTE desKey1[8], BYTE desKey2[8]) {
    BYTE* r = (BYTE*)&rid;
    BYTE k1[7] = { r[2], r[1], r[0], r[3], r[2], r[1], r[0] };
    BYTE k2[7] = { r[1], r[0], r[3], r[2], r[1], r[0], r[3] };
    FR2S_DeriveDESKey(k1, desKey1);
    FR2S_DeriveDESKey(k2, desKey2);
}

// ── Double DES decrypt for NTLM hash (RID-keyed) ──
static BOOL FR2S_DecryptNTLMWithRID(const BYTE* encHash, DWORD encLen, ULONG rid, BYTE outHash[16]) {
    if (encLen < 16) return FALSE;

    BYTE desKey1[8], desKey2[8];
    FR2S_DeriveRIDKeys(rid, desKey1, desKey2);

    printf("     [dbg] DES input1: "); for(int i=0;i<8;i++) printf("%02x",encHash[i]); printf("\n");
    printf("     [dbg] DES input2: "); for(int i=0;i<8;i++) printf("%02x",encHash[8+i]); printf("\n");
    printf("     [dbg] DES key1:   "); for(int i=0;i<8;i++) printf("%02x",desKey1[i]); printf("\n");
    printf("     [dbg] DES key2:   "); for(int i=0;i<8;i++) printf("%02x",desKey2[i]); printf("\n");

    DWORD out1Len = 0, out2Len = 0;
    BYTE* part1 = FR2S_DES_ECB_Decrypt(desKey1, encHash, 8, &out1Len);
    BYTE* part2 = FR2S_DES_ECB_Decrypt(desKey2, encHash + 8, 8, &out2Len);

    if (part1) { printf("     [dbg] DES out1:   "); for(int i=0;i<8;i++) printf("%02x",part1[i]); printf("\n"); }
    if (part2) { printf("     [dbg] DES out2:   "); for(int i=0;i<8;i++) printf("%02x",part2[i]); printf("\n"); }

    if (!part1 || !part2) {
        free(part1);
        free(part2);
        return FALSE;
    }

    memcpy(outHash, part1, 8);
    memcpy(outHash + 8, part2, 8);
    free(part1);
    free(part2);
    return TRUE;
}

// ── Compute NTLM hash from plaintext password ──
static BOOL FR2S_ComputeNTLM(const char* password, BYTE outHash[16]) {
    int len = (int)strlen(password);
    BYTE* unicode = (BYTE*)malloc(len * 2);
    if (!unicode) return FALSE;

    for (int i = 0; i < len; i++) {
        unicode[i * 2] = (BYTE)password[i];
        unicode[i * 2 + 1] = 0;
    }

    BOOL ret = FR2S_MD4(unicode, len * 2, outHash);
    free(unicode);
    return ret;
}
