#pragma once
// fr2system - Registry Hive Parser
// Custom offline registry hive parser — no offreg.lib dependency
// Parses Windows NT registry hive format (regf) directly from file buffer

#include "common.h"

// ── Registry hive file format structures ──
// Reference: https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

#define REGF_SIGNATURE 0x66676572  // "regf"
#define HBIN_SIGNATURE 0x6E696268  // "hbin"

#define CM_KEY_NODE_SIGNATURE     0x6B6E  // "nk"
#define CM_KEY_VALUE_SIGNATURE    0x6B76  // "vk"

// Key node flags
#define KEY_HIVE_ENTRY  0x0004
#define KEY_NO_DELETE   0x0008

#pragma pack(push, 1)

typedef struct _REGF_HEADER {
    ULONG Signature;        // "regf"
    ULONG Sequence1;
    ULONG Sequence2;
    LARGE_INTEGER Timestamp;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG Type;
    ULONG Format;
    ULONG RootCellOffset;   // offset to root cell from start of hive bins
    ULONG HiveDataSize;
    ULONG Cluster;
    // ... more fields we don't need
} REGF_HEADER;

typedef struct _HBIN_HEADER {
    ULONG Signature;        // "hbin"
    ULONG Offset;           // offset from start of hive bins
    ULONG Size;             // size of this hbin
    ULONG Reserved[2];
    LARGE_INTEGER Timestamp;
    ULONG Spare;
} HBIN_HEADER;

typedef struct _CM_KEY_NODE {
    USHORT Signature;       // "nk"
    USHORT Flags;
    LARGE_INTEGER Timestamp;
    ULONG Access;
    ULONG Parent;
    ULONG SubKeyCount;
    ULONG VolatileSubKeyCount;
    ULONG SubKeyListOffset;
    ULONG VolatileSubKeyListOffset;
    ULONG ValueCount;
    ULONG ValueListOffset;
    ULONG SecurityKeyOffset;
    ULONG ClassNameOffset;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG WorkVar;
    USHORT NameLength;
    USHORT ClassLength;
    // Name follows (NameLength bytes)
} CM_KEY_NODE;

typedef struct _CM_KEY_VALUE {
    USHORT Signature;       // "vk"
    USHORT NameLength;
    ULONG  DataLength;
    ULONG  DataOffset;
    ULONG  Type;
    USHORT Flags;
    USHORT Spare;
    // Name follows (NameLength bytes)
} CM_KEY_VALUE;

#pragma pack(pop)

// ── Hive context ──
typedef struct _HIVE_CTX {
    BYTE*  data;            // raw hive file data
    DWORD  dataSize;
    ULONG  hbinOffset;      // offset to first hbin (always 0x1000)
    ULONG  rootCellOffset;  // from REGF header
} HIVE_CTX;

// ── Get cell pointer from cell offset ──
// Cell offsets are relative to the start of hive bin data (after REGF header, at 0x1000)
// Cells start with a 4-byte size field (negative = allocated, positive = free)
static BYTE* FR2S_HiveGetCell(HIVE_CTX* hive, ULONG cellOffset) {
    if (cellOffset == 0xFFFFFFFF) return NULL;
    ULONG absoluteOffset = 0x1000 + cellOffset;
    if (absoluteOffset + 4 >= hive->dataSize) return NULL;

    // Skip the 4-byte cell size header
    return &hive->data[absoluteOffset + 4];
}

// ── Open hive from buffer ──
static BOOL FR2S_HiveOpen(BYTE* data, DWORD dataSize, HIVE_CTX* hive) {
    if (dataSize < 0x1000 + sizeof(HBIN_HEADER)) return FALSE;

    REGF_HEADER* hdr = (REGF_HEADER*)data;
    if (hdr->Signature != REGF_SIGNATURE) {
        FR2S_Err("Invalid hive signature: 0x%08X", hdr->Signature);
        return FALSE;
    }

    hive->data = data;
    hive->dataSize = dataSize;
    hive->hbinOffset = 0x1000;
    hive->rootCellOffset = hdr->RootCellOffset;
    return TRUE;
}

// ── Get root key node ──
static CM_KEY_NODE* FR2S_HiveGetRootKey(HIVE_CTX* hive) {
    return (CM_KEY_NODE*)FR2S_HiveGetCell(hive, hive->rootCellOffset);
}

// ── Find subkey by name (case-insensitive) ──
static CM_KEY_NODE* FR2S_HiveFindSubKey(HIVE_CTX* hive, CM_KEY_NODE* parentKey, const char* name) {
    if (!parentKey || parentKey->SubKeyCount == 0) return NULL;
    if (parentKey->SubKeyListOffset == 0xFFFFFFFF) return NULL;

    BYTE* listCell = FR2S_HiveGetCell(hive, parentKey->SubKeyListOffset);
    if (!listCell) return NULL;

    USHORT listSig = *(USHORT*)listCell;
    ULONG count = 0;

    // Handle different subkey list types: lf, lh, ri, li
    if (listSig == 0x666C || listSig == 0x686C) {
        // "lf" or "lh" — fast leaf / hash leaf
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG keyOffset = *(ULONG*)(listCell + 4 + i * 8);
            CM_KEY_NODE* subKey = (CM_KEY_NODE*)FR2S_HiveGetCell(hive, keyOffset);
            if (!subKey || subKey->Signature != CM_KEY_NODE_SIGNATURE) continue;

            char* keyName = (char*)(subKey + 1);
            if (subKey->NameLength == strlen(name) &&
                _strnicmp(keyName, name, subKey->NameLength) == 0) {
                return subKey;
            }
        }
    }
    else if (listSig == 0x696C) {
        // "li" — leaf index
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG keyOffset = *(ULONG*)(listCell + 4 + i * 4);
            CM_KEY_NODE* subKey = (CM_KEY_NODE*)FR2S_HiveGetCell(hive, keyOffset);
            if (!subKey || subKey->Signature != CM_KEY_NODE_SIGNATURE) continue;

            char* keyName = (char*)(subKey + 1);
            if (subKey->NameLength == strlen(name) &&
                _strnicmp(keyName, name, subKey->NameLength) == 0) {
                return subKey;
            }
        }
    }
    else if (listSig == 0x6972) {
        // "ri" — root index (contains offsets to other lf/lh/li lists)
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG subListOffset = *(ULONG*)(listCell + 4 + i * 4);
            // Create a temporary parent that points to this sub-list
            CM_KEY_NODE tempParent = *parentKey;
            tempParent.SubKeyListOffset = subListOffset;
            CM_KEY_NODE* result = FR2S_HiveFindSubKey(hive, &tempParent, name);
            if (result) return result;
        }
    }

    return NULL;
}

// ── Navigate a registry path like "SAM\Domains\Account\Users" ──
static CM_KEY_NODE* FR2S_HiveOpenKey(HIVE_CTX* hive, const char* path) {
    CM_KEY_NODE* current = FR2S_HiveGetRootKey(hive);
    if (!current) return NULL;

    char pathCopy[512];
    strncpy(pathCopy, path, sizeof(pathCopy) - 1);
    pathCopy[sizeof(pathCopy) - 1] = 0;

    char* ctx = NULL;
    char* token = strtok_s(pathCopy, "\\", &ctx);
    while (token && current) {
        current = FR2S_HiveFindSubKey(hive, current, token);
        token = strtok_s(NULL, "\\", &ctx);
    }
    return current;
}

// ── Get value data by name ──
static BYTE* FR2S_HiveGetValue(HIVE_CTX* hive, CM_KEY_NODE* key, const char* valueName, DWORD* outSize) {
    if (!key || key->ValueCount == 0) return NULL;
    if (key->ValueListOffset == 0xFFFFFFFF) return NULL;

    BYTE* valListCell = FR2S_HiveGetCell(hive, key->ValueListOffset);
    if (!valListCell) return NULL;

    ULONG* valueOffsets = (ULONG*)valListCell;

    for (ULONG i = 0; i < key->ValueCount; i++) {
        CM_KEY_VALUE* val = (CM_KEY_VALUE*)FR2S_HiveGetCell(hive, valueOffsets[i]);
        if (!val || val->Signature != CM_KEY_VALUE_SIGNATURE) continue;

        char* vName = (char*)(val + 1);
        BOOL nameMatch = FALSE;

        if (valueName == NULL || valueName[0] == '\0') {
            // Default value (no name)
            nameMatch = (val->NameLength == 0);
        }
        else {
            nameMatch = (val->NameLength == strlen(valueName) &&
                _strnicmp(vName, valueName, val->NameLength) == 0);
        }

        if (nameMatch) {
            DWORD dataLen = val->DataLength & 0x7FFFFFFF;
            BOOL isResident = (val->DataLength & 0x80000000) != 0;

            if (isResident) {
                // Data is stored in the DataOffset field itself (≤ 4 bytes)
                if (outSize) *outSize = dataLen;
                BYTE* result = (BYTE*)malloc(dataLen);
                if (result) memcpy(result, &val->DataOffset, dataLen);
                return result;
            }
            else {
                // Data is in a separate cell
                BYTE* dataCell = FR2S_HiveGetCell(hive, val->DataOffset);
                if (!dataCell) return NULL;
                if (outSize) *outSize = dataLen;
                BYTE* result = (BYTE*)malloc(dataLen);
                if (result) memcpy(result, dataCell, dataLen);
                return result;
            }
        }
    }
    return NULL;
}

// ── Enumerate subkeys ──
typedef BOOL(*FR2S_ENUM_KEY_CALLBACK)(HIVE_CTX* hive, CM_KEY_NODE* subKey, const char* name, void* context);

static BOOL FR2S_HiveEnumSubKeys(HIVE_CTX* hive, CM_KEY_NODE* parentKey, FR2S_ENUM_KEY_CALLBACK callback, void* context) {
    if (!parentKey || parentKey->SubKeyCount == 0) return TRUE;
    if (parentKey->SubKeyListOffset == 0xFFFFFFFF) return TRUE;

    BYTE* listCell = FR2S_HiveGetCell(hive, parentKey->SubKeyListOffset);
    if (!listCell) return FALSE;

    USHORT listSig = *(USHORT*)listCell;
    ULONG count = 0;

    if (listSig == 0x666C || listSig == 0x686C) {
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG keyOffset = *(ULONG*)(listCell + 4 + i * 8);
            CM_KEY_NODE* subKey = (CM_KEY_NODE*)FR2S_HiveGetCell(hive, keyOffset);
            if (!subKey || subKey->Signature != CM_KEY_NODE_SIGNATURE) continue;

            char name[256] = { 0 };
            DWORD nameLen = min(subKey->NameLength, sizeof(name) - 1);
            memcpy(name, (char*)(subKey + 1), nameLen);

            if (!callback(hive, subKey, name, context))
                return FALSE;
        }
    }
    else if (listSig == 0x696C) {
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG keyOffset = *(ULONG*)(listCell + 4 + i * 4);
            CM_KEY_NODE* subKey = (CM_KEY_NODE*)FR2S_HiveGetCell(hive, keyOffset);
            if (!subKey || subKey->Signature != CM_KEY_NODE_SIGNATURE) continue;

            char name[256] = { 0 };
            DWORD nameLen = min(subKey->NameLength, sizeof(name) - 1);
            memcpy(name, (char*)(subKey + 1), nameLen);

            if (!callback(hive, subKey, name, context))
                return FALSE;
        }
    }
    else if (listSig == 0x6972) {
        count = *(USHORT*)(listCell + 2);
        for (ULONG i = 0; i < count; i++) {
            ULONG subListOffset = *(ULONG*)(listCell + 4 + i * 4);
            CM_KEY_NODE tempParent = *parentKey;
            tempParent.SubKeyListOffset = subListOffset;
            if (!FR2S_HiveEnumSubKeys(hive, &tempParent, callback, context))
                return FALSE;
        }
    }

    return TRUE;
}
