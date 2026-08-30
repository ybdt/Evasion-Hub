# Module Stomping

## Stomping In Local Process
1. **Load:** Use LoadLibraryExA with DONT_RESOLVE_DLL_REFERENCES flag to map a legitimate DLL into current process, DONT_RESOLVE_DLL_REFERENCES indicates don't execute entry point and don't parse IAT.

2. **Locate:** Locate .text section of loaded legitimate DLL for overwriting(stomping).

3. **Write:** WriteProcessMemory or RtlCopyMemory to copy shellcode to .text section of legitimate DLL.

4. **Execute:** Trigger shellcode execute using CreateThread or CreateRemoteThread.

## Stomping In Remote Process
Attention: stomp in remote process is different from in local process, you can't control remote process load specific DLL, so you can only stomp the existing content.

1. Acquire the remote process handle using OpenProcess with the required access rights.

2. Query the remote process to find its Process Environment Block (PEB) address， and walk the InMemoryOrderModuleList of PEB to dynamically locate the base address of module (e.g. Kernel32.dll)

3. Locate the base address of function (e.g. FileTimeToSystemTime) via manual Export Address Tale (EAT) parse.

4. Write shellcode to base address of function (e.g. FileTimeToSystemTime)

5. Trigger the shellcode via CreateRemoteThread(or SetThreadContext) to pointing the stomped function address.

# Defensive

## Detect Point One
Modern EDRs perform "Module Integrity Check" by comparing the code in memory against the code on disk file

If memory_hash(dll) != disk_hash(dll), an alert is triggered.

#### Solution
For example, the .text section of chakra.dll is 1MB, your shellcode is 100KB, you shellcode is only ten percent of chakra.dll .text section, EDR always random sampling inspection, your shellcode face a lower chance being inspect.

When stomping DLL, someone always clear .text section with 0x00 or 0x90, this will increase chance being detected, only stomp specific bytes.

The first few bytes of sRDI always has obvious signature, so use "NOP" mask it, that can decrease being detected.

In summary, choose a large dll, and only stomp specific bytes needed, and consider using "Nop" to mask the payload entry.

## Detect Point Two
The use of VirtualProtect on a image-backed memory region is a high-confidence suscipious for many security products.

The sequence:
LoadLibraryExA -> WriteProcessMemory
LoadLibraryExA -> VirtualProtect(RW) -> memcpy -> VirtualProtect(RX)
is a classic signature of memory manipulation.

#### Solution
Instead of VirtualProtect, you can use NtMapViewOfSection to map a modified view of DLL directly in memory, avoiding "Modify" behavior.

## Detect Point Three
Thread execute from the middle of DLL, instead of a legitimate export function base address (e.g. FileTimeToSystemTime) is suscipious

#### Solution
You should stomp a legitimate Export function base address.

## Detect Point Four
EDR always scan the memory of important DLL or the DLL used by redteam frequently.

#### Solution
Choose the one that normally present.