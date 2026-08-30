#include "check_alertable.h"
#include <iostream>

// based on Tal Liberman's method and: https://modexp.wordpress.com/2019/08/27/process-injection-apc/
HANDLE find_alertable_by_event(HANDLE hProcess, std::vector<DWORD>& threads)
{
    size_t cnt = 0;
    HANDLE threadHandles[MAXIMUM_WAIT_OBJECTS] = { 0 };
    HANDLE eventHandlesL[MAXIMUM_WAIT_OBJECTS] = { 0 };
    HANDLE eventHandlesR[MAXIMUM_WAIT_OBJECTS] = { 0 };

    for (auto itr = threads.begin(); itr != threads.end(); ++itr) {
        if (cnt == MAXIMUM_WAIT_OBJECTS) break;

        DWORD threadId = *itr;
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
        if (!hThread || hThread == INVALID_HANDLE_VALUE) {
            continue;
        }
        threadHandles[cnt++] = hThread;
    }

    for (size_t i = 0; i < cnt; i++) {
        // 2. create event and duplicate in target process
        eventHandlesL[i] = CreateEvent(NULL, FALSE, FALSE, NULL);

        DuplicateHandle(
            GetCurrentProcess(),  // source process
            eventHandlesL[i],           // source handle to duplicate
            hProcess,                   // target process
            &eventHandlesR[i],          // target handle
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);

        FARPROC _SetEvent = GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetEvent");
        // 3. Queue APC for thread passing target event handle
        QueueUserAPC((PAPCFUNC)_SetEvent, threadHandles[i], (ULONG_PTR)eventHandlesR[i]);
    }

    HANDLE signaledThread = NULL;
    // 4. Wait for event to become signalled
    DWORD i = WaitForMultipleObjects(cnt, eventHandlesL, FALSE, 1000);
    if (i != WAIT_TIMEOUT) {
        // 5. save thread handle
        signaledThread = threadHandles[i];
    }

    // 6. Close handles
    for (i = 0; i < cnt; i++) {
        CloseHandle(eventHandlesL[i]);
        if (threadHandles[i] != signaledThread) {
            CloseHandle(threadHandles[i]);
        }
    }
    return signaledThread;
}
