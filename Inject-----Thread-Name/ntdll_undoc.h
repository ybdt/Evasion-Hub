#pragma once
#include "ntddk.h"

#define NT_SUCCESS 0
#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF
#define ThreadNameInformation 0x26

NTSTATUS
NTAPI
NtQueueApcThread(
	IN HANDLE	ThreadHandle,
	IN PVOID	ApcRoutine,
	IN PVOID	ApcRoutineContext OPTIONAL,
	IN PVOID	ApcStatusBlock OPTIONAL,
	IN PVOID	ApcReserved OPTIONAL
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueueApcThreadEx2(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE ReserveHandle, // NtAllocateReserveObject
    _In_ ULONG ApcFlags, // QUEUE_USER_APC_FLAGS
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PVOID ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN              CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT PULONG           StackReserved,
    IN OUT PULONG           StackCommit,
    IN PVOID                StartAddress,
    IN PVOID                StartParameter OPTIONAL,
    OUT PHANDLE             ThreadHandle,
    OUT PCLIENT_ID          ClientID);

NTSYSCALLAPI
NTSTATUS NtSetInformationThread(
    IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
);

NTSTATUS
RtlInitUnicodeStringEx(
    UNICODE_STRING* DestinationString,
    PCWSTR SourceString);
