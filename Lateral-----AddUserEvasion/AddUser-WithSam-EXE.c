#include <stdio.h>
#include <Windows.h>
#include "samlib.h"

#pragma comment(lib, "samlib.lib")
#pragma comment(lib, "ntdll.lib")

NTSTATUS status = STATUS_INVALID_ACCOUNT_NAME;
NTSTATUS enumDomainStatus;

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}

int main()
{
	UNICODE_STRING serverName;
	UNICODE_STRING password;
	UNICODE_STRING user;
	UNICODE_STRING sBuiltin;
	RtlInitUnicodeString(&serverName, L"localhost");
	RtlInitUnicodeString(&user, L"test");
	RtlInitUnicodeString(&password, L"p@ssw0rd");
	RtlInitUnicodeString(&sBuiltin, L"Builtin");
	int i;
	NTSTATUS status = STATUS_DATA_ERROR;
	SAMPR_HANDLE hServer = NULL;
	SAMPR_HANDLE hDomainHandle = NULL;
	SAMPR_HANDLE hUserHandle = NULL;
	ULONG grantAccess;
	ULONG relativeId;
	PSID AccountSID = 0;
	PSID BuiltSID = 0;
	long enumDomainStatus;
	long changePassStatus;
	unsigned long RID = 0;
	unsigned long outVersion;
	unsigned long domainEnumerationContext = 0;
	unsigned long domainCountReturned;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer = NULL;
	UNICODE_STRING adminGroup;
	DWORD* adminRID;
	SAMPR_HANDLE hAdminGroup;
	PSID userSID = NULL;
	SAMPR_USER_ALL_INFORMATION userAllInfo = { 0 };

	status = SamConnect(&serverName, &hServer, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	if (NT_SUCCESS(status))
	{
		do
		{
			enumDomainStatus = SamEnumerateDomainsInSamServer(hServer, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountReturned);
			for (i = 0; i < domainCountReturned; i++)
			{
				if (RtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &sBuiltin, TRUE)) {
					status = SamLookupDomainInSamServer(hServer, &pEnumDomainBuffer[i].Name, &BuiltSID);
					if (NT_SUCCESS(status)) {
						wprintf(L"[+] SamLookupDomainInSamServer Built \n");
					}
				}
				else {
					status = SamLookupDomainInSamServer(hServer, &pEnumDomainBuffer[i].Name, &AccountSID);
					if (NT_SUCCESS(status)) {
						wprintf(L"[+] SamLookupDomainInSamServer Account \n");
					}
				}
			}
		} while (enumDomainStatus == STATUS_MORE_ENTRIES);

		status = SamOpenDomain(hServer, DOMAIN_LOOKUP | DOMAIN_CREATE_USER, AccountSID, &hDomainHandle);
		if (NT_SUCCESS(status))
		{
			status = SamCreateUser2InDomain(hDomainHandle, &user, USER_NORMAL_ACCOUNT, USER_ALL_ACCESS | DELETE | WRITE_DAC, &hUserHandle, &grantAccess, &relativeId);
			if (NT_SUCCESS(status))
			{
				wprintf(L"[+] SamCreateUser2InDomain success. User RID: %d\n", relativeId);
				userAllInfo.NtPasswordPresent = TRUE;
				userAllInfo.WhichFields |= USER_ALL_NTPASSWORDPRESENT;
				userAllInfo.UserAccountControl &= 0xFFFFFFFE;
				userAllInfo.UserAccountControl |= USER_NORMAL_ACCOUNT;
				userAllInfo.WhichFields |= USER_ALL_USERACCOUNTCONTROL;
				RtlInitUnicodeString(&userAllInfo.NtOwfPassword, password.Buffer);
				status = SamSetInformationUser(hUserHandle, UserAllInformation, &userAllInfo);
				if (NT_SUCCESS(status))
				{
					wprintf(L"[+] SamSetInformationUser success.\n");
				}
				else wprintf(L"[!] SamSetInformationUser error 0x%ld\n", status);
			}
			else wprintf(L"[!] SamCreateUser2InDomain error 0x%ld\n", status);

		}
		else wprintf(L"[!] SamOpenDomain error. 0x%ld\n", status);

		status = SamOpenDomain(hServer, DOMAIN_LOOKUP, BuiltSID, &hDomainHandle);
		if (NT_SUCCESS(status))
		{
			RtlInitUnicodeString(&adminGroup, L"administrators");

			// Lookup Administrators in Builtin Domain
			status = SamLookupNamesInDomain(hDomainHandle, 1, &adminGroup, &adminRID, &user);
			if (NT_SUCCESS(status))
			{
				status = SamOpenAlias(hDomainHandle, ALIAS_ADD_MEMBER, *adminRID, &hAdminGroup);
				if (NT_SUCCESS(status))
				{
					SamRidToSid(hUserHandle, relativeId, &userSID);

					// Add user to Administrators
					status = SamAddMemberToAlias(hAdminGroup, userSID);
					if (NT_SUCCESS(status))
					{
						wprintf(L"[+] SamAddMemberToAlias success.\n");
					}
					else wprintf(L"[!] AddMemberToAlias error 0x%08X\n", status);
				}
				else wprintf(L"[!] SamOpenAlias error 0x%08X\n", status);
			}
			else wprintf(L"[!] SamLookupNamesInDomain error 0x%08X\n", status);
		}
	}
	else wprintf(L"[!] Samconnect error\n");

	return 0;
}