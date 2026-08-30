#include <windows.h>
#include <lm.h>
#include <iostream>
#include <string>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

class UserManager {
public:
    static void CheckAdmin(int& isAdmin) {
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
    }

    static BOOL AddUser(const wstring& username, const wstring& password) {
        USER_INFO_1 userInfo;
        DWORD dwLevel = 1;
        DWORD dwError = 0;
        NET_API_STATUS nStatus;
        userInfo.usri1_name = (LPWSTR)username.c_str();
        userInfo.usri1_password = (LPWSTR)password.c_str();
        userInfo.usri1_priv = USER_PRIV_USER;
        userInfo.usri1_home_dir = NULL;
        userInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        userInfo.usri1_script_path = NULL;
        nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&userInfo, &dwError);

        if (nStatus != NERR_Success) {
            switch (nStatus) {
            case NERR_UserExists:
                wcout << L"[-] User has already exist, error code: " << nStatus << endl;
                break;
            case NERR_InvalidComputer:
                wcout << L"[-] Invalid computer name, error code: " << nStatus << endl;
                break;
            case ERROR_ACCESS_DENIED:
                wcout << L"[-] Access deny, need admin privilege, error code: " << nStatus << endl;
                break;
            }
            return FALSE;
        }
        else {
            return TRUE;
        }
    }

    static void AddGroup(const wstring& username, const wstring& groupName) {
        LOCALGROUP_MEMBERS_INFO_3 account;
        NET_API_STATUS nStatus;
        account.lgrmi3_domainandname = (LPWSTR)username.c_str();
        nStatus = NetLocalGroupAddMembers(NULL, groupName.c_str(), 3, (LPBYTE)&account, 1);

        if (nStatus == NERR_Success) {
            wcout << L"[+] User " << username << L" has add to group " << groupName << endl;
        }
        else if (nStatus == ERROR_MEMBER_IN_ALIAS) {
            wcout << L"[-] User " << username << L" has already in " << groupName << endl;
        }
        else {
            wcout << L"[-] Add to group failed, error code: " << nStatus << endl;
        }
    }
};

int wmain(int argc, wchar_t* argv[]) {
    int isAdmin;
    UserManager::CheckAdmin(isAdmin);
    if (!isAdmin) {
        wcout << L"[-] Please run this program with admin privilege." << endl;
        exit(-1);
    }

    if (UserManager::AddUser(L"TestAdmin", L"AdminPassword123!")) {
        wcout << L"[+] Add user success." << endl;
    }

    UserManager::AddGroup(L"TestAdmin", L"Administrators");

    return 0;
}