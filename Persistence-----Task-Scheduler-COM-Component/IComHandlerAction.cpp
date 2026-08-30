#include <Windows.h>
#include <stdio.h>
#include <comutil.h>
#include <taskschd.h>
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "taskschd.lib")

DWORD CreateScheduledTask(WCHAR* TaskAuthor, WCHAR* TaskName, WCHAR* TaskCLSID)
{
	// WCHAR TaskAuthor[] = L"Microsoft Corporation";
	// WCHAR TaskName[] = L"TestTask";
	// TaskCLSID must be a GUID
	// WCHAR TaskCLSID[] = L"<INSERT GUID>";
	// DWORD res_sch = CreateScheduledTask(TaskAuthor, TaskName, TaskCLSID);

	HRESULT hr = S_OK;

	// initialize the COM library
	hr = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if ((hr != S_OK) && hr != S_FALSE)
	{
		::wprintf(L"[-] CoInitializeEx has failed\n");
		return 0;
	}
	else if (hr == S_FALSE)
	{
		// informational
		::wprintf(L"[*] COM library has been already initialized\n");
	}

	// set security for the process
	PSECURITY_DESCRIPTOR pSecDesc = { 0 };
	hr = ::CoInitializeSecurity(pSecDesc, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (hr != S_OK)
	{
		::wprintf(L"[-] CoInitializeSecurity has failed\n");
		::CoUninitialize();
		return 0;
	}

	// create and initiliaze an object of the class associated with the specified CLSID
	ITaskService* pService = NULL;
	hr = ::CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (hr != S_OK)
	{
		::wprintf(L"[-] CoCreateInstance has failed\n");
		::CoUninitialize();
		return 0;
	}

	// connect to the task service
	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::Connect has failed\n");
		pService->Release();
		::CoUninitialize();
		return 0;
	}

	// get root task folder
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::GetFolder has failed\n");
		pService->Release();
		::CoUninitialize();
		return 0;
	}

	// task builder object
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	pService->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] ITaskService::NewTask has failed\n");
		pService->Release();
		::CoUninitialize();
		return 0;
	}

	// set identification
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

	// get AuthorName from user
	hr = pRegInfo->put_Author(_bstr_t(TaskAuthor));
	pRegInfo->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] get_RegistrationInfo has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	// principal for the task
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

	// principal logon type INTERACTIVE LOGON
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

	// add time trigger
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

	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger Create has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	IDailyTrigger* pDailyTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	hr = pDailyTrigger->put_Id(_bstr_t(L"TestTrigger"));
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger put_Id has failed\n");
	}

	/*
	hr = pDailyTrigger->put_EndBoundary(_bstr_t(L"2022-05-02T08:00:00"));
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger put_EndBoundary has failed\n");
	}
	*/

	hr = pDailyTrigger->put_StartBoundary(_bstr_t(L"1992-01-05T15:00:00"));
	if (FAILED(hr))
	{
		::wprintf(L"[-] Trigger put_StartBoundary has failed\n");
		return 0;
	}

	hr = pDailyTrigger->put_DaysInterval((short)1);
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface has failed\n");
		pRootFolder->Release();
		pDailyTrigger->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	// repetition to the trigger
	IRepetitionPattern* pRepetitionPattern = NULL;
	hr = pDailyTrigger->get_Repetition(&pRepetitionPattern);
	pDailyTrigger->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	// repeat task every day
	// P<days>D<hours>H<minutes>M<seconds>S
	hr = pRepetitionPattern->put_Interval(_bstr_t(L"P1D"));
	pRepetitionPattern->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	// set task action
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
	hr = pActionCollection->Create(TASK_ACTION_COM_HANDLER, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] Create action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	IComHandlerAction* comAction = NULL;
	hr = pAction->QueryInterface(IID_PPV_ARGS(&comAction));
	pAction->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] QueryInterface action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	hr = comAction->put_ClassId(BSTR(TaskCLSID));
	if (FAILED(hr))
	{
		::wprintf(L"[-] put_ClassId action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	/*
	hr = comAction->put_Data(TaskName);
	comAction->Release();
	if (FAILED(hr))
	{
		::wprintf(L"[-] put_Data action has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}
	*/

	// Register the task
	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(TaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(),
		_variant_t(),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask
	);

	if (FAILED(hr))
	{
		::wprintf(L"[-] RegisterTaskDefinition has failed\n");
		pRootFolder->Release();
		pTask->Release();
		::CoUninitialize();
		return 0;
	}

	::wprintf(L"[+] Scheduled task has been created\n");
	// close the COM library
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	::CoUninitialize();

	return 1;
}

int main()
{
	WCHAR TaskAuthor[] = L"Microsoft Corporation";
	WCHAR TaskName[] = L"TestTask";
	// TaskCLSID must be a GUID
	WCHAR TaskCLSID[] = L"<INSERT GUID>";
	DWORD res_sch = CreateScheduledTask(TaskAuthor, TaskName, TaskCLSID);
}