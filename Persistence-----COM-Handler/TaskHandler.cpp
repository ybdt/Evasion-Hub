#include <initguid.h>
#include "TaskHandler.hpp"
#include <ObjIdl.h>
#include "stager/Common.h"
#include <Windows.h>

DEFINE_GUID(IID_ITaskHandler, 0x839d7762, 0x5121, 0x4009, 0x92, 0x34, 0x4f, 0x0d, 0x19, 0x39, 0x4f, 0x04);

extern "C" DWORD WINAPI init() {
    MessageBoxA(NULL, "Title", "Hello ybdt, I am from COM Handler", 0);
    return 0;
}

CTaskHandler::CTaskHandler()
{
    InterlockedIncrement(&m_nRefCount);
}

CTaskHandler::~CTaskHandler()
{
    InterlockedDecrement(&m_nRefCount);
}

STDMETHODIMP CTaskHandler::Start(IUnknown* handler, BSTR data)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    init();
    return S_OK;
}

STDMETHODIMP CTaskHandler::Stop(HRESULT* retCode)
{
    ExitProcess(0);
    return S_OK;
}

STDMETHODIMP CTaskHandler::Pause()
{
    ExitProcess(0);
    return S_OK;
}

STDMETHODIMP CTaskHandler::Resume()
{
    return S_OK;
}

STDMETHODIMP CTaskHandler::QueryInterface(_In_ REFIID riid, _COM_Outptr_ LPVOID* ppv)
{
    if (!ppv) { return E_INVALIDARG; }

    if (IsEqualGUID(riid, IID_IUnknown))
    {
        *ppv = static_cast<IUnknown*>(this);
    }
    else if (IsEqualGUID(riid, IID_ITaskHandler))
    {
        *ppv = static_cast<ITaskHandler*>(this);
    }
    else {
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) CTaskHandler::AddRef()
{
    return InterlockedIncrement(&m_nRefCount);
}

STDMETHODIMP_(ULONG) CTaskHandler::Release()
{
    LONG nRefCount = 0;
    nRefCount = InterlockedDecrement(&m_nRefCount);
    if (nRefCount == 0) delete this;
    return nRefCount;
}