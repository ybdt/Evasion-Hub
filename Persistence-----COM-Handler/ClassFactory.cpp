#include "ClassFactory.hpp"

STDMETHODIMP ClassFactory::CreateInstance(_In_opt_ IUnknown* pUnknownOuter, _In_ REFIID riid, _COM_Outptr_ LPVOID* ppv)
{
    COM_CLASS_NAME* pTaskHandler;
    if (!ppv) { return E_INVALIDARG; }
    if (pUnknownOuter) { return CLASS_E_NOAGGREGATION; }
    pTaskHandler = new COM_CLASS_NAME();
    if (!pTaskHandler) { return E_OUTOFMEMORY; }
    return pTaskHandler->QueryInterface(riid, ppv);
}

STDMETHODIMP ClassFactory::LockServer(_In_ BOOL bLock)
{
    UNREFERENCED_PARAMETER(bLock);
    return S_OK;
}

STDMETHODIMP ClassFactory::QueryInterface(_In_ REFIID riid, _COM_Outptr_ LPVOID* ppv)
{
    if (!ppv) { return E_INVALIDARG; }
    if (IsEqualGUID(riid, IID_IUnknown))
    {
        *ppv = static_cast<IUnknown*>(this);
    }
    else if (IsEqualGUID(riid, IID_IClassFactory))
    {
        *ppv = static_cast<IClassFactory*>(this);
    }
    else {
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) ClassFactory::AddRef()
{
    return InterlockedIncrement(&m_nRefCount);
}

STDMETHODIMP_(ULONG) ClassFactory::Release()
{
    LONG nRefCount = 0;
    nRefCount = InterlockedDecrement(&m_nRefCount);
    if (nRefCount == 0) delete this;
    return nRefCount;
}