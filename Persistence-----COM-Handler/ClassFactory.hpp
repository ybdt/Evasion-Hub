#pragma once

#include <comdef.h>
#include "TaskHandler.hpp"

#define COM_CLASS_NAME CTaskHandler

class ClassFactory : public IClassFactory
{
public:
    ClassFactory()
    {
        InterlockedIncrement(&m_nRefCount);
    }

    ~ClassFactory()
    {
        InterlockedDecrement(&m_nRefCount);
    }

    // IUnknown中的3个方法必须实现
    STDMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ LPVOID* ppObj) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IClassFactory中的2个方法必须实现
    STDMETHODIMP CreateInstance(_In_opt_ IUnknown* pUnknownOuter, _In_ REFIID riid, _COM_Outptr_ LPVOID* ppv);
    STDMETHODIMP LockServer(_In_ BOOL bLock);

private:
    long m_nRefCount;
};