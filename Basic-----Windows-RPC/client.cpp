#include <windows.h>
#include <stdio.h>
#include "SimpleCalc.h"

#pragma comment(lib, "Rpcrt4.lib")

void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER MIDL_user_free(void* p) { free(p); }

int main()
{
    RPC_STATUS status;
    RPC_BINDING_HANDLE binding = NULL;
    RPC_CSTR pszStringBinding = NULL;
    
    /*
    status = RpcStringBindingComposeA(
        NULL,
        (RPC_CSTR)"ncacn_ip_tcp",
        (RPC_CSTR)"127.0.0.1",
        (RPC_CSTR)"50000",
        NULL,
        &pszStringBinding
    );
    */
    
    status = RpcStringBindingComposeA(
        NULL,
        (RPC_CSTR)"ncalrpc",
        NULL,               // LRPC不需要地址
        (RPC_CSTR)"MyLocalRPC",
        NULL,
        &pszStringBinding
    );

    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcStringBindingComposeA failed: 0x%lx\n", status);
        return 1;
    }

    status = RpcBindingFromStringBindingA(pszStringBinding, &binding);
    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcBindingFromStringBindingA failed: 0x%lx\n", status);
        RpcStringFreeA(&pszStringBinding);
        return 1;
    }

    RpcStringFreeA(&pszStringBinding);

    // ✅ 用 RpcTryExcept 捕获 RPC 异常
    RpcTryExcept
    {
        int sum = Add(binding, 3, 7);
        printf("[Client] Add(3,7) = %d\n", sum);

        Shutdown(binding);
    }
    RpcExcept(1)
    {
        printf("[Client] RPC Exception code: 0x%lx\n", RpcExceptionCode());
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return 0;
}