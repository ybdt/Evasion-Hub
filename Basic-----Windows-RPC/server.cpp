#include <windows.h>
#include <stdio.h>
#include "SimpleCalc.h"
#pragma comment(lib, "Rpcrt4.lib")


void* __RPC_USER MIDL_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER MIDL_user_free(void* p) { free(p); }


extern "C" int Add(handle_t IDL_handle, int a, int b) {
    printf("[Server] Add(%d, %d)\n", a, b);
    return a + b;
}
extern "C" void Shutdown(handle_t IDL_handle) {
    printf("[Server] Shutdown requested\n");
    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(NULL, NULL, TRUE);
}


int main()
{
    RPC_STATUS status;
    RPC_CSTR pszProtocolSequence = (RPC_CSTR)"ncalrpc";
    RPC_CSTR pszEndpoint = (RPC_CSTR)"MyLocalRPC";
    status = RpcServerUseProtseqEpA(pszProtocolSequence, RPC_C_PROTSEQ_MAX_REQS_DEFAULT, pszEndpoint, NULL);
    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcServerUseProtseqEpA failed: 0x%lx\n", status);
        return 1;
    }

    status = RpcServerRegisterIf(SimpleCalc_v1_0_s_ifspec, NULL, NULL);
    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcServerRegisterIf failed: 0x%lx\n", status);
        return 1;
    }

    RpcServerRegisterAuthInfoA(NULL, RPC_C_AUTHN_NONE, NULL, NULL);

    printf("[Server] Listening on ncacn_ip_tcp port %s\n", (char*)pszEndpoint);

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    if (status != RPC_S_OK) {
        fprintf(stderr, "RpcServerListen failed: 0x%lx\n", status);
        return 1;
    }

    printf("[Server] RpcServerListen returned, exiting.\n");
    return 0;
}