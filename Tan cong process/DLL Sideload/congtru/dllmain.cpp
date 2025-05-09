// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>

extern "C" __declspec(dllexport) void cong(int a, int b) {
    printf("%d + %d = %d\n", a, b, a + b);
}

extern "C" __declspec(dllexport) void tru(int a, int b) {
    printf("%d - %d = %d\n", a, b, a - b);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        printf("Load thanh cong DLL goc\n");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

