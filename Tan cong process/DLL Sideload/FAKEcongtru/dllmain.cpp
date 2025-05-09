// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>

// gia mao ham trong congtru.dll
extern "C" __declspec(dllexport) void cong(void) {
    MessageBoxA(NULL, "fucntion cong gia mao", "FAKEcongtru.dll", MB_OK | MB_ICONWARNING);
}
extern "C" __declspec(dllexport) void tru(void) {
    MessageBoxA(NULL, "fucntion tru gia mao", "FAKEcongtru.dll", MB_OK | MB_ICONWARNING);
}

// Ham rong
//extern "C" __declspec(dllexport) void cong(void) {
//    // zzz
//}
//
//extern "C" __declspec(dllexport) void tru(void) {
//    // zzz
//}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Sideloaded DLL", "FAKEcongtru.dll", MB_OK | MB_ICONWARNING);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

