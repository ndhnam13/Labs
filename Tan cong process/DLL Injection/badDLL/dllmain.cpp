// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "DLL injected", "DLL injector", MB_OK);
        break;
    }
    return TRUE;
}