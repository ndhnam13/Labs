// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include "MessageBoxDll.h"


DWORD find_process_id(const wchar_t* process_name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

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
    if (pid==0) {
        printf("Khong tim thay notepad.exe\n");
        return 1;
    }
    printf("Tim thay notepad.exe voi PID: %lu\n", pid);

    auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    auto pRemote = VirtualAllocEx(hProcess, 0, MessageBox_dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pRemote, MessageBox_dll, MessageBox_dll_len, NULL);

    auto hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemote, NULL, 0, 0);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
    
}
