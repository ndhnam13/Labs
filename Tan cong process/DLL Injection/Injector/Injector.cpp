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
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);

    // cap phat bo nho trong tien trinh dich
    auto p = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Viet path den DLL
    WriteProcessMemory(hProcess, p, dll_path, strlen(dll_path) + 1, nullptr);

    // tao thread tu ham load_library de process nap DLL
    auto hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"),
        p, 0, nullptr);

    printf("DLL da duoc inject thanh cong\n");

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

