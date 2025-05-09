// vulnapp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdio.h>
#include <Windows.h>

typedef void (*func)(int, int); // Ham nhan 2 int, khong return

int main()
{
    HMODULE hDLL = LoadLibraryA("congtru.dll");
    if (!hDLL) {
        printf("Khong load duoc DLL");
    }

    func cong = (func)GetProcAddress(hDLL, "cong");
    if (!cong) {
        printf("Khong load duoc ham cong\n");
        return -1;
    }
    cong(1, 3);
    func tru = (func)GetProcAddress(hDLL, "tru");
    if (!tru) {
        printf("Khong load duoc ham tru\n");
        return -1;
    }
    tru(8, 6);


}
