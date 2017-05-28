#include <Windows.h>
#include <iostream>
#include <assert.h>

#include "../HookCore/HookCore.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/HookCore.lib" )
#else
#pragma comment( lib, "../Release/HookCore.lib" )
#endif
using namespace HookCore;

#include "../SyscallHelper/SyscallHelper.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/SyscallHelper.lib" )
#else
#pragma comment( lib, "../Release/SyscallHelper.lib" )
#endif
using namespace SyscallHelper;


static HMODULE hNtdll;

typedef NTSTATUS(NTAPI* lpNtWriteVirtualMemory)(HANDLE, PVOID, LPCVOID, SIZE_T, PSIZE_T);
static lpNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;

typedef NTSTATUS(NTAPI* lpNtSuspendProcess)(HANDLE);
static lpNtSuspendProcess NtSuspendProcess = nullptr;


static DWORD g_dwSyscallIndexOfNtWriteVirtualMemory = 0;
static DWORD g_dwSyscallIndexOfNtSuspendProcess		= 0;
static LPVOID g_lpBaseAddress = nullptr;



NTSTATUS __declspec(naked) NtWriteVirtualMemoryHook(HANDLE, PVOID, CONST VOID *, SIZE_T, PSIZE_T)
{
	__asm pushad

	printf("NtWriteVirtualMemory called.\n");

	__asm popad
	__asm jmp g_lpBaseAddress
}

NTSTATUS __declspec(naked) NtSuspendProcessHook(HANDLE hProcess)
{
	printf("NtSuspendProcess called.\n");
	hProcess = nullptr;

	__asm jmp g_lpBaseAddress
}

static void __declspec(naked) Wow64Trampoline()
{
	//__asm int 3;
	__asm
	{
		cmp eax, g_dwSyscallIndexOfNtWriteVirtualMemory
			jz NtWriteVirtualMemoryHook
		cmp eax, g_dwSyscallIndexOfNtSuspendProcess
			jz NtSuspendProcessHook

		jmp g_lpBaseAddress;
	}
}

void SuspendSelf()
{
	__try { NtSuspendProcess(GetCurrentProcess()); }
	__except (1) { }
}

int main()
{
#pragma region Helper
	auto syscallHelper = new CSyscallHelper();

	auto dwIndex = syscallHelper->FindSysCall("NtWriteVirtualMemory");
	if (!dwIndex) {
		printf("FindSysCall(NtWriteVirtualMemory) fail! Err: %u", dwIndex);
		delete syscallHelper;
		return 0;
	}
	g_dwSyscallIndexOfNtWriteVirtualMemory = dwIndex;


	auto dwIndex2 = syscallHelper->FindSysCall("NtSuspendProcess");
	if (!dwIndex2) {
		printf("FindSysCall(NtSuspendProcess) fail! Err: %u", dwIndex2);
		delete syscallHelper;
		return 0;
	}
	g_dwSyscallIndexOfNtSuspendProcess = dwIndex2;
#pragma endregion Helper



#pragma region Core
	auto hookCore = new CHookCore();

	g_lpBaseAddress = hookCore->CreateTrampoline();
	hookCore->EnableTrampoline(&Wow64Trampoline);
#pragma endregion Core


#pragma region Test
	// Init
	hNtdll = LoadLibraryA("ntdll");
	assert(hNtdll);

	NtWriteVirtualMemory = (lpNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	assert(NtWriteVirtualMemory);
	NtSuspendProcess = (lpNtSuspendProcess)GetProcAddress(hNtdll, "NtSuspendProcess");
	assert(NtSuspendProcess);


	/// Work
	auto j = 0x500;
	while (1) {
		NtWriteVirtualMemory(GetCurrentProcess(), &j, &j, sizeof(j), nullptr);
		printf("j = 0x%X\n", j++);

		SuspendSelf();

		Sleep(5000);
	}
#pragma endregion Test




	// Final
	delete hookCore;
	delete syscallHelper;
	return 0;
}