#include "HookCore.h"

static DWORD g_dwWow64Address = 0x0;


HookCore::CHookCore::CHookCore()
{
	m_hNtdll			= LoadLibraryA("ntdll.dll");

	__asm {
		push dword ptr fs : [0xC0]
		pop  dword ptr[g_dwWow64Address]
	}
	m_dwWow64Address = g_dwWow64Address;

	m_pBaseAddress = nullptr;
}
HookCore::CHookCore::~CHookCore()
{
	g_dwWow64Address = 0x0;

	if (m_hNtdll)
		FreeLibrary(m_hNtdll);

	m_dwWow64Address = 0x0;

	if (m_pBaseAddress) {
		VirtualFree(m_pBaseAddress, 0x1000, MEM_RELEASE);
		m_pBaseAddress = nullptr;
	}
}


LPVOID HookCore::CHookCore::CreateTrampoline()
{
	auto pBaseAddr = CreateNewJump((LPVOID)m_dwWow64Address, 0x1000, 0x9);
	return pBaseAddr;
}

void HookCore::CHookCore::EnableTrampoline(LPVOID pTrampolineAddr)
{
	EnableWow64Redirect((LPVOID)m_dwWow64Address, 0x1000, pTrampolineAddr);
}



void HookCore::CHookCore::WriteJump(LPVOID pWow64Address, DWORD dwSize, LPCVOID c_pBuffer, size_t uiSize)
{
	DWORD dwOldProtect = 0;
	VirtualProtect(pWow64Address, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(pWow64Address, c_pBuffer, uiSize);
	VirtualProtect(pWow64Address, dwSize, dwOldProtect, &dwOldProtect);
}

LPVOID HookCore::CHookCore::CreateNewJump(LPCVOID c_pWow64Address, DWORD dwSize, size_t uiNumOfWow64Bytes)
{
	m_pBaseAddress = VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(m_pBaseAddress, c_pWow64Address, uiNumOfWow64Bytes);
	return m_pBaseAddress;
}

void HookCore::CHookCore::EnableWow64Redirect(LPVOID pWow64Address, DWORD dwSize, LPCVOID c_pNewJumpLocation)
{
	BYTE byTrampolineBytes[] =
	{
		0x68, 0xDD, 0xCC, 0xBB, 0xAA,
		0xC3,
		0xCC, 0xCC, 0xCC
	};

	memcpy(&byTrampolineBytes[1], &c_pNewJumpLocation, sizeof(c_pNewJumpLocation));

	WriteJump(pWow64Address, dwSize, byTrampolineBytes, sizeof(byTrampolineBytes));
}

