#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>


namespace HookCore
{
	class CHookCore
	{
		public:
			CHookCore();
			~CHookCore();

			LPVOID CreateTrampoline();
			void EnableTrampoline(LPVOID pTrampolineAddr);

		protected:
			void WriteJump(LPVOID pWow64Address, DWORD dwSize, LPCVOID c_pBuffer, size_t uiSize);
			LPVOID CreateNewJump(LPCVOID c_pWow64Address, DWORD dwSize, size_t uiNumOfWow64Bytes);
			void EnableWow64Redirect(LPVOID pWow64Address, DWORD dwSize, LPCVOID c_pNewJumpLocation);

		private:
			HMODULE m_hNtdll;
			DWORD	m_dwWow64Address;
			LPVOID	m_pBaseAddress;
	};
}

