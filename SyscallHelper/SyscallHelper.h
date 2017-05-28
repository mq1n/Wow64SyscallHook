#pragma once

#include <Windows.h>
#include <vector>

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

typedef struct _syscall_index_list
{
	DWORD dwFunc;
	DWORD dwWinXPSP0;
	DWORD dwWinXpSP1;
	DWORD dwWinXpSP2;
	DWORD dwWinXPSP3;
	DWORD dwWinVistaSP0;
	DWORD dwWinVistaSP1;
	DWORD dwWinVistaSP2;
	DWORD dwWinSevenSP0;
	DWORD dwWinSevenSP1;
	DWORD dwWinEight;
	DWORD dwWinEightPointOne;
	DWORD dwWinTenBuild1507;
	DWORD dwWinTenBuild1511;
	DWORD dwWinTenBuild1607;
	DWORD dwWinTenBuild1703;
} SSyscallIndexList, *PSyscallIndexList;


namespace SyscallHelper
{
	class CSyscallHelper
	{
		public:
			CSyscallHelper();
			~CSyscallHelper();

			DWORD FindSysCall(std::string szFunction);

		protected:
			void BuildSyscallList();
			void DestroySyscallList();

			void RegisterSyscall(std::string szFunction,
				DWORD dwXPsp0idx, DWORD dwXPsp1idx, DWORD dwXPsp2idx, DWORD dwXPsp3idx,
				DWORD dwVistaSp0idx, DWORD dwVistaSp1idx, DWORD dwVistaSp2idx,
				DWORD dwSevenSp0idx, DWORD dwSevenSp1idx,
				DWORD dwEightidx, DWORD dwEightPointOneIdx,
				DWORD dwTenBuild1507Idx, DWORD dwTenBuild1511Idx, DWORD dwTenBuild1607Idx, DWORD dwTenBuild1703Idx);
	};
}

