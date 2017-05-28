#include "SyscallHelper.h"

static std::vector< PSyscallIndexList > vSyscallList;


static DWORD GetStringHash(LPVOID lpBuffer, BOOL bUnicode, UINT uLen)
{
	DWORD dwHash = 0;
	LPSTR strBuffer = (LPSTR)lpBuffer;

	while (uLen--)
	{
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += (DWORD)*strBuffer++;

		if (bUnicode)
			strBuffer++;
	}
	return dwHash;
}

static bool GetVersionInfo(LPDWORD pDwGetMajorVersion, LPDWORD pDwGetMinorVersion, LPDWORD pDwGetBuildNumber, LPDWORD pDwSPMajor, LPDWORD pDwSpMinor)
{
	auto hNtdll = LoadLibraryA("ntdll");
	if (!hNtdll) return false;

	typedef NTSTATUS(NTAPI* lpRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
	auto RtlGetVersion = (lpRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
	if (!RtlGetVersion) return false;

	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	if (RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo) != 0) return false;
	
	if (pDwGetMajorVersion)
		*pDwGetMajorVersion = verInfo.dwMajorVersion;
	if (pDwGetMinorVersion)
		*pDwGetMinorVersion = verInfo.dwMinorVersion;
	if (pDwGetBuildNumber)
		*pDwGetBuildNumber = verInfo.dwBuildNumber;
	if (pDwSPMajor)
		*pDwSPMajor = verInfo.wServicePackMajor;
	if (pDwSpMinor)
		*pDwSpMinor = verInfo.wServicePackMinor;

	return true;
}



SyscallHelper::CSyscallHelper::CSyscallHelper()
{
	BuildSyscallList();
}
SyscallHelper::CSyscallHelper::~CSyscallHelper()
{
	DestroySyscallList();
}


void SyscallHelper::CSyscallHelper::RegisterSyscall(
	std::string szFunction,
	DWORD dwXPsp0idx, DWORD dwXPsp1idx, DWORD dwXPsp2idx, DWORD dwXPsp3idx,
	DWORD dwVistaSp0idx, DWORD dwVistaSp1idx, DWORD dwVistaSp2idx, 
	DWORD dwSevenSp0idx, DWORD dwSevenSp1idx, 
	DWORD dwEightidx, DWORD dwEightPointOneIdx, 
	DWORD dwTenBuild1507Idx, DWORD dwTenBuild1511Idx, DWORD dwTenBuild1607Idx, DWORD dwTenBuild1703Idx)
{
	auto sycallIndexList = (PSyscallIndexList)malloc(sizeof(SSyscallIndexList));


	sycallIndexList->dwFunc = GetStringHash((LPVOID)szFunction.c_str(), FALSE, szFunction.size());

	sycallIndexList->dwWinXPSP0 = dwXPsp0idx;
	sycallIndexList->dwWinXpSP1 = dwXPsp1idx;
	sycallIndexList->dwWinXpSP2 = dwXPsp2idx;
	sycallIndexList->dwWinXPSP3 = dwXPsp3idx;

	sycallIndexList->dwWinVistaSP0 = dwVistaSp0idx;
	sycallIndexList->dwWinVistaSP1 = dwVistaSp1idx;
	sycallIndexList->dwWinVistaSP2 = dwVistaSp2idx;

	sycallIndexList->dwWinSevenSP0 = dwSevenSp0idx;
	sycallIndexList->dwWinSevenSP1 = dwSevenSp1idx;

	sycallIndexList->dwWinEight = dwEightidx;
	sycallIndexList->dwWinEightPointOne = dwEightPointOneIdx;

	sycallIndexList->dwWinTenBuild1507 = dwTenBuild1507Idx;
	sycallIndexList->dwWinTenBuild1511 = dwTenBuild1511Idx;
	sycallIndexList->dwWinTenBuild1607 = dwTenBuild1607Idx;
	sycallIndexList->dwWinTenBuild1703 = dwTenBuild1703Idx;


	vSyscallList.push_back(sycallIndexList);
}

DWORD SyscallHelper::CSyscallHelper::FindSysCall(std::string szFunction)
{
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuildNumber = 0;
	DWORD dwMajorSPVersion = 0;
	DWORD dwMinorSPVersion = 0;

	auto bOSInformationRet = GetVersionInfo(&dwMajorVersion, &dwMinorVersion, &dwBuildNumber, &dwMajorSPVersion, &dwMinorSPVersion);
	if (bOSInformationRet == false) {
		printf("bOSInformationRet fail!\n");
		return 0;
	}
	auto dwFunctionHash = GetStringHash((LPVOID)szFunction.c_str(), FALSE, szFunction.size());
	if (!dwFunctionHash) {
		printf("dwFunctionHash fail!\n");
		return 0;
	}

	for (auto &pSyscall : vSyscallList)
	{
		if (pSyscall->dwFunc == dwFunctionHash)
		{
			if (dwMajorVersion == 10) {
				if (dwBuildNumber == 10240)
					return pSyscall->dwWinTenBuild1507;
				else if (dwBuildNumber == 10586)
					return pSyscall->dwWinTenBuild1511;
				else if (dwBuildNumber == 14393)
					return pSyscall->dwWinTenBuild1607;
				else if (dwBuildNumber == 15063)
					return pSyscall->dwWinTenBuild1703;
			}

			else if (dwMajorVersion == 6) {
				if (dwMinorVersion == 0) {
					if (dwMajorSPVersion == 2)
						return pSyscall->dwWinVistaSP2;
					else if (dwMajorSPVersion == 1)
						return pSyscall->dwWinVistaSP1;
					else if (dwMajorSPVersion == 0)
						return pSyscall->dwWinVistaSP0;
				}

				else if (dwMinorVersion == 1) {
					if (dwMajorSPVersion == 1)
						return pSyscall->dwWinSevenSP1;
					else if (dwMajorSPVersion == 0)
						return pSyscall->dwWinSevenSP0;
				}

				else if (dwMinorVersion == 2)
					return pSyscall->dwWinEight;

				else if (dwMinorVersion == 3)
					return pSyscall->dwWinEightPointOne;
			}

			else if (dwMajorVersion == 5 && dwMinorVersion == 1) {
				if (dwMajorSPVersion == 3)
					return pSyscall->dwWinXPSP3;
				else if (dwMajorSPVersion == 2)
					return pSyscall->dwWinXpSP2;
				else if (dwMajorSPVersion == 1)
					return pSyscall->dwWinXpSP1;
				else if (dwMajorSPVersion == 0)
					return pSyscall->dwWinXPSP0;
			}
		}
	}

	printf("Unknown OS! %u - %u - %u - %u - %u\n",
		dwMajorVersion, dwMinorVersion, dwBuildNumber, dwMajorSPVersion, dwMinorSPVersion);
	return 0;
}


void SyscallHelper::CSyscallHelper::BuildSyscallList()
{
	/*
	Function,
	XP Index List,
	Vista Index List,
	7 Index List,
	8 Index List,
	10 Index List
	*/

	RegisterSyscall("NtWriteVirtualMemory", 
		0x0037, 0x0037, 0x0037, 0x0037,
		0x0037, 0x0037, 0x0037, 
		0x0037, 0x0037,
		0x0038, 0x0039,
		0x003a, 0x003a, 0x003a, 0x003a
	);
	RegisterSyscall("NtSuspendProcess",
		0x0117, 0x0117, 0x0117, 0x0117,
		0x0178, 0x0171, 0x0171,
		0x017a, 0x017a,
		0x0192, 0x0197,
		0x019f, 0x01a2, 0x01a8, 0x01ae
	);
}

void SyscallHelper::CSyscallHelper::DestroySyscallList()
{
	for (auto &pSyscall : vSyscallList)
		free(pSyscall);
	vSyscallList.clear();
}


