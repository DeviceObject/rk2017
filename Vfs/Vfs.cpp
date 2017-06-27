#include "Vfs.h"
#include "Guid.h"
#include "Setup.h"
#include "UAC.h"
#include "Time.h"



HANDLE g_VfsHandle = NULL;
PWCHAR g_VfsRootName = NULL;


PVOID AllocateMemory(ULONG ulSize)
{
	return VirtualAlloc(NULL,ulSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
}
BOOLEAN FreeMemory(PVOID pFreeMemory)
{
	return VirtualFree(pFreeMemory,0,MEM_RELEASE);
}
PWCHAR GenFsDeviceName()
{
	ULONG ulSystemTimeStamp;
	PWCHAR pGuidName;
	PWCHAR pDeviceName;
	GUID Guid;

	pDeviceName = NULL;
	pGuidName = NULL;
	ulSystemTimeStamp = 0;

	ulSystemTimeStamp = GetSystemTimeStamp();
	GenGuid(&Guid,&ulSystemTimeStamp);
	if (pGuidName = GuidToString(&Guid))
	{
		if (pDeviceName = (PWCHAR)VfsAllocate((wcslen(VFS_ROOT_FORMAT) + GUID_STR_LEN + 1) * sizeof(WCHAR)))
		{
			wsprintf(pDeviceName,VFS_ROOT_FORMAT,pGuidName);
		}
		else
		{
			VfsFree((PCHAR)pGuidName);
		}
	}
	return pDeviceName;
}
BOOLEAN VfsCreateDevice()
{
	BOOLEAN	bRet = FALSE;
	HANDLE hFile;

	hFile = CreateFile(g_VfsRootName, \
		GENERIC_READ | GENERIC_WRITE, \
		FILE_SHARE_READ | FILE_SHARE_WRITE, \
		NULL, OPEN_ALWAYS, \
		FILE_ATTRIBUTE_DIRECTORY, \
		0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		bRet = TRUE;
	}
	return bRet;
}
PCHAR VfsAllocate(ULONG ulSize)
{
	HANDLE hCurHeap = NULL;
	PCHAR pRetBuf = NULL;

	hCurHeap = GetProcessHeap();
	if (NULL == hCurHeap)
	{
		return NULL;
	}
	pRetBuf = (PCHAR)HeapAlloc(hCurHeap,HEAP_ZERO_MEMORY,ulSize);
	if (NULL == pRetBuf)
	{
		return NULL;
	}
	return pRetBuf;
}
BOOLEAN VfsFree(PCHAR pFreeBuf)
{
	HANDLE hCurHeap = NULL;
	BOOLEAN bRet = FALSE;

	hCurHeap = GetProcessHeap();
	if (NULL == hCurHeap)
	{
		return FALSE;
	}
	bRet = HeapFree(hCurHeap,HEAP_ZERO_MEMORY,pFreeBuf);
	if (bRet == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}
#ifndef VFS_ENTRY
int main(ULONG ulArgc, PCHAR pArgv[])
{
	PWCHAR pKeyNameW,pMutexNameW;
	ULONG ulStatus;
	HKEY hKey;
	HANDLE hMutex;
	ULONG ulOsVersion;
	BYTE bVersionHigh,bVersionLow;
	BOOLEAN bElevated;

	pKeyNameW = NULL;
	pMutexNameW = NULL;
	hMutex = NULL;
	ulOsVersion = 0;
	bElevated = TRUE;
	
	do 
	{
		if (!GetProgramKeyName(&pKeyNameW,&pMutexNameW))
		{
			ulStatus = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		if (!(hMutex = CreateMutex(NULL,TRUE,pMutexNameW)) || ((ulStatus = GetLastError()) == ERROR_ALREADY_EXISTS))
		{
			ulStatus = ERROR_SERVICE_ALREADY_RUNNING;
			break;		
		}
		if (RegOpenKey(HKEY_LOCAL_MACHINE,pKeyNameW,&hKey) == NO_ERROR)
		{
			RegCloseKey(hKey);
			ulStatus = ERROR_ALREADY_EXISTS;
			break;
		}
		ulOsVersion = GetVersion();
		bVersionHigh = LOBYTE(LOWORD(ulOsVersion));
		bVersionLow = HIBYTE(LOWORD(ulOsVersion));

		// Checking if current OS supported
		if ((bVersionHigh == 5 && bVersionLow == 0) || bVersionHigh < 5 || bVersionHigh > 6)
		{
			ulStatus = ERROR_OLD_WIN_VERSION;
			break;
		}
		// Running as separate executable
		if (bVersionHigh == 6)
		{
			// For Vista and higher:
			// Checking for UAC elevated token
			HANDLE hToken;
			ULONG ulSize;

			bElevated = FALSE;
			if (OpenProcessToken(GetCurrentProcess(),READ_CONTROL | TOKEN_QUERY,&hToken))
			{
				GetTokenInformation(hToken,(TOKEN_INFORMATION_CLASS)20,&bElevated,sizeof(BOOLEAN),&ulSize);
				CloseHandle(hToken);
			}
		}
		if (!bElevated)
		{
			CloseHandle(hMutex);
			hMutex = 0;
			RequestUac();
			ulStatus = ERROR_ACCESS_DENIED;
			break;
		}
		
	} while (0);
}
#else
int main(ULONG ulArgc, PCHAR pArgv[])
{
	BOOLEAN bRet = FALSE;

	if (g_VfsRootName = GenFsDeviceName())
	{
		bRet = VfsCreateDevice();
	}

	return 0;
}
#endif


