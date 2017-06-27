#include "stdafx.h"
#include "DrvDat.h"
#include "Utils.h"
#include "LoadDrv.h"

HANDLE g_hDevice = NULL;

BOOL Unpack()
{
	BOOL bRet = FALSE;
	ULONG ulRetReadBytes = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WCHAR wSysDir[MAX_PATH] = {0};
	WCHAR SysPath[MAX_PATH] = {0};

	GetSystemDirectoryW(wSysDir,MAX_PATH);
	wsprintfW(SysPath,L"%s\\%s",wSysDir,DRIVER_NAMEW L".sys");

	hFile = CreateFileW(SysPath, \
		FILE_ALL_ACCESS, \
		FILE_SHARE_READ | FILE_SHARE_WRITE, \
		NULL, \
		CREATE_ALWAYS, \
		FILE_ATTRIBUTE_NORMAL, \
		NULL);
	if (FALSE == hFile)
	{
		return bRet;
	}
	bRet = WriteFile(hFile, \
		g_DrvDat, \
		RK2017_DRV_LENGTH, \
		&ulRetReadBytes, \
		NULL);
	if (FALSE == bRet)
	{
		if (hFile)
		{
			CloseHandle(hFile);
			hFile = NULL;
		}
		return bRet;
	}
	if (hFile)
	{
		CloseHandle(hFile);
		hFile = NULL;
	}
	return bRet;
}
BOOLEAN InstallAndLdrDrv()
{
	WCHAR SysPath[MAX_PATH] = {0};
	CHAR DrvPath[MAX_PATH] = {0};
	ULONG ulLdrCnt;
	BOOLEAN bRet = FALSE;

	if(!Unpack())
	{
		return FALSE;
	}
	wsprintfW(SysPath,L"%s\\%s",L"\\SystemRoot\\System32",DRIVER_NAMEW L".sys");
	RtlZeroMemory(DrvPath,MAX_PATH);
	UnicodeToAnsi(SysPath,DrvPath,MAX_PATH);

	for (ulLdrCnt = 0;ulLdrCnt < 0x100;ulLdrCnt++)
	{
		if (MiniFilerLoadDrv(DRIVER_NAMEA,DrvPath,"370090") == TRUE)
		{
			bRet = TRUE;
			break;
		}
		Sleep(1000);
	}
	return bRet;
}
HANDLE OpenDevice()
{
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	WCHAR DeviceName[MAX_PATH]  = {0};
	if((GetVersion() & 0xFF) >= 5)
	{
		wsprintfW(DeviceName,L"\\\\.\\Global\\%s",RK2017_BASENAME);
	}
	else
	{
		wsprintfW(DeviceName,L"\\\\.\\%s",RK2017_BASENAME);
	}
	hDevice = CreateFileW(DeviceName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if(hDevice==INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	return hDevice;
}

BOOL CheckServiceIsExist(PCHAR pServiceName)
{
	SC_HANDLE hScManager = OpenSCManagerA(NULL,NULL,GENERIC_EXECUTE);
	if(hScManager == NULL)
	{
		return FALSE;
	}
	SC_HANDLE hScService = OpenServiceA(hScManager,pServiceName,SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
	if(hScService == NULL)
	{
		CloseServiceHandle(hScManager);
		return FALSE;
	}
	CloseServiceHandle(hScService);
	CloseServiceHandle(hScManager);
	return TRUE;
}
BOOL CheckServiceIsRun(PCHAR pServiceName) 
{ 
	BOOL bRet = FALSE;
	SC_HANDLE hScManager,hScService; 
	SERVICE_STATUS ServiceStatus; 
	hScManager = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS); 
	if(hScManager != NULL) 
	{ 
		hScService = OpenServiceA(hScManager,pServiceName,SERVICE_QUERY_STATUS); 
		if(hScService != NULL) 
		{ 
			QueryServiceStatus(hScService,&ServiceStatus); 
			if(ServiceStatus.dwCurrentState == SERVICE_RUNNING) 
			{
				bRet = TRUE;
			}
			CloseServiceHandle(hScService); 
		} 
		CloseServiceHandle(hScManager); 
	} 	
	return bRet;
}
BOOL InstallMiniDriver(const char* lpszDriverName,const char* lpszDriverPath,const char* lpszAltitude)
{
	char szTempStr[MAX_PATH];
	HKEY hKey;
	DWORD dwData;
	//char szDriverImagePath[MAX_PATH];
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hService = NULL;

	if(NULL == lpszDriverName || NULL == lpszDriverPath)
	{
		return FALSE;
	}
	//GetFullPathNameA(lpszDriverPath,MAX_PATH,szDriverImagePath,NULL);
	hServiceMgr = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if(hServiceMgr == NULL) 
	{
		CloseServiceHandle(hServiceMgr);
		return FALSE;        
	}
	hService = CreateServiceA(hServiceMgr,
		lpszDriverName,
		lpszDriverName,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_SYSTEM_START,
		SERVICE_ERROR_NORMAL,
		lpszDriverPath,
		"FSFilter Activity Monitor",
		NULL, 
		"FltMgr",
		NULL, 
		NULL);

	if(hService == NULL) 
	{        
		if(GetLastError() == ERROR_SERVICE_EXISTS) 
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hServiceMgr);
			return TRUE; 
		}
		else 
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hServiceMgr);
			return FALSE;
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hServiceMgr);

	strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr,"\\Instances");
	if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,szTempStr,0,"",REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	strcpy(szTempStr,lpszDriverName);
	strcat(szTempStr," Instance");
	if(RegSetValueExA(hKey,"DefaultInstance",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);
	RegCloseKey(hKey);

	strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr,"\\Instances\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr," Instance");
	if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,szTempStr,0,"",REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	strcpy(szTempStr,lpszAltitude);
	if(RegSetValueExA(hKey,"Altitude",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	dwData = 0x0;
	if(RegSetValueExA(hKey,"Flags",0,REG_DWORD,(CONST BYTE*)&dwData,sizeof(DWORD))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);
	RegCloseKey(hKey);
	return TRUE;
}
BOOL StartMiniDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

	if(NULL==lpszDriverName)
	{
		return FALSE;
	}

	schManager = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	schService = OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL == schService)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if(!StartServiceA(schService,0,NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) 
		{             
			return TRUE;
		} 
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);
	return TRUE;
}
BOOL StopMiniDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;
	bool            bStopped=false;

	schManager=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		return FALSE;
	}
	schService=OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL==schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}    
	if(!ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus) && (svcStatus.dwCurrentState!=SERVICE_STOPPED))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}
BOOL DeleteMiniDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

	schManager=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		return FALSE;
	}
	schService=OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL==schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus);
	if(!DeleteService(schService))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}
BOOLEAN MiniFilerLoadDrv(PCHAR pDriverName,PCHAR pDriverPath,PCHAR pAltitude)
{
	BOOLEAN bRet;

	bRet = FALSE;

	if (InstallMiniDriver(pDriverName,pDriverPath,pAltitude) == TRUE)
	{
		bRet = StartMiniDriver(pDriverName);
	}
	else
	{
		bRet = StartMiniDriver(pDriverName);
		if (bRet == FALSE)
		{
			StopMiniDriver(pDriverName);
			DeleteMiniDriver(pDriverName);
			if (InstallMiniDriver(pDriverName,pDriverPath,pAltitude) == TRUE)
			{
				bRet = StartMiniDriver(pDriverName);
			}
		}
	}

	//if (CheckServiceIsExist(pDriverName))
	//{
	//	bRet = StartMiniDriver(pDriverName);
	//	if (bRet == FALSE)
	//	{
	//		StopMiniDriver(pDriverName);
	//		DeleteMiniDriver(pDriverName);
	//		if (InstallMiniDriver(pDriverName,pDriverPath,pAltitude) == TRUE)
	//		{
	//			bRet = StartMiniDriver(pDriverName);
	//		}
	//	}
	//}
	return bRet;
}