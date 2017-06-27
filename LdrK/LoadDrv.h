#ifndef __LOAD_DRV_H__
#define __LOAD_DRV_H__

#define DRIVER_NAMEA "rk"
#define DRIVER_NAMEW L"rk"
#define SERVICE_KEY L"SYSTEM\\CurrentControlSet\\Services\\" DRIVER_NAMEW

BOOL Unpack();
BOOLEAN InstallAndLdrDrv();
HANDLE OpenDevice();
BOOL CheckServiceIsExist(PCHAR pServiceName);
BOOL CheckServiceIsRun(PCHAR pServiceName) ;
BOOL DeleteMiniDriver(const char* lpszDriverName);
BOOL StopMiniDriver(const char* lpszDriverName);
BOOL StartMiniDriver(const char* lpszDriverName);
BOOL InstallMiniDriver(const char* lpszDriverName,const char* lpszDriverPath,const char* lpszAltitude);
BOOLEAN MiniFilerLoadDrv(PCHAR pDriverName,PCHAR pDriverPath,PCHAR pAltitude);

extern HANDLE g_hDevice;

#endif