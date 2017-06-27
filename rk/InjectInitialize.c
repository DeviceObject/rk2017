#include "rk.h"
#include "InjectKtrapFrame.h"
#include "GetProcAddr.h"
#include "InjectInitialize.h"

BOOLEAN InitializeInjectDllPath(PINJECT_OBJECT_INFORMATION pInjectObjInfo,CHAR *InjectDllPath)
{
	if (NULL == pInjectObjInfo)
	{
		return FALSE;
	}
	RtlZeroMemory(pInjectObjInfo->InjectDllPath,100);
	RtlCopyMemory(pInjectObjInfo->InjectDllPath,InjectDllPath,strlen(InjectDllPath));
	return TRUE;
}
BOOLEAN InitializeInjectApiList(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PINJECT_API_LIST pInjectApiList)
{
#ifndef __x86_64__
	PVOID pBaseAddr;
	PCHAR pTmp;
	SHORT Index;
	KAPC_STATE ApcState;
	
	Index = 0;
	if (NULL == pInjectObjInfo || \
		NULL == pInjectApiList)
	{
		return FALSE;
	}
	KeStackAttachProcess(pInjectObjInfo->pInjectProcess,&ApcState);
	pBaseAddr = (PVOID)GetModuleBaseFromPeb(pInjectObjInfo,"ntdll.dll");
	if (NULL == pBaseAddr)
	{
		KeUnstackDetachProcess(&ApcState);
		return FALSE;
	}
	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwSuspendThread");
	if (pTmp)
	{
		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
		pInjectApiList->StdCallKeSuspendThread =  \
			(STDCALL_NTSUSPENDTHREAD)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
	}

	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwResumeThread");
	if (pTmp)
	{
		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
		pInjectApiList->StdCallKeResumeThread =  \
			(STDCALL_NTSUSPENDTHREAD)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
	}

	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwProtectVirtualMemory");
	if (pTmp)
	{
		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
		pInjectApiList->StdCallNtProtectVirtualMemory =  \
			(STDCALL_NTPROTECTVIRTUALMEMORY)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
	}

	pBaseAddr = (PVOID)GetModuleBaseFromPeb(pInjectObjInfo,"kernel32.dll");
	if (NULL == pBaseAddr)
	{
		KeUnstackDetachProcess(&ApcState);
		return FALSE;
	}
	g_InjectAplList.ulx86LoadLibrary = GetExportFunction(pBaseAddr,"LoadLibraryA");
	if ((ULONG_PTR)NULL == g_InjectAplList.ulx86LoadLibrary)
	{
		KeUnstackDetachProcess(&ApcState);
		return FALSE;
	}
	KeUnstackDetachProcess(&ApcState);
	if (/*pInjectApiList->FastCallKeSuspendThread && \
		pInjectApiList->FastCallKeResumeThread && \*/
		pInjectApiList->StdCallKeSuspendThread && \
		pInjectApiList->StdCallKeResumeThread/* && \
		pInjectApiList->bInitialize == FALSE*/)
	{
		pInjectApiList->bInitialize = TRUE;
		return TRUE;
	}
#endif
	return FALSE;
}
//BOOLEAN InitializeInjectApiList(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PINJECT_API_LIST pInjectApiList)
//{
//	PVOID pBaseAddr;
//	PCHAR pTmp;
//	SHORT Index;
//	KAPC_STATE ApcState;
//	
//	Index = 0;
//	if (NULL == pInjectObjInfo || \
//		NULL == pInjectApiList)
//	{
//		return FALSE;
//	}
//	KeStackAttachProcess(pInjectObjInfo->pInjectProcess,&ApcState);
//	pBaseAddr = (PVOID)GetModuleBaseFromPeb(pInjectObjInfo,"ntdll.dll");
//	if (NULL == pBaseAddr)
//	{
//		KeUnstackDetachProcess(&ApcState);
//		return FALSE;
//	}
//	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwSuspendThread");
//	if (pTmp)
//	{
//		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
//		pInjectApiList->StdCallKeSuspendThread =  \
//			(STDCALL_NTSUSPENDTHREAD)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
//	}
//
//	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwResumeThread");
//	if (pTmp)
//	{
//		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
//		pInjectApiList->StdCallKeResumeThread =  \
//			(STDCALL_NTSUSPENDTHREAD)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
//	}
//
//	pTmp = (PCHAR)GetExportFunction(pBaseAddr,"ZwProtectVirtualMemory");
//	if (pTmp)
//	{
//		Index = *(USHORT*)((ULONG_PTR)pTmp + 1);
//		pInjectApiList->StdCallNtProtectVirtualMemory =  \
//			(STDCALL_NTPROTECTVIRTUALMEMORY)*(ULONG_PTR *)((ULONG_PTR)KeServiceDescriptorTable->pServiceTableBase + Index * 4);
//	}
//
//	pBaseAddr = (PVOID)GetModuleBaseFromPeb(pInjectObjInfo,"kernel32.dll");
//	if (NULL == pBaseAddr)
//	{
//		KeUnstackDetachProcess(&ApcState);
//		return FALSE;
//	}
//	g_InjectAplList.ulx86LoadLibrary = GetExportFunction(pBaseAddr,"LoadLibraryA");
//	if ((ULONG_PTR)NULL == g_InjectAplList.ulx86LoadLibrary)
//	{
//		KeUnstackDetachProcess(&ApcState);
//		return FALSE;
//	}
//	KeUnstackDetachProcess(&ApcState);
//	if (/*pInjectApiList->FastCallKeSuspendThread && \
//		pInjectApiList->FastCallKeResumeThread && \*/
//		pInjectApiList->StdCallKeSuspendThread && \
//		pInjectApiList->StdCallKeResumeThread/* && \
//		pInjectApiList->bInitialize == FALSE*/)
//	{
//		pInjectApiList->bInitialize = TRUE;
//		return TRUE;
//	}
//	return FALSE;
//}
//BOOLEAN InitializeInjectApiList(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PINJECT_API_LIST pInjectApiList)
//{
//	UNICODE_STRING unStrNtdll32;
//	UNICODE_STRING unStrNtdll64;
//	ULONG_PTR ulAddress;
//	ULONG64 ulAddress64;
//	USHORT Index;
//	if (NULL == pInjectApiList)
//	{
//		return FALSE;
//	}
//	ulAddress = 0;
//	Index = 0;
//	RtlZeroMemory(pInjectApiList,sizeof(INJECT_API_LIST));
//	RtlInitUnicodeString(&unStrNtdll32,L"\\??\\C:\\Windows\\System32\\ntdll.dll");
//	RtlInitUnicodeString(&unStrNtdll64,L"\\??\\C:\\Windows\\SysWOW64\\ntdll.dll");
//	
//	ulAddress = GetDllFunctionAddress("ZwSuspendThread",&unStrNtdll32);
//	Index = *(SHORT*)ulAddress + 1;
//	pInjectApiList->StdCallKeSuspendThread =  \
//		(STDCALL_ZWSUSPENDTHREAD)*((PUCHAR)KeServiceDescriptorTable->pServiceTableBase + Index);
//
//	ulAddress = GetDllFunctionAddress("ZwResumeThread",&unStrNtdll32);
//	Index = *(SHORT*)ulAddress + 1;
//	pInjectApiList->StdCallKeResumeThread =  \
//		(STDCALL_ZWSUSPENDTHREAD)*((PUCHAR)KeServiceDescriptorTable->pServiceTableBase + Index);
//
//	//64bits,����϶�������,�������
//	ulAddress64 = GetDllFunctionAddress("ZwSuspendThread",&unStrNtdll64);
//	Index = *(SHORT*)ulAddress64 + 1;
//	pInjectApiList->FastCallKeSuspendThread =  \
//		(FASTCALL_ZWSUSPENDTHREAD)*((PUCHAR)KeServiceDescriptorTable->pServiceTableBase + Index);
//
//	ulAddress64 = GetDllFunctionAddress("ZwResumeThread",&unStrNtdll64);
//	Index = *(SHORT*)ulAddress64 + 1;
//	pInjectApiList->FastCallKeSuspendThread =  \
//		(FASTCALL_ZWSUSPENDTHREAD)*((PUCHAR)KeServiceDescriptorTable->pServiceTableBase + Index);
//
//	if (/*pInjectApiList->FastCallKeSuspendThread && \
//		pInjectApiList->FastCallKeResumeThread && \*/
//		pInjectApiList->StdCallKeSuspendThread && \
//		pInjectApiList->StdCallKeResumeThread && \
//		pInjectApiList->bInitialize == FALSE)
//	{
//		pInjectApiList->bInitialize = TRUE;
//		return TRUE;
//	}
//	return FALSE;
//}