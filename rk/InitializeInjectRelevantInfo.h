#ifndef ITIALIZE_INJECT_RELEVANT_INFO__
#define ITIALIZE_INJECT_RELEVANT_INFO__

typedef struct _RK_SYSTEM_VERSION
{
	ULONG ulMajorVersion;
	ULONG ulMinorVersion;
	ULONG ulBuildNumber;
	PUNICODE_STRING unStrCSDVersion;
}RK_SYSTEM_VERSION,*PRK_SYSTEM_VERSION;

typedef struct _CM_KEY_OFFSET
{
	ULONG ulOffsetKeyHive;
	ULONG ulOffsetKeyCell;
	ULONG ulOffsetCellRoutine;
}CM_KEY_OFFSET,*PCM_KEY_OFFSET;

typedef struct _STORE_PROCESS_INFORMATION
{
	HANDLE hProcessId;
}STORE_PROCESS_INFORMATION,*PSTORE_PROCESS_INFORMATION;

typedef struct _WINDOWS_VERSION
{
#ifndef _WIN64
	ULONG_PTR ulReserved:20;
#else
	ULONG_PTR ulReserved:52;
#endif
	ULONG_PTR bIsUnknow:1;
	ULONG_PTR bIsWindows2000:1;
	ULONG_PTR bIsWindowsXp:1;
	ULONG_PTR bIsWindows2003:1;
	ULONG_PTR bIsWindowsVista:1;
	ULONG_PTR bIsWindows7:1;
	ULONG_PTR bIsWindows2008:1;
	ULONG_PTR bIsWindows8:1;
	ULONG_PTR bIsWindows81:1;
	ULONG_PTR bIsWindows10:1;
	ULONG_PTR bIsWindows2012:1;
	ULONG_PTR bIs64Bit:1;
}WINDOWS_VERSION,*PWINDOWS_VERSION;

typedef struct _INJECT_RELEVANT_OFFSET
{
	//Process
	ULONG_PTR ulOffsetPeb;
	ULONG_PTR ulOffsetName;
	ULONG_PTR ulOffsetFlink;
	ULONG_PTR ulOffsetResv;
	ULONG_PTR ulOffsetThreadListHead;
	ULONG_PTR ulOffsetPid;

	//Thread
	ULONG_PTR ulOffsetThreadListEntry;
	ULONG_PTR ulOffsetSuspendCount;
	ULONG_PTR ulOffsetCrossThreadFlags;
	ULONG_PTR ulOffsetCid;
	ULONG_PTR ulOffsetTrapFrame;
	ULONG_PTR ulOffsetTeb;

	//PEB
	ULONG_PTR ulOffsetPebLdr;
	ULONG_PTR ulOffsetPebModuleListEntry;

	//Teb
	ULONG_PTR ulOffsetActivationContextStackPointer;
	
	WINDOWS_VERSION WindowsVersion;

	STORE_PROCESS_INFORMATION StoreProcessExplorer;

	CM_KEY_OFFSET CmKeyOffset;

	PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer;
	//PVOID PspTerminateThreadByPointer;
}INJECT_RELEVANT_OFFSET,*PINJECT_RELEVANT_OFFSET;
#define NT_SYSTEM_NAME "System"



extern INJECT_RELEVANT_OFFSET g_InjectRelevantOffset;

ULONG GetProcessNameOffset();
NTSTATUS IsWindows64Bits(PVOID pCurProcess);
BOOLEAN InitializeWindows2k(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
BOOLEAN InitializeWindowsXp(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
BOOLEAN InitializeWindows2003(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
NTSTATUS InitializeWindows7(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
NTSTATUS InitializeWindows8(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
NTSTATUS InitializeWindows8_1(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
NTSTATUS InitializeWindows10(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
BOOLEAN InitializeInjectInformation(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);

#endif
