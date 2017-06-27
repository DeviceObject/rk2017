#ifndef __APC_KILL_PROCESS_H__
#define __APC_KILL_PROCESS_H__


#ifndef _WIN64
VOID ApcKillThreadRoutine(PVOID pApc, \
						  PVOID *NormalRoutine, \
						  PVOID *NormalContext, \
						  PVOID *SystemArgument1, \
						  PVOID *SystemArgument2);

VOID KillProcessWithApc(PVOID pEProc);

NTSTATUS PspTerminateThreadByPointerForWindows8x86(PVOID pEThread, \
												   NTSTATUS ExitStatus, \
												   BOOLEAN DirectTerminate);
NTSTATUS PspTerminateThreadByPointerForWindows81x86(PVOID pEThread, \
													NTSTATUS ExitStatus, \
													BOOLEAN DirectTerminate);
NTSTATUS PspTerminateThreadByPointerForWindows10x86(PVOID pEThread, \
													NTSTATUS ExitStatus, \
													BOOLEAN DirectTerminate);
NTSTATUS PspTerminateThreadByPointerForWindowsXpx86(PVOID pEThread, \
													NTSTATUS ExitStatus, \
													BOOLEAN DirectTerminate);
#endif

PVOID SearchHexCodeFromAddress(PVOID pAddress);
VOID InjectNotifyRoutine(PUNICODE_STRING FullImageName,HANDLE ProcessId,PIMAGE_INFO ImageInfo);
void CreateProcessRoutine(HANDLE ParentId,HANDLE ProcessId,BOOLEAN Create);
BOOLEAN InjectProcess(HANDLE hProcessId);
BOOLEAN InsertApc(PVOID pShellCode,PKAPC pApc);

extern HANDLE g_hExplorerProcessId;

#endif
