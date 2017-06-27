#ifndef __RK_H__
#define __RK_H__

#include <ntifs.h>
#include <ntddk.h>
#include <stdio.h>
#include <fltKernel.h>
#include <strsafe.h>
#include <ntstrsafe.h>
#include <tdiinfo.h>
#include <tdistat.h>
#include <ntimage.h>
#include <ntdef.h>

#define MAX_PATH 300
#define MAX_PATH_LEN 1024

#include "IoCtlCode.h"

typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER)(IN PETHREAD Thread,IN NTSTATUS ExitStatus,IN BOOLEAN DirectTerminate);

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

VOID KeInitializeApc(PRKAPC Apc,
					 PRKTHREAD Thread,
					 KAPC_ENVIRONMENT Environment,
					 PKKERNEL_ROUTINE KernelRoutine,
					 PKRUNDOWN_ROUTINE RundownRoutine,
					 PKNORMAL_ROUTINE NormalRoutine,
					 KPROCESSOR_MODE ProcessorMode,
					 PVOID NormalContext);
BOOLEAN KeInsertQueueApc(PRKAPC Apc,
						 PVOID SystemArgument1,
						 PVOID SystemArgument2,
						  KPRIORITY Increment);
PUCHAR PsGetProcessImageFileName(IN PEPROCESS Process);
NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, \
						  PROCESSINFOCLASS ProcessInformationClass, \
						  PVOID ProcessInformation, \
						  ULONG ProcessInformationLength, \
						  PULONG ReturnLength);
BOOLEAN KeAlertThread(PKTHREAD Thread,KPROCESSOR_MODE AlertMode);

extern USHORT *NtBuildNumber;
extern ULONG *InitSafeBootMode;

typedef struct _RK2017_RUNTIME_LIBRARY
{
	PDRIVER_OBJECT pDriverObject;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING UniRegPath;
	WCHAR wDrvName[MAX_PATH];
	CHAR DrvName[MAX_PATH];
	ULONG ulSafeMode;
	BOOLEAN bIsUninstall;
	BOOLEAN bIsStartFilter;
	PFLT_FILTER phFltHide;
	PFLT_INSTANCE pFltInstance;
	PVOID pSystemProcess;
}RK2017_RUNTIME_LIBRARY,*PRK2017_RUNTIME_LIBRARY;

extern RK2017_RUNTIME_LIBRARY g_Rk2017RunTimeLibrary;
#endif