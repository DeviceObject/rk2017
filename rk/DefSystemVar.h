#ifndef __DEF_SYSTEM_VAR_H__
#define __DEF_SYSTEM_VAR_H__

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG  NextEntryDelta;
	ULONG  ThreadCount;
	ULONG  Reserved1[6];
	LARGE_INTEGER  ftCreateTime;
	LARGE_INTEGER  ftUserTime;
	LARGE_INTEGER  ftKernelTime;
	UNICODE_STRING ProcessName;
	ULONG  BasePriority;
	ULONG  ProcessId;
	ULONG  InheritedFromProcessId;
	ULONG  HandleCount;
	ULONG  Reserved2[2];
	ULONG  VmCounters;
	ULONG  dCommitCharge;
	PVOID  ThreadInfos[1];
}SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
}SYSTEM_THREAD_INFORMATION,*PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION
{ 
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{   
	SystemBasicInformation,   
	SystemProcessorInformation,   
	SystemPerformanceInformation,   
	SystemTimeOfDayInformation,   
	SystemNotImplemented1,   
	SystemProcessesAndThreadsInformation,   
	SystemCallCounts,   
	SystemConfigurationInformation,   
	SystemProcessorTimes,   
	SystemGlobalFlag,   
	SystemNotImplemented2,   
	SystemModuleInformation,   
	SystemLockInformation,   
	SystemNotImplemented3,   
	SystemNotImplemented4,   
	SystemNotImplemented5,   
	SystemHandleInformation,   
	SystemObjectInformation,   
	SystemPagefileInformation,   
	SystemInstructionEmulationCounts,   
	SystemInvalidInfoClass1,   
	SystemCacheInformation,   
	SystemPoolTagInformation,   
	SystemProcessorStatistics,   
	SystemDpcInformation,   
	SystemNotImplemented6,   
	SystemLoadImage,   
	SystemUnloadImage,   
	SystemTimeAdjustment,   
	SystemNotImplemented7,   
	SystemNotImplemented8,   
	SystemNotImplemented9,   
	SystemCrashDumpInformation,   
	SystemExceptionInformation,   
	SystemCrashDumpStateInformation,   
	SystemKernelDebuggerInformation,   
	SystemContextSwitchInformation,   
	SystemRegistryQuotaInformation,   
	SystemLoadAndCallImage,   
	SystemPrioritySeparation,   
	SystemNotImplemented10,   
	SystemNotImplemented11,   
	SystemInvalidInfoClass2,   
	SystemInvalidInfoClass3,   
	SystemTimeZoneInformation,   
	SystemLookasideInformation,   
	SystemSetTimeSlipEvent,   
	SystemCreateSession,   
	SystemDeleteSession,   
	SystemInvalidInfoClass4,   
	SystemRangeStartInformation,   
	SystemVerifierInformation,   
	SystemAddVerifier,   
	SystemSessionProcessesInformation   
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

extern POBJECT_TYPE *IoDriverObjectType;


NTKERNELAPI NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING ObjectName,
						IN ULONG   Attributes,
						IN PACCESS_STATE PassedAccessState OPTIONAL,
						IN ACCESS_MASK  DesiredAccess OPTIONAL,
						IN POBJECT_TYPE  ObjectType OPTIONAL,
						IN KPROCESSOR_MODE AccessMode,
						IN OUT PVOID  ParseContext OPTIONAL,
						OUT PVOID   *Object);

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,   
						 OUT PVOID SystemInformation,   
						 IN ULONG SystemInformationLength,   
						 OUT PULONG ReturnLength OPTIONAL);


NTSYSAPI NTSTATUS NTAPI ZwDeviceIoControlFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength );



typedef NTSTATUS (*ZWDEVICECONTROLIOFILE)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN ULONG                IoControlCode,
	IN PVOID                InputBuffer OPTIONAL,
	IN ULONG                InputBufferLength,
	OUT PVOID               OutputBuffer OPTIONAL,
	IN ULONG                OutputBufferLength);


#define PS_CROSS_THREAD_FLAGS_SYSTEM 0x00000010UL 
#endif