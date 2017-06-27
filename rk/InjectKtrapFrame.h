#ifndef JECT_KTRAP_FRAME_H__
#define JECT_KTRAP_FRAME_H__

#define WINDOWS_VERSION_NONE                                0
#define WINDOWS_VERSION_2K                                  1
#define WINDOWS_VERSION_XP                                  2
#define WINDOWS_VERSION_2K3                                 3
#define WINDOWS_VERSION_2K3_SP1                             4
#define WINDOWS_VERSION_VISTA                               5
#define WINDOWS_VERSION_WIN7                                6

typedef struct _INJECT_X64_KTRAP_FRAME
{
	ULONG64 P1Home;
	ULONG64 P2Home;
	ULONG64 P3Home;
	ULONG64 P4Home;
	ULONG64 P5;
	KPROCESSOR_MODE PreviousMode;
	KIRQL PreviousIrql;
	UCHAR FaultIndicator;
	UCHAR ExceptionActive;
	ULONG MxCsr;
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	union
	{
		ULONG64 GsBase;
		ULONG64 GsSwap;
	};
	M128A Xmm0;
	M128A Xmm1;
	M128A Xmm2;
	M128A Xmm3;
	M128A Xmm4;
	M128A Xmm5;
	union
	{
		ULONG64 FaultAddress;
		ULONG64 ContextRecord;
		ULONG64 TimeStampCKCL;
	};
	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr6;
	ULONG64 Dr7;

	union
	{
		struct
		{
			ULONG64 DebugControl;
			ULONG64 LastBranchToRip;
			ULONG64 LastBranchFromRip;
			ULONG64 LastExceptionToRip;
			ULONG64 LastExceptionFromRip;
		};
		struct
		{
			ULONG64 LastBranchControl;
			ULONG LastBranchMSR;
		};
	};
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
	USHORT SegGs;
	ULONG64 TrapFrame;
	ULONG64 Rbx;
	ULONG64 Rdi;
	ULONG64 Rsi;
	ULONG64 Rbp;
	union
	{
		ULONG64 ErrorCode;
		ULONG64 ExceptionFrame;
		ULONG64 TimeStampKlog;
	};
	ULONG64 Rip;
	USHORT SegCs;
	UCHAR Fill0;
	UCHAR Logging;
	USHORT Fill1[2];
	ULONG EFlags;
	ULONG Fill2;
	ULONG64 Rsp;
	USHORT SegSs;
	USHORT Fill3;
	LONG CodePatchCycle;
} INJECT_X64_KTRAP_FRAME,*PINJECT_X64_KTRAP_FRAME;

typedef struct _INJECT_X86_KTRAP_FRAME
{
	ULONG   DbgEbp;
	ULONG   DbgEip;
	ULONG   DbgArgMark;
	ULONG   DbgArgPointer;
	ULONG   TempSegCs;
	ULONG   TempEsp;
	ULONG   Dr0;
	ULONG   Dr1;
	ULONG   Dr2;
	ULONG   Dr3;
	ULONG   Dr6;
	ULONG   Dr7;
	ULONG   SegGs;
	ULONG   SegEs;
	ULONG   SegDs;
	ULONG   Edx;
	ULONG   Ecx;
	ULONG   Eax;
	ULONG   PreviousPreviousMode;
	ULONG   ExceptionList;
	ULONG   SegFs;
	ULONG   Edi;
	ULONG   Esi;
	ULONG   Ebx;
	ULONG   Ebp;
	ULONG   ErrCode;
	ULONG   Eip;
	ULONG   SegCs;
	ULONG   EFlags;
	ULONG   HardwareEsp;
	ULONG   HardwareSegSs;
	ULONG   V86Es;
	ULONG   V86Ds;
	ULONG   V86Fs;
	ULONG   V86Gs;
}INJECT_X86_KTRAP_FRAME,*PINJECT_X86_KTRAP_FRAME;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
}LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;

typedef struct _INJECT_OBJECT_INFORMATION
{
	PVOID pInjectProcess;
	PVOID pInjectThread;
	CHAR InjectDllPath[100];
}INJECT_OBJECT_INFORMATION,*PINJECT_OBJECT_INFORMATION;

typedef NTSTATUS (__fastcall *FASTCALL_NTSUSPENDTHREAD)(IN HANDLE ThreadHandle,OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS (__stdcall *STDCALL_NTSUSPENDTHREAD)(IN HANDLE ThreadHandle,OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS (__stdcall *STDCALL_NTPROTECTVIRTUALMEMORY)(HANDLE ProcessHandle, \
															 PVOID *BaseAddress , \
															 PSIZE_T RegionSize, \
															 ULONG NewProtect, \
															 PULONG OldProtect);

typedef struct _INJECT_API_LIST
{
	FASTCALL_NTSUSPENDTHREAD FastCallKeSuspendThread;
	FASTCALL_NTSUSPENDTHREAD FastCallKeResumeThread;

	STDCALL_NTSUSPENDTHREAD StdCallKeSuspendThread;
	STDCALL_NTSUSPENDTHREAD StdCallKeResumeThread;

	STDCALL_NTPROTECTVIRTUALMEMORY StdCallNtProtectVirtualMemory;

	ULONG_PTR ulx86LoadLibrary;
	ULONG64 ulx64LoadLibrary;

	BOOLEAN bInitialize;
}INJECT_API_LIST,*PINJECT_API_LIST;

typedef struct _INJECT_PROCESS_INFORMATION
{
	ULONG_PTR ulPid;
	CHAR pInjectProcessName[1];
}INJECT_PROCESS_INFORMATION,*PINJECT_PROCESS_INFORMATION;


extern INJECT_API_LIST g_InjectAplList;
extern BOOLEAN g_bIsInjectKtrapFrame;

#endif

#define INJECT_KTRAP_FRAME_EIP_TAG	0x40404040
#define INJECT_KTRAP_FRAME_PATH_TAG	0x80808080
#define INJECT_KTRAP_FRAME_PARAMETERS 0x88888888

PINJECT_OBJECT_INFORMATION FindInjectThread(PINJECT_PROCESS_INFORMATION pInjectProcessInfo);
NTSTATUS InjectKtrapFrame(PINJECT_PROCESS_INFORMATION pInjectProcessInfo,PCHAR pDllPath);
NTSTATUS x86ShellCodeInject(PINJECT_OBJECT_INFORMATION pInjectObjInfo,PCHAR pShellCode,ULONG ulSize);