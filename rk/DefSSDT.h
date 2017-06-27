#ifndef __DEF_SSDT_H__
#define __DEF_SSDT_H__

typedef PVOID* PNTPROC;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID ServiceTableBase; 
	PULONG ServiceCounterTableBase; 
	ULONG ulNumberOfServices; 
	PUCHAR ParamTableBase; 
} SYSTEM_SERVICE_TABLE,*PSYSTEM_SERVICE_TABLE;


typedef struct _SERVICE_DESCRIPTOR_TABLE 
{
	SYSTEM_SERVICE_TABLE Ntoskrnl;  
	SYSTEM_SERVICE_TABLE Win32k;    
	SYSTEM_SERVICE_TABLE iis;
	SYSTEM_SERVICE_TABLE unused;    
} SERVICE_DESCRIPTOR_TABLE,*PSERVICE_DESCRIPTOR_TABLE;


#pragma pack(1)


extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

typedef struct ServiceDescriptorEntry
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //根据WRK貌似只有check Build版才有
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

#pragma pack()
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig) \
	_Orig = (PVOID)InterlockedExchange((PLONG)&pNewSystemCallTable[SYSCALL_INDEX(_Function)], (LONG)_Hook)
#define UNHOOK_SYSCALL(_Function, _Hook, _Orig )  \
	InterlockedExchange((PLONG)&pNewSystemCallTable[SYSCALL_INDEX(_Function)], (LONG)_Hook)

#endif