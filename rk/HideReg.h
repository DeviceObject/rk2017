#ifndef __HIDE_REG_H__
#define __HIDE_REG_H__

#define CM_HIDE_KEY_MAX_PATH	512
#define CM_KEY_INDEX_ROOT      0x6972         // ir
#define CM_KEY_INDEX_LEAF      0x696c         // il
#define CM_KEY_FAST_LEAF       0x666c         // fl
#define CM_KEY_HASH_LEAF       0x686c         // hl

typedef PVOID (__stdcall *PGET_CELL_ROUTINE)(PVOID,HANDLE);

#pragma pack(1)

typedef struct _CM_KEY_NODE
{
	USHORT Signature;
	USHORT Flags;
	LARGE_INTEGER LastWriteTime;
	ULONG Spare;               // used to be TitleIndex
	HANDLE Parent;
	ULONG SubKeyCounts[2];     // Stable and Volatile
	HANDLE SubKeyLists[2];     // Stable and Volatile
	// ...
} CM_KEY_NODE, *PCM_KEY_NODE;

typedef struct _CM_KEY_INDEX
{
	USHORT Signature;
	USHORT Count;
	HANDLE List[1];
} CM_KEY_INDEX, *PCM_KEY_INDEX;

typedef struct _CM_KEY_BODY
{
	ULONG Type;              // "ky02"
	PVOID KeyControlBlock;
	PVOID NotifyBlock;
	PEPROCESS Process;       // the owner process
	LIST_ENTRY KeyBodyList; 	// key_nodes using the same kcb
} CM_KEY_BODY, *PCM_KEY_BODY;

typedef struct _HHIVE
{
	ULONG ulSignature;
	PGET_CELL_ROUTINE GetCellRoutine;
	// бн
} HHIVE, *PHHIVE;

typedef struct _HIDE_KEY_LIST
{
	LIST_ENTRY NextHideKey;
	PCM_KEY_NODE pHideNode;
	PCM_KEY_NODE pLastNode;
	PGET_CELL_ROUTINE pGetCellRoutine;
	PGET_CELL_ROUTINE *ppGetCellRoutine;
	WCHAR HideKeyNameW[CM_HIDE_KEY_MAX_PATH];
	PHHIVE pHive;
}HIDE_KEY_LIST,*PHIDE_KEY_LIST;
extern LIST_ENTRY g_HideKeyList;
extern KSPIN_LOCK g_SpinLockHideKeyList;
#pragma pack()



//key to hide

PVOID MyGetCellRoutine(PVOID pHive,HANDLE Cell);
PVOID GetLastKeyNode(PVOID pHive,PCM_KEY_NODE pNode,PGET_CELL_ROUTINE pGetCellRoutine);
PVOID GetKeyControlBlock(HANDLE hKey);
HANDLE OpenKeyByName(PWCHAR pKeyNameW);
NTSTATUS CmHideKey(PWCHAR pHideKeyPathW);
void InitializeHideKeyList();

#endif