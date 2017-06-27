#ifndef __SYSTEM_PRE_INIT_H__
#define __SYSTEM_PRE_INIT_H__

//VOID DrvReInitCallback(IN PDRIVER_OBJECT pDriverObject,IN PVOID pContext,IN ULONG ulCount);
//BOOLEAN DrvCheckFileSystemIsOK();
//VOID SystemPreInit(PDRIVER_OBJECT pDrvObj);
//NTSTATUS Rk2017Process(PRK2017_RUNTIME_LIBRARY pRk2017RTLib);
//BOOLEAN FileIsError(PUNICODE_STRING pUnFileName);
//BOOLEAN FileExists_S1(char* szFileName);
//BOOLEAN FileCopy_S1(IN char *pszSrc,IN char *pszTarget);
//NTSTATUS SetFlagsValue(ULONG ulFlags);
//BOOLEAN CreateFile_S1(char* pszFileName);
//ULONG WriteFile_S1(char* pszFileName,PCHAR pBuffer,ULONG uSize);
//PCHAR ReadFile_S1(char* pszFileName,ULONG* uSizeX);
//BOOLEAN FileCheck();
//VOID FileLock();
//VOID RegWrite(PWCHAR value_name,LONG value_value);
//LONG RegRead(PWCHAR value_name);
//BOOLEAN RegCheck();
//VOID RegLock();
//static ULONG GetSumCheck(PVOID buffer,int len);
VOID SystemSleep(LONGLONG sec);
#define WATCHDOG_INTERNAL			30  //√Î
#define TERMINATE_PROCESS_TIMEOUT	20  //√Î
#define RUN_TARGET_INERVAL			72  //–° ±
#define WAIT_ONE_MINUTE				60
#define RUN_SUBKEY_NAME				L"r"

//////////////////////////////////////////////////////////////////////////

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND * 1000)
#define DELAY_ONE_SECOND      (DELAY_ONE_MILLISECOND * 1000)
#define START_DEFAULT_VALUE 0x01


//typedef struct _CHECK_PROTECT_FILE_LIST
//{
//	LIST_ENTRY NextList;
//	PVOID kOriginalFileImage;
//	ULONG kOriginalFileLength;
//	CHAR FileName[MAX_PATH];
//	BOOLEAN bIsLoader;
//}CHECK_PROTECT_FILE_LIST,*PCHECK_PROTECT_FILE_LIST;
//
//extern LIST_ENTRY g_CheckProtectFileList;
//extern KSPIN_LOCK g_SpinLockProtectFileList;
#endif