#include "rk.h"
#include "DrvRegSystem.h"

LONG RegRead(PWCHAR pValueNameW,PWCHAR pDriverNameW)
{
	NTSTATUS Status;
	HANDLE hServKey;
	OBJECT_ATTRIBUTES ObjectAttributes;	
	UNICODE_STRING UniServKeyPath;
	UNICODE_STRING UniValueName;
	WCHAR KeyPathW[MAX_PATH];
	UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(LONG)];
	ULONG ulResultLength;
	LONG dwValue = 0;

	hServKey = NULL;

	do
	{	//¼ì²é¼ü
		if(pDriverNameW[0] == 0)
		{
			break;
		}
		RtlZeroMemory(KeyPathW,sizeof(WCHAR) * MAX_PATH);
		RtlCopyMemory(KeyPathW,SERVICE_DRIVER_REG_PATH,wcslen(SERVICE_DRIVER_REG_PATH) * sizeof(WCHAR));
		wcscat_s(KeyPathW,MAX_PATH,pDriverNameW);
		RtlInitUnicodeString(&UniServKeyPath,KeyPathW);
		InitializeObjectAttributes(&ObjectAttributes,&UniServKeyPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
		Status = ZwOpenKey(&hServKey,KEY_READ,&ObjectAttributes);
		if (NT_ERROR(Status)) 
		{
			break;
		}
		//¼ì²éÖµ
		RtlInitUnicodeString(&UniValueName,pValueNameW);
		Status = ZwQueryValueKey(hServKey, \
			&UniValueName, \
			KeyValuePartialInformation, \
			buffer, \
			sizeof(buffer), \
			&ulResultLength);
		if (NT_ERROR(Status)) 
		{
			break;
		}
		dwValue = *((PLONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
	} while (0);
	if(hServKey)
	{
		ZwClose(hServKey);
	}
	return dwValue;
}

VOID RegWrite(PWCHAR pValueNameW,PWCHAR pDriverNameW,ULONG ulValue)
{
	NTSTATUS Status;
	HANDLE hServKey;
	OBJECT_ATTRIBUTES ObjectAttributes;	
	UNICODE_STRING UniServKeyPath;	
	UNICODE_STRING UniSubKey;
	WCHAR KeyPathW[MAX_PATH];

	do
	{			
		if(pDriverNameW[0] == 0)
		{
			break;
		}
		RtlZeroMemory(KeyPathW,sizeof(WCHAR) * MAX_PATH);
		RtlCopyMemory(KeyPathW,SERVICE_DRIVER_REG_PATH,wcslen(SERVICE_DRIVER_REG_PATH) * sizeof(WCHAR));
		wcscat_s(KeyPathW,MAX_PATH,pDriverNameW);
		RtlInitUnicodeString(&UniServKeyPath,KeyPathW);
		InitializeObjectAttributes(&ObjectAttributes,&UniServKeyPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
		Status = ZwCreateKey(&hServKey,KEY_SET_VALUE | KEY_WRITE | KEY_ALL_ACCESS,&ObjectAttributes,0,NULL,REG_OPTION_NON_VOLATILE,0);
		if (NT_SUCCESS(Status))
		{
			RtlInitUnicodeString(&UniSubKey,pValueNameW);
			ZwSetValueKey(hServKey,&UniSubKey,0,REG_DWORD,&ulValue,sizeof(ULONG));
			ZwClose(hServKey);
		}
	}while(0);
	return;
}