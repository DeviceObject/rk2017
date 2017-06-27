#include "TdiFlt.h"


PDEVICE_OBJECT g_pTcpFltObj = NULL;
PDEVICE_OBJECT g_pUdpFltObj = NULL;
PDEVICE_OBJECT g_pRawIpFltObj = NULL;

PDEVICE_OBJECT g_pTcpOldObj = NULL;
PDEVICE_OBJECT g_pUdpOldObj = NULL;
PDEVICE_OBJECT g_pRawIpOldObj = NULL;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	if (g_pTcpOldObj)
	{
		IoDetachDevice(g_pTcpOldObj);
	}
	if (g_pTcpFltObj)
	{
		IoDeleteDevice(g_pTcpFltObj);
	}

	if (g_pUdpOldObj)
	{
		IoDetachDevice(g_pUdpOldObj);
	}
	if (g_pUdpFltObj)
	{
		IoDeleteDevice(g_pUdpFltObj);
	}

	if (g_pRawIpOldObj)
	{
		IoDetachDevice(g_pRawIpOldObj);
	}
	if (g_pRawIpFltObj)
	{
		IoDeleteDevice(g_pRawIpFltObj);
	}
}
NTSTATUS AttachDeviceFromName(PDRIVER_OBJECT pDriverObject, \
							  PDEVICE_OBJECT *pFltObj, \
							  PDEVICE_OBJECT *pOldObj, \
							  PWCHAR pDevName)
{
	NTSTATUS Status;
	UNICODE_STRING UniDevName;

	Status = IoCreateDevice(pDriverObject, \
		0, \
		NULL, \
		FILE_DEVICE_UNKNOWN, \
		0, \
		TRUE, \
		pFltObj);
	if (NT_ERROR(Status))
	{
		return Status;
	}
	(*pFltObj)->Flags |= DO_DIRECT_IO;
	RtlInitUnicodeString(&UniDevName,pDevName);
	Status = IoAttachDevice(*pFltObj,&UniDevName,pOldObj);
	if (NT_ERROR(Status))
	{
		if (*pFltObj)
		{
			IoDeleteDevice(*pFltObj);
			*pFltObj = NULL;
		}
		return Status;
	}
	return Status;
}
NTSTATUS DeviceDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	NTSTATUS Status;
	PIO_STACK_LOCATION pIrpStack;

	Status = STATUS_SUCCESS;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pIrpStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_DEVICE_CONTROL:
		break;
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		break;
	case IRP_MJ_CLOSE:
		break;
	case IRP_MJ_CLEANUP:
		break;
	default:
		break;
	}
	return Status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pUniRegister)
{
	NTSTATUS Status;
	ULONG uli;

	Status = STATUS_SUCCESS;
	uli = 0;

	for (;uli < IRP_MJ_MAXIMUM_FUNCTION;uli++)
	{
		pDriverObject->MajorFunction[uli] = NULL;
	}
	do 
	{
		Status = AttachDeviceFromName(pDriverObject,&g_pTcpFltObj,&g_pTcpOldObj,DEVICE_TCP_NAMEW);
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = AttachDeviceFromName(pDriverObject,&g_pUdpFltObj,&g_pUdpOldObj,DEVICE_UDP_NAMEW);
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = AttachDeviceFromName(pDriverObject,&g_pRawIpFltObj,&g_pRawIpOldObj,DEVICE_RAWIP_NAMEW);
		if (NT_ERROR(Status))
		{
			break;
		}
	} while (0);
	if (NT_ERROR(Status))
	{
#ifdef _DEBUG
		DriverUnload(pDriverObject);
#endif
	}
	return Status;
}