#ifndef __TDIFLT_H__
#define __TDIFLT_H__

#include <ntddk.h>
#include <tdikrnl.h>

#define DEVICE_TCP_NAMEW		L"\\Device\\Tcp"
#define DEVICE_UDP_NAMEW		L"\\Device\\Udp"
#define DEVICE_RAWIP_NAMEW		L"\\Device\\RawIp"

extern PDEVICE_OBJECT g_pTcpFltObj;
extern PDEVICE_OBJECT g_pUdpFltObj;
extern PDEVICE_OBJECT g_pRawIpFltObj;

extern PDEVICE_OBJECT g_pTcpOldObj;
extern PDEVICE_OBJECT g_pUdpOldObj;
extern PDEVICE_OBJECT g_pRawIpOldObj;

NTSTATUS AttachDeviceFromName(PDRIVER_OBJECT pDriverObject, \
							  PDEVICE_OBJECT *pFltObj, \
							  PDEVICE_OBJECT *pOldObj, \
							  PWCHAR pDevName);

NTSTATUS DeviceDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);

#endif