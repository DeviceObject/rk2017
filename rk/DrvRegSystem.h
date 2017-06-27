#ifndef __DRV_REG_SYSTEM_H__
#define __DRV_REG_SYSTEM_H__

#define SERVICE_DRIVER_REG_PATH		L"\\registry\\machine\\system\\currentcontrolset\\services\\"

LONG RegRead(PWCHAR pValueNameW,PWCHAR pDriverNameW);
VOID RegWrite(PWCHAR pValueNameW,PWCHAR pDriverNameW,ULONG ulValue);
#endif