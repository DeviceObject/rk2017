#ifndef __VFS_H__
#define __VFS_H__

#include <windows.h>

#define PAGE_SIZE 0x1000


#define DOS_NAME_LEN	8+1+3+1	// 8.3 name size in chars with 0
#define	tczOpen			_T("open")
#define	RUNAS			L"runas"
#define tczBkSlash		_T("\\")
#define tczBatFmt		_T("%lu.bat")
#define tczBatchFile	_T("attrib -r -s -h%%1\r\n:%u\r\ndel %%1\r\nif exist %%1 goto %u\r\ndel %%0\r\n")
#define szKernel32		"KERNEL32.DLL"

#define GUID_STR_LEN	16 * 2 + 4 + 2	// length of the GUID string in chars
#define GUID_FORMAT		L"{%08X-%04X-%04X-%04X-%08X%04X}"
#define	VFS_ROOT_FORMAT L"\\\\.\\%s\\"
#define	PROGRAMKEYNAME	L"Software\\Classes\\CLSID\\"
#define	LOCALNAME		L"Local\\"


extern HANDLE g_VfsHandle;
extern PWCHAR g_VfsRootName;


BOOLEAN VfsFree(PCHAR pFreeBuf);
PCHAR VfsAllocate(ULONG ulSize);
PWCHAR GenFsDeviceName();
BOOLEAN VfsCreateDevice();
BOOLEAN FreeMemory(PVOID pFreeMemory);
PVOID AllocateMemory(ULONG ulSize);

#endif