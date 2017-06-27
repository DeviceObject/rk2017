#include "rk.h"
#include "ApcKillProcess.h"
#include "DrvFunction.h"

NTSTATUS KillProcessByApc(HANDLE hProcessId)
{
	NTSTATUS Status;
	PVOID pCurProc;

	Status = STATUS_UNSUCCESSFUL;
	pCurProc = NULL;

	Status = PsLookupProcessByProcessId(hProcessId,(PEPROCESS*)&pCurProc);
	if (NT_SUCCESS(Status))
	{
		ObDereferenceObject(pCurProc);
		KillProcessWithApc(pCurProc);
	}
	return Status;
}
BOOLEAN SetCurrentProcess(HANDLE Pid)
{
	PVOID pProcess;

	pProcess = NULL;
	
	if (0 == Pid)
	{
		return FALSE;
	}
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid,(PEPROCESS*)&pProcess)))
	{
		ObDereferenceObject(pProcess);
		return TRUE;
	}
	return FALSE;
}
BOOLEAN SetCurClientPath(WCHAR *wPath)
{
    if (NULL == wPath)
    {
        return FALSE;
    }
    return FALSE;
}