#ifndef __DRV_FUNCTION_H__
#define __DRV_FUNCTION_H__

BOOLEAN SetCurrentProcess(HANDLE Pid);
BOOLEAN SetCurClientPath(WCHAR *wPath);
NTSTATUS KillProcessByApc(HANDLE hProcessId);

#endif