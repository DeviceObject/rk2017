#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <Winsock2.h>
#include <Windows.h>

#pragma comment(lib,"Ws2_32.lib")

#include "../rk/IoCtlCode.h"
#pragma warning(push)
#pragma warning(disable:4005)
#include "..\Inc\ntdll.h"
#include <ntstatus.h>
#include "..\Inc\dbg.h"
#pragma warning(pop)