#include "stdafx.h"
#include "Utils.h"
//#define NTSECAPI
//#include <Winternl.h>

ULONG UnicodeToAnsi(PWCHAR pSrc,PCHAR pDst,ULONG ulSize)
{
	ULONG ulNeedSize;

	ulNeedSize = 0;
	if (ulSize)
	{
		ulNeedSize = WideCharToMultiByte(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			pDst, \
			ulSize, \
			NULL, \
			FALSE);
	}
	else
	{
		ulNeedSize = WideCharToMultiByte(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			NULL, \
			0, \
			NULL, \
			FALSE);
	}
	return ulNeedSize;
}
ULONG AnsiToUnicode(PCHAR pSrc,PWCHAR pDst,ULONG ulSize)
{
	ULONG ulNeedSize;

	ulNeedSize = 0;
	if (ulSize)
	{
		ulNeedSize = MultiByteToWideChar(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			pDst, \
			ulSize);
	}
	else
	{
		ulNeedSize = MultiByteToWideChar(CP_ACP, \
			NULL, \
			pSrc, \
			-1, \
			NULL, \
			0);
	}
	return ulNeedSize;
}