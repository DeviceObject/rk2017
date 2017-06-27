#include "Vfs.h"
#include "Time.h"
#include "Guid.h"


VOID GenGuid(GUID* pGuid,PULONG pSeed)
{
	ULONG uli;
	pGuid->Data1 = MyRandom(pSeed);
	pGuid->Data2 = (USHORT)MyRandom(pSeed);
	pGuid->Data3 = (USHORT)MyRandom(pSeed);
	for (uli = 0;uli < 8;uli++)
	{
		pGuid->Data4[uli] = (UCHAR)MyRandom(pSeed);
	}
}
PWCHAR GuidName(PULONG pSeed,PWCHAR pPrefixW)
{
	ULONG ulNameLen = GUID_STR_LEN + 1;
	PWCHAR pGuidStr,pName = NULL;
	GUID Guid;

	GenGuid(&Guid,pSeed);
	if (pGuidStr = GuidToString(&Guid))
	{
		if (pPrefixW)
		{
			ulNameLen += wcslen(pPrefixW);
		}
		if (pName = (PWCHAR)AllocateMemory(ulNameLen * sizeof(WCHAR)))
		{
			pName[0] = 0;
			if (pPrefixW)
			{
				wcscpy(pName,pPrefixW);
			}
			wcscat(pName,pGuidStr);
		}
		FreeMemory(pGuidStr);
	}
	return pName;
}
PWCHAR GuidToString(GUID* pGuid)
{
	PWCHAR pGuidStr = (PWCHAR)VfsAllocate((GUID_STR_LEN + 1) * sizeof(WCHAR));
	if (pGuidStr)
	{
		wsprintf(pGuidStr, \
			GUID_FORMAT, \
			pGuid->Data1, \
			pGuid->Data2, \
			pGuid->Data3, \
			*(USHORT*)&pGuid->Data4[0], \
			*(ULONG*)&pGuid->Data4[2], \
			*(USHORT*)&pGuid->Data4[6]);
	}
	return pGuidStr;
}