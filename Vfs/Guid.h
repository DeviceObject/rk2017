#ifndef __GUID_H__
#define __GUID_H__




VOID GenGuid(GUID* pGuid,PULONG pSeed);
PWCHAR GuidToString(GUID* pGuid);
PWCHAR GuidName(PULONG pSeed,PWCHAR pPrefixW);
#endif