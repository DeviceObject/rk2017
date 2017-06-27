#ifndef __UTILS_H__
#define __UTILS_H__

ULONG UnicodeToAnsi(PWCHAR pSrc,PCHAR pDst,ULONG ulSize);
ULONG AnsiToUnicode(PCHAR pSrc,PWCHAR pDst,ULONG ulSize);

#endif