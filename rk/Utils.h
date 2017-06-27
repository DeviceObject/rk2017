#ifndef __UTILS_H__
#define __UTILS_H__


CHAR __ISUPPER__(CHAR c);
CHAR __TOLOWER__(CHAR c);
void CleanZero(PCHAR pCleanBuffer,ULONG ulLength);
PCHAR MyMEMCPY(PCHAR pDst,PCHAR pSrc,ULONG ulLength);
ULONG CalcHashValue(char *szApiName);
int MyMemicmp(char *src,char *dest,int size);
char *MyStristr(char *src,char *dest);
int my_strcmp(char *src,char *dest);
char *MyStrCpy(char *dst,const char *src);
PCHAR MyStrChr(PCHAR pDest,ULONG ulAscii);
ULONG __STRLEN__(PCHAR pStr);
ULONG __STRNCMPI__(PCHAR lpStr1,PCHAR lpStr2,ULONG ulLen);
PVOID KernelMalloc(ULONG ulSize);
void KernelFree(PVOID pFreeAddr);
char *ltoa(long value, char *string, int radix);
ULONG GetSumCheck(PCHAR pDat,ULONG ulLen);
#endif