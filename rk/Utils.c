#include "rk.h"
#include "Utils.h"

ULONG GetSumCheck(PCHAR pDat,ULONG ulLen)
{
	ULONG ulSum;
	ULONG uli;

	ulSum = 0;

	for(uli = 0;uli < ulLen;uli++)
	{
		ulSum += pDat[uli];
	}
	return ulSum;
}
CHAR __ISUPPER__(CHAR c)
{
	return ('A' <= c) && (c <= 'Z'); 
}

CHAR __TOLOWER__(CHAR c)
{
	return __ISUPPER__(c) ? c - 'A' + 'a' : c; 
}
ULONG __STRNCMPI__(LPSTR lpStr1,LPSTR lpStr2,ULONG ulLen)
{
	int  v;
	CHAR c1, c2;
	do
	{
		ulLen--;
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (ULONG)__TOLOWER__(c1) - (ULONG)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0') && ulLen > 0);
	return v;
}

char *MyStrCpy(char *dst,const char *src)
{
	char *ret = dst;
	while((*dst++ = *src++) != '\0');
	return ret;
}
void CleanZero(PCHAR pCleanBuffer,ULONG ulLength)
{
	ULONG ulCnt;

	ulCnt = 0;

	while (ulCnt < ulLength)
	{
		if (*(pCleanBuffer + ulCnt) != 0)
		{
			*(pCleanBuffer + ulCnt) = 0;
		}
		ulCnt++;
	}
}
PCHAR MyMEMCPY(PCHAR pDst,PCHAR pSrc,ULONG ulLength)
{
	ULONG ulCnt;

	ulCnt = 0;
	while (ulCnt < ulLength)
	{
		*pDst++ = *pSrc++;
		ulCnt++;
	}
	return pDst;
}
ULONG CalcHashValue(char *szApiName)
{
	USHORT ulHashValue;
	ULONG ulTmp,ulOrValue;
	ULONG uli;
	CHAR szTmp;

	ulHashValue = 1;
	ulOrValue = 0;

	for (uli = 0;uli < __STRLEN__(szApiName);uli++)
	{
		szTmp = szApiName[uli];
		ulHashValue += szTmp;
		ulOrValue += ulHashValue;
	}
	ulTmp = ulOrValue << 0x10;
	ulTmp |= ulHashValue;
	return ulTmp;
}
int MyMemicmp(char *src,char *dest,int size)
{
	char *src_tmp = src;
	char *dest_tmp = dest;
	while(size--)
	{
		if((*src_tmp==*dest_tmp)||
			(((*src_tmp)-'A'+'a')==*dest_tmp)
			||*src_tmp==((*dest_tmp)-'A'+'a'))
		{
			src_tmp++;
			dest_tmp++;
			continue;
		}
		return -1;
	}
	return 0;
}
char *MyStristr(char *src,char *dest)
{
	int x_len;
	int i;
	int ret;
	char *src_tmp = src;
	char *dest_tmp = dest;
	x_len = __STRLEN__(dest_tmp);
	i = __STRLEN__(src_tmp);
	if(i < x_len)
	{
		return 0;
	}
	i -= (x_len-1);
	while(i--)
	{
		ret = MyMemicmp(src_tmp++,dest_tmp,x_len);
		if(!ret)
		{
			return --src_tmp;
		}
	}
	return 0;
}
int my_strcmp(char *src,char *dest)
{
	char *src_tmp = src;
	char *dest_tmp = dest;
	while(*src_tmp == *dest_tmp)
	{
		if(*src_tmp)
		{
			src_tmp++;
			dest_tmp++;
			continue;
		}
		return 0;
	}
	return -1;
}
PCHAR MyStrChr(PCHAR pDest,ULONG ulAscii)
{
    ULONG uli,ulLength;
    if (NULL == pDest || ulAscii == 0)
    {
        return NULL;
    }
    ulLength = strlen(pDest);
    for (uli = 0;uli < ulLength;uli++)
    {
        if (pDest[uli] == ulAscii)
        {
            return (PCHAR)(pDest + uli);
        }
    }
    return NULL;
}
ULONG __STRLEN__(PCHAR pStr)
{
	ULONG uli = 0;
	while (pStr[uli] != '\0')
	{
		uli++;
	}
	return uli;
}
PVOID KernelMalloc(ULONG ulSize)
{
	return ExAllocatePoolWithTag(NonPagedPool,ulSize,'LdrK');//分配内部缓冲区
}
void KernelFree(PVOID pFreeAddr)
{
	ExFreePoolWithTag(pFreeAddr,'LdrK');
}
char *ltoa(long value, char *string, int radix)
{
	char tmp[33];
	char *tp = tmp;
	long i;
	unsigned long v;
	int sign;
	char *sp;

	if (radix > 36 || radix <= 1)
	{
		return 0;
	}

	sign = (radix == 10 && value < 0);
	if (sign)
		v = -value;
	else
		v = (unsigned long)value;
	while (v || tp == tmp)
	{
		i = v % radix;
		v = v / radix;
		if (i < 10)
			*tp++ = (CHAR)(i + '0');
		else
			*tp++ = (CHAR)(i + 'a' - 10);
	}

	if (string == 0)
		string = (char *)KernelMalloc((tp-tmp)+sign+1);
	sp = string;

	if (sign)
		*sp++ = '-';
	while (tp > tmp)
		*sp++ = *--tp;
	*sp = 0;
	return string;
}