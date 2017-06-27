#include "rk.h"
#include "ToolFnc.h"

char* _strlwr_d(char* src)
{
	while (*src != '\0')
	{
		if (*src > 'A' && *src <= 'Z')
		{
			//*src += 0x20; 
			*src += 32;
		}
		src++;
	}
	return src;
}
static int __inline Lower(int c)
{
	if ((c >= L'A') && (c <= L'Z'))
	{
		return(c + (L'a' - L'A'));
	}
	else
	{
		return(c);
	}
}


BOOLEAN RtlPatternMatch(WCHAR * pat, WCHAR * str)
{
	register WCHAR * s;
	register WCHAR * p;
	BOOLEAN star = FALSE;

loopStart:
	for (s = str, p = pat; *s; ++s, ++p) {
		switch (*p) {
		 case L'?':
			 if (*s == L'.') goto starCheck;
			 break;
		 case L'*':
			 star = TRUE;
			 str = s, pat = p;
			 if (!*++pat) return TRUE;
			 goto loopStart;
		 default:
			 if (Lower(*s) != Lower(*p))
				 goto starCheck;
			 break;
		} 
	} 
	if (*p == L'*') ++p;
	return (!*p);

starCheck:
	if (!star) return FALSE;
	str++;
	goto loopStart;
}