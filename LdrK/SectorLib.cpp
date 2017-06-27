#include "stdafx.h"
#include "SectorLib.h"

NTSTATUS _stdcall SectorIo(PUNICODE_STRING pUniDriveName,		// drive name to read/write sectors from/to
						   PCHAR pBuffer,			// bufer to store the data
						   ULONG ulLength,			// size of the buffer
						   ULONGLONG ulStartSector,	// starting LBA sector
						   ULONG ulCount,			// number of sectors to read/write
						   ULONG ulFlags)
{
	HANDLE hDrive;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER lFilePos;
	ULONG ulObjectFlags;

	Status = STATUS_BUFFER_TOO_SMALL;
	ulObjectFlags = 0;
	lFilePos.QuadPart = 0;

#ifdef _WIN64
	if ((ULONG_PTR)&ulObjectFlags & 0x8000000000000000)
#else
	if ((ULONG_PTR)&ulObjectFlags & 0x80000000)
#endif
		ulObjectFlags |= OBJ_KERNEL_HANDLE;

	InitializeObjectAttributes(&ObjectAttributes, \
		pUniDriveName, \
		ulObjectFlags, \
		NULL, \
		NULL);

	if ((ulCount * BIOS_DEFAULT_SECTOR_SIZE) <= ulLength)
	{
		Status = ZwOpenFile(&hDrive, \
			FILE_GENERIC_READ | FILE_GENERIC_WRITE, \
			&ObjectAttributes, \
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_WRITE, \
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
		if (NT_SUCCESS(Status))
		{
			lFilePos.QuadPart = (ulStartSector * BIOS_DEFAULT_SECTOR_SIZE);

			if (ulFlags & BK_IO_WRITE)
			{
				Status = ZwWriteFile(hDrive, \
					0, \
					NULL, \
					NULL, \
					&IoStatus, \
					pBuffer, \
					(ulCount * BIOS_DEFAULT_SECTOR_SIZE), \
					&lFilePos, \
					NULL);
			}
			else
			{
				Status = ZwReadFile(hDrive, \
					0, \
					NULL, \
					NULL, \
					&IoStatus, \
					pBuffer, \
					(ulCount * BIOS_DEFAULT_SECTOR_SIZE), \
					&lFilePos, \
					NULL);
			}
			ZwClose(hDrive);
		}
	}
	return Status;
}
NTSTATUS _stdcall GetDriveGeometry(PUNICODE_STRING pUniDriveName,PVOID pDriveGeo)
{
	NTSTATUS Status;
	HANDLE hDevice;           
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK	IoStatus;
	PDISK_GEOMETRY pDiskGeometry = (PDISK_GEOMETRY)pDriveGeo;

	InitializeObjectAttributes(&ObjectAttributes, \
		pUniDriveName, \
		OBJ_CASE_INSENSITIVE, \
		NULL, \
		NULL);
	Status = ZwCreateFile(&hDevice, \
		GENERIC_READ | SYNCHRONIZE, \
		&ObjectAttributes, \
		&IoStatus, \
		NULL, \
		0, \
		FILE_SHARE_READ | FILE_SHARE_WRITE, \
		FILE_OPEN, \
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, \
		NULL, \
		0);
	if (NT_SUCCESS(Status))
	{
		Status = ZwDeviceIoControlFile(hDevice, \
			0, \
			NULL, \
			NULL, \
			&IoStatus, \
			IOCTL_DISK_GET_DRIVE_GEOMETRY, \
			NULL, \
			0, \
			pDiskGeometry, \
			sizeof(DISK_GEOMETRY));
		ZwClose(hDevice);
	}
	return Status;
}
//
//	Searches for the boot sector and calculates where to place VFS area.
//
static VOID	CalculateFsArea(PDISK_GEOMETRY pDiskGeo,PPARTITION_TABLE PTable,PBK_FS_AREA pFsArea)
{
	ULONG uli,ulStartSector = 0,ulEndSector = 0,ulNonNtFirst = 0,ulNonNtSize = 0;

	// Calculating drive unpartitioned space size
	for (uli = 0;uli < BIOS_MAX_PARTITION_COUNT;uli++)
	{
		if (PTable->Entry[uli].Descriptor)	
		{
			if (ulStartSector == 0 || ulStartSector > PTable->Entry[uli].LBAStartSector)
			{
				ulStartSector = PTable->Entry[uli].LBAStartSector;
			}
			if (ulEndSector < (PTable->Entry[uli].LBAStartSector + PTable->Entry[uli].PartitionSize))
			{
				ulEndSector = (PTable->Entry[uli].LBAStartSector + PTable->Entry[uli].PartitionSize);
			}
		}	// if (PTable->Entry[i].Descriptor)

		if (PTable->Entry[uli].Descriptor == BIOS_PARTITION_TYPE_INSTALLABLE)
		{
			// This is a NTFS partition
			if (PTable->Entry[uli].ActiveFlag & BIOS_PARTITION_ACTIVE_FLAG)
				// This an active partition, storing it's start sector
				pFsArea->BootSector = (ULONGLONG)PTable->Entry[uli].LBAStartSector;
		}
		else
		{			
			if (PTable->Entry[uli].Descriptor != 0)
			{
				// This is an existing non-NTFS partition
				ulNonNtFirst = PTable->Entry[uli].LBAStartSector;
				ulNonNtSize	= PTable->Entry[uli].PartitionSize;
			}
		}
	}	// for (i=0; i<BIOS_MAX_PARTITION_COUNT; i++)
	if (ulStartSector > BK_FS_SIZE_MIN)
	{
		// There is a space for VFS before the first partition
		pFsArea->StartSector = 1;
		pFsArea->NumberOfSectors = ulStartSector - 1;
	}
	else	// if (StartSector > BK_FS_SIZE_MIN)
	{
		ULONG LastSector = (pDiskGeo->Cylinders.LowPart * pDiskGeo->TracksPerCylinder * pDiskGeo->SectorsPerTrack);
		// LastSectior value can be smaller then EndSector (bacause of alingment?). 
		//	In this case using LastSectior as the end of the partitioned space.
		if ((LastSector > ulEndSector) && ((LastSector - ulEndSector) > BK_FS_SIZE_MIN))
		{
			// There is a space for VFS after the last partition
			pFsArea->StartSector = (ULONGLONG)(ulEndSector + 1);
			pFsArea->NumberOfSectors = LastSector - ulEndSector - 1;
		}
		else
		{
			if (ulNonNtSize >= BK_FS_SIZE_MIN)
			{
				// Using a part of an existing non-NTFS partition to store the VFS
				pFsArea->StartSector = (ULONGLONG)ulNonNtFirst + ulNonNtSize - BK_FS_SIZE_MIN;
			}
			else
			{
				// Trying to reduce last partition size to fit the VFS
				pFsArea->StartSector = (ULONGLONG)LastSector - BK_FS_SIZE_MIN;
			}
			pFsArea->NumberOfSectors = BK_FS_SIZE_MIN;
		}
	}	// else	// if (StartSector > BK_FS_SIZE_MIN)
	pFsArea->BytesPerSector = pDiskGeo->BytesPerSector;
}


//
//	Searches for and allocates space for BK file system partition.
//  Fills BK_FS_AREA structure with partition start sector and sizes.
//
NTSTATUS BkAllocateFsArea(PBK_FS_AREA pFsArea,PVOID WorkBuffer)
{

	NTSTATUS Status;
	PCHAR pSector = (PCHAR)WorkBuffer;
	DISK_GEOMETRY pDiskGeo;
	ULONGLONG LStartSector = 0;
	PPARTITION_TABLE PTable;

	do
	{
		if (!(NT_SUCCESS(Status = GetDriveGeometry(pFsArea->pDeviceName,&pDiskGeo))))
		{
			break;
		}
		if (pDiskGeo.BytesPerSector != BIOS_DEFAULT_SECTOR_SIZE)
		{
			// Unsupported sector size
			Status = STATUS_BAD_DEVICE_TYPE; 			
			break;
		}
		// Reading MBR sector
		if (!(NT_SUCCESS(Status = BkReadSectors(pFsArea->pDeviceName,pSector,BIOS_DEFAULT_SECTOR_SIZE,LStartSector,1))))
		{
			// Reading failed 
			break;
		}
		// Check out we read a right one
		if (*(PUSHORT)(pSector + BIOS_DEFAULT_SECTOR_SIZE - sizeof(USHORT)) != BIOS_MBR_MAGIC)
		{
			// Wrong or corrupt sector loaded
			Status = STATUS_BAD_DEVICE_TYPE;
			break;
		}
		// We have read the Disk Boot sector and now analyzing it's partition table
		PTable = (PPARTITION_TABLE)(pSector + BIOS_PARTITION_TABLE_OFFSET);
		CalculateFsArea(&pDiskGeo,PTable,pFsArea);
	} while(FALSE);
	return Status;
}
