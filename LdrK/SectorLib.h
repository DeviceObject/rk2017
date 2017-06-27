#ifndef __SECTOR_LIB_H__
#define __SECTOR_LIB_H__




#define NTFS_OEM_ID				"NTFS    "
#define NTFS_LOADER_SIZE		16		// sectors
#define NTFS_LDR_HEADER_SIZE	0x20	// bytes

#define		BK_IO_READ		1
#define		BK_IO_WRITE		2


// BIOS structures
typedef struct _PARTITION_TABLE_ENTRY
{
	ULONG		ActiveFlag		: 8;
	ULONG		CHSStartSector	: 24;
	ULONG		Descriptor		: 8;
	ULONG		CHSEndSector	: 24;
	ULONG		LBAStartSector;
	ULONG		PartitionSize;	
}PARTITION_TABLE_ENTRY, *PPARTITION_TABLE_ENTRY;


typedef	struct	_PARTITION_TABLE	
{
	PARTITION_TABLE_ENTRY	Entry[BIOS_MAX_PARTITION_COUNT];
}PARTITION_TABLE, *PPARTITION_TABLE;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	BK file system area descriptor.
typedef struct _BK_FS_AREA
{
	PUNICODE_STRING pDeviceName;		// Name of the device where BK FS partition located
	HANDLE			hDevice;			// Handle to the device
	ULONGLONG		StartSector;		// Start sector of the BK FS partition
	ULONG			NumberOfSectors;	// Number of sectors within BK FS partition
	ULONG			BytesPerSector;		// Bytes per sector 
	ULONGLONG		BootSector;			// Boot sector of the active partition (containing initial loader)
} BK_FS_AREA, *PBK_FS_AREA;


// Minimum supportd FS size
#define		BK_FS_SIZE_MIN				2000	// sectors
#define		BK_FS_RESERVED_SECTORS		1		// number of FS reserved sectors
#define		BK_FS_NUMBER_FATS			1		// number of File allocation tables
#define		BK_FS_SECTORS_PER_ROOT		1		// initial Root directory size (sectors)
#define		BK_FS_BOOT_FILE_SIZE		102400	// size of BOOT.SYS file (the place for the loader) in bytes

#pragma pack (push)
#pragma pack(1)

// BIOS Parameter block
typedef	struct _BPB
{
	USHORT		SectorSize;
	UCHAR		SectorsPerCluster;
	USHORT		RecervedSectors;
	UCHAR		NumberOfFats;			// for FAT only
	union
	{
		USHORT		MaxRDEntries;		// for FAT only
		USHORT		FirstRDSector;		// for VFAT
	};
	USHORT		SmallSectorsCount;		// for FAT12/16 only
	UCHAR		MediaDescriptorId;		
	USHORT		SectorsPerFat;			// for FAT only
	USHORT		SectorsPerTrack;
	USHORT		NumberOfHeads;
	ULONG		NumberOfHiddenSectors;
	ULONG		FatTotalSectors;		// for FAT only
	union {
		ULONG		DriveNumber;
		ULONG		RDSize;				// for VFAT
	};
	ULONGLONG	VolumeTotalSectors;		// NTFS only
	ULONGLONG	MftStartingCluster;		// NTFS only
	ULONGLONG	MftMirrowCluster;		// NTFS only
	LONG		ClustersPerRecord;		// NTFS only
	ULONG		ClustersPerIndex;		// NTFS only
	ULONGLONG	VolumeSerialNumber;		// NTFS only
	ULONG		Checksum;
} BPB, *PBPB;

// Volume Boot Record
typedef struct	_VBR
{
	CHAR JumpInstruction[3];
	CHAR VolumeOemId[8];
	BPB Bpb;
} VBR,*PVBR;

#pragma pack(pop)

NTSTATUS _stdcall SectorIo(PUNICODE_STRING pUniDriveName,		// drive name to read/write sectors from/to
						   PCHAR pBuffer,			// bufer to store the data
						   ULONG ulLength,			// size of the buffer
						   ULONGLONG ulStartSector,	// starting LBA sector
						   ULONG ulCount,			// number of sectors to read/write
						   ULONG ulFlags);
NTSTATUS _stdcall GetDriveGeometry(PUNICODE_STRING pUniDriveName,PVOID pDriveGeo);

#define BkReadSectors(uDriveName,pBuffer,Length,StartSector,Count)	\
	SectorIo(uDriveName,pBuffer,Length,StartSector,Count,BK_IO_READ)

#define BkWriteSectors(uDriveName,pBuffer,Length,StartSector,Count)	\
	SectorIo(uDriveName,pBuffer,Length,StartSector,Count,BK_IO_WRITE)

#endif