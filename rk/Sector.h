#ifndef __SECTOR_H__
#define __SECTOR_H__

#define		BIOS_DEFAULT_SECTOR_SIZE			0x200		// 512 bytes
#define		BIOS_MBR_MAGIC						0xaa55
#define		BIOS_PARTITION_TABLE_OFFSET			0x1be
#define		BIOS_MAX_PARTITION_COUNT			4
#define		BIOS_PARTITION_ACTIVE_FLAG			0x80
#define		BIOS_PARTITION_TYPE_INSTALLABLE		7
#define		VBR_DEFAULT_SIZE					0x2000
#define		NTFS_OEM_ID							"NTFS    "
#define		NTFS_LOADER_SIZE					16		// sectors
#define		NTFS_LDR_HEADER_SIZE				0x20	// bytes

#define		BK_IO_READ							1
#define		BK_IO_WRITE							2

#define		OP_JMP_SHORT						0xeb
#define		OP_JMP_NEAR							0xe9

#define		PARTITION							L"\\Device\\Harddisk0\\Partition%u"
#define		PHYSICALDRIVE0						L"\\??\\PHYSICALDRIVE0"

typedef struct _SENSE_DATA
{
	unsigned char Valid;
	unsigned char SegmentNumber;
	unsigned char FileMark;
	unsigned char Information[4];
	unsigned char AdditionalSenseLength;
	unsigned char CommandSpecificInformation[4];
	unsigned char AdditionalSenseCode;
	unsigned char AdditionalSenseCodeQualifier;
	unsigned char FieldReplaceableUnitCode;
	unsigned char SenseKeySpecific[3];
} SENSE_DATA,*PSENSE_DATA;

// BIOS structures
typedef struct _PARTITION_TABLE_ENTRY
{
	//0x80
	ULONG		ActiveFlag		: 8;
	//0x002120
	ULONG		CHSStartSector	: 24;
	//0x07
	ULONG		Descriptor		: 8;
	//0xFFFFFE
	ULONG		CHSEndSector	: 24;
	//0x00000800
	ULONG		LBAStartSector;
	//0x01DFF000
	ULONG		PartitionSize;	
}PARTITION_TABLE_ENTRY, *PPARTITION_TABLE_ENTRY;


typedef	struct	_PARTITION_TABLE	
{
	PARTITION_TABLE_ENTRY Entry[BIOS_MAX_PARTITION_COUNT];
}PARTITION_TABLE, *PPARTITION_TABLE;

typedef struct _DISK_ADDRESS_PACKET
{
	UCHAR PacketSize;    // ���ݰ��ߴ�(16�ֽ�)
	UCHAR Reserved;      // ==0
	USHORT BlockCount;    // Ҫ��������ݿ����(������Ϊ��λ)
	ULONG BufferAddr;    // ���仺���ַ(segment:offset,���ڴ���Ϊoffset�ڵ͵�ַ��166b:400���ڴ���Ϊ��00 04 6b 16)
	ULONGLONG BlockNum;      // ������ʼ���Կ��ַ����LBA��ַ��
}DISK_ADDRESS_PACKET,*PDISK_ADDRESS_PACKET;

typedef struct _DRIVE_PARAMETERS_PACKET
{
	//0x1A00
	USHORT InfoSize;          // ���ݰ��ߴ� (26 �ֽ�)
	//0x0003
	USHORT Flags;            // ��Ϣ��־
	//0x981E0000
	ULONG Cylinders;        // ����������
	//0x000000FF
	ULONG Heads;            // ���̴�ͷ��
	//0x0000003F
	ULONG SectorsPerTrack;  // ÿ�ŵ�������
	//0x00008007 00000000
	//0x00000000 07800000
	ULONGLONG Sectors;          // ������������
	//0x0200
	USHORT SectorSize;        // �����ߴ� (���ֽ�Ϊ��λ)
}DRIVE_PARAMETERS_PACKET,*PDRIVE_PARAMETERS_PACKET;

#pragma pack(push)
#pragma pack(1)

// BIOS Parameter block
typedef	struct _BPB
{
	USHORT SectorSize;
	UCHAR SectorsPerCluster;
	USHORT RecervedSectors;
	UCHAR NumberOfFats;			// for FAT only
	union
	{
		USHORT MaxRDEntries;		// for FAT only
		USHORT FirstRDSector;		// for VFAT
	};
	USHORT SmallSectorsCount;		// for FAT12/16 only
	UCHAR MediaDescriptorId;		
	USHORT SectorsPerFat;			// for FAT only
	USHORT SectorsPerTrack;
	USHORT NumberOfHeads;
	ULONG NumberOfHiddenSectors;
	ULONG FatTotalSectors;		// for FAT only
	union
	{
		ULONG DriveNumber;
		ULONG RDSize;				// for VFAT
	};
	ULONGLONG VolumeTotalSectors;		// NTFS only
	ULONGLONG MftStartingCluster;		// NTFS only
	ULONGLONG MftMirrowCluster;		// NTFS only
	LONG ClustersPerRecord;		// NTFS only
	ULONG ClustersPerIndex;		// NTFS only
	ULONGLONG VolumeSerialNumber;		// NTFS only
	ULONG Checksum;
}BPB,*PBPB;

// Volume Boot Record
typedef struct _VBR
{
	CHAR JumpInstruction[3];
	CHAR VolumeOemId[8];
	BPB Bpb;
} VBR,*PVBR;

#pragma pack(pop)

NTSTATUS __stdcall GetDriveGeometry(PUNICODE_STRING pUniDriveName,PVOID pDriveGeometry);
NTSTATUS __stdcall SectorIo(PUNICODE_STRING pUniDriveName, \
							PCHAR pBuffer, \
							ULONG ulLength, \
							ULONGLONG ulStartSector, \
							ULONG ulCount, \
							ULONG ulFlags);

#define OrReadSectors(pUniDriveName,pBuffer,ulLength,ulStartSector,ulCount)	\
	SectorIo(pUniDriveName,pBuffer,ulLength,ulStartSector,ulCount,BK_IO_READ)

#define OrWriteSectors(pUniDriveName,pBuffer,ulLength,ulStartSector,ulCount)	\
	SectorIo(pUniDriveName,pBuffer,ulLength,ulStartSector,ulCount,BK_IO_WRITE)

BOOLEAN __stdcall DirectWriteSectors(PWSTR pDrive,PCHAR pBuffer,ULONG ulLength,ULONG ulSector,ULONG ulCount);
BOOLEAN __stdcall DirectReadSectors(PWSTR pDrive,PCHAR pBuffer,ULONG ulLength,ULONG ulSector,ULONG ulCount);


#ifdef	_SCSI_IO
#define	ReadSectors(a,b,c,d,e)	ScsiReadSectors(a,b,c,d,e)
#define	WriteSectors(a,b,c,d,e)	ScsiWriteSectors(a,b,c,d,e)
#else
#define	ReadSectors(a,b,c,d,e)	DirectReadSectors(a,b,c,d,e)
#define	WriteSectors(a,b,c,d,e)	DirectWriteSectors(a,b,c,d,e)
#endif

NTSTATUS ReadSector(ULONG ulDiskIndex,ULONG ulSectorSize,ULONG ulStartSector,PCHAR pSector,ULONG ulLength);
NTSTATUS WriteSector(ULONG ulDiskIndex,ULONG ulSectorSize,ULONG ulStartSector,PCHAR pSector,ULONG ulLength);
PDEVICE_OBJECT GetSelectDevObj(ULONG ulIndex);

NTSTATUS ReadVbrFromSector(PCHAR *pVbr,ULONG ulVbrSize);
NTSTATUS WriteVbrFromSector(PCHAR pVbr,ULONG ulVbrSize);
BOOLEAN VbrCheck();

#endif