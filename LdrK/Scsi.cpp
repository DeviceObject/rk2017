#include "stdafx.h"
#include "Scsi.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Reads or writes specified number of sectors from/to specified buffer using SCSI PATH THROUGH method.
//
static BOOL ScsiIo(PWCHAR pDriveW,		// drive name to read/write sectors from/to
				   PCHAR pBuffer,		// buffer to store the data
				   ULONG Length,		// size of the buffer in bytes
				   ULONG LBASector,	// starting LBA sector
				   ULONG ulCount,		// number of sectors to read/write
				   ULONG ulFlags		// variouse operation flags
				   )
{
	BOOLEAN	Ret = FALSE;
	HANDLE hDrive;
	WINERROR Status;
	ULONG ulRead = 0;
	ULONG ulLen = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
	PSCSI_PASS_THROUGH_DIRECT pSpt;
	PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER pSptb;
	UCHAR Direction,OpCode,OpCode16;

	if (ulFlags & SCSI_IO_WRITE_SECTOR)
	{
		Direction = SCSI_IOCTL_DATA_OUT;
		OpCode = SCSIOP_WRITE;
		OpCode16 = SCSIOP_WRITE16;
	}
	else
	{
		ASSERT(ulFlags & SCSI_IO_READ_SECTOR);
		Direction = SCSI_IOCTL_DATA_IN;
		OpCode = SCSIOP_READ;
		OpCode16 = SCSIOP_READ16;

	}	// if (Flags & SCSI_IO_READ)

	if (pSpt = (PSCSI_PASS_THROUGH_DIRECT)malloc(ulLen))
	{
		memset(pSpt,0,ulLen);
		pSptb = (PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER)pSpt;
		hDrive = CreateFile(pDriveW,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
		if (hDrive != INVALID_HANDLE_VALUE)
		{
			pSpt->Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
			pSpt->PathId = 0;
			pSpt->TargetId = 0; 
			pSpt->Lun = 0; 
			pSpt->CdbLength = 16; 
			pSpt->SenseInfoLength = SPTWB_SENSE_LENGTH; 
			pSpt->DataIn = Direction;
			pSpt->DataTransferLength = Length; 
			pSpt->TimeOutValue = 200; 
			pSpt->DataBuffer = pBuffer; 
			pSpt->SenseInfoOffset = (ULONG)((PCHAR)&pSptb->SenseInfoBuffer - (PCHAR)pSptb);

			// Formating CDB16
			if (LOBYTE(LOWORD(GetVersion())) > 5)
			{
				// Vista and highter
				pSpt->Cdb16.OperationCode = OpCode16;
			}
			else
			{
				// XP and w2k3
				pSpt->Cdb16.OperationCode = OpCode;
			}
			pSpt->Cdb16.ForceUnitAccess = TRUE;

			pSpt->Cdb16.LogicalBlock[0] = HIBYTE(HIWORD(LBASector));
			pSpt->Cdb16.LogicalBlock[1] = LOBYTE(HIWORD(LBASector));
			pSpt->Cdb16.LogicalBlock[2] = HIBYTE(LOWORD(LBASector));
			pSpt->Cdb16.LogicalBlock[3] = LOBYTE(LOWORD(LBASector));

			pSpt->Cdb16.TransferLength[0] = HIBYTE(HIWORD(ulCount));
			pSpt->Cdb16.TransferLength[1] = LOBYTE(HIWORD(ulCount));
			pSpt->Cdb16.TransferLength[2] = HIBYTE(LOWORD(ulCount));
			pSpt->Cdb16.TransferLength[3] = LOBYTE(LOWORD(ulCount));

			pSpt->Cdb16.Control = 0x10;

			// Sending SRB block to the device
			Status = DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,pSpt,ulLen,pSpt,ulLen,&ulRead,NULL);
			if ((Status) && ulRead < ulLen)
			{
				Ret = TRUE;
			}
			else
			{
				Status = GetLastError();
			}
			CloseHandle(hDrive);
		}	// if (hDrive != INVALID_HANDLE_VALUE)
		free(pSpt);
	}
	return(Ret);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Reads or writes specified number of sectors from/to specified buffer.
//
static BOOL DirectIo(PWCHAR	pDriveW,			// drive name to read/write sectors from/to
						 PCHAR	pBuffer,			// bufer to store the data
						 ULONG	ulLength,			// size of the buffer
						 ULONG	ulLBASector,		// starting LBA sector
						 ULONG	ulCount,			// number of sectors to read/write
						 ULONG	ulFlags			// variouse operation flags
						 )
{
	BOOLEAN bRet = FALSE;
	HANDLE hDrive;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes = {0};
	UNICODE_STRING us;
	IO_STATUS_BLOCK IoStatus = {0};
	LARGE_INTEGER lFilePos = {0};
	HANDLE hEvent = CreateEvent(NULL,TRUE,FALSE,NULL);

	RtlInitUnicodeString(&us,pDriveW);
	InitializeObjectAttributes(&ObjectAttributes,&us,OBJ_CASE_INSENSITIVE,NULL,NULL);

	if ((ulCount * BIOS_DEFAULT_SECTOR_SIZE) <= ulLength)
	{
		Status = NtCreateFile(&hDrive, \
			GENERIC_WRITE | GENERIC_READ, \
			&ObjectAttributes, \
			&IoStatus, \
			NULL, \
			FILE_ATTRIBUTE_NORMAL, \
			FILE_SHARE_READ | FILE_SHARE_WRITE, \
			FILE_OPEN, \
			0, \
			NULL, \
			0);
		if (NT_SUCCESS(Status))
		{
			lFilePos.QuadPart = ((ULONGLONG)ulLBASector * BIOS_DEFAULT_SECTOR_SIZE);

			if (ulFlags & SCSI_IO_WRITE_SECTOR)
			{
				Status = NtWriteFile(hDrive, \
				hEvent, \
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
				Status = NtReadFile(hDrive, \
					hEvent, \
					NULL, \
					NULL, \
					&IoStatus, \
					pBuffer, \
					(ulCount * BIOS_DEFAULT_SECTOR_SIZE), \
					&lFilePos, \
					NULL);
			}
			if (Status == STATUS_PENDING)
			{
				WaitForSingleObject(hEvent,INFINITE);
			}
			NtClose(hDrive);
			if (NT_SUCCESS(IoStatus.Status))
			{
				bRet = TRUE;
			}
		}
	}
	return bRet;
}

