#include "rk.h"
#include <srb.h>
#include "DefSystemVar.h"
#include "DrvFileSystem.h"
#include "Utils.h"
#include "Sector.h"

#pragma warning (disable: 4333)


BOOLEAN __stdcall DirectReadSectors(PWSTR pDrive,PCHAR pBuffer,ULONG ulLength,ULONG ulSector,ULONG ulCount)
{
	NTSTATUS Status;
	UNICODE_STRING UniDriveName;

	RtlInitUnicodeString(&UniDriveName,pDrive);

	Status = OrReadSectors(&UniDriveName,pBuffer,ulLength,(ULONGLONG)ulSector,ulCount);
	if (NT_SUCCESS(Status))
	{
		return TRUE;
	}
	return FALSE;
}


BOOLEAN __stdcall DirectWriteSectors(PWSTR pDrive,PCHAR pBuffer,ULONG ulLength,ULONG ulSector,ULONG ulCount)
{
	NTSTATUS Status;
	UNICODE_STRING UniDriveName;

	RtlInitUnicodeString(&UniDriveName,pDrive);
	Status = OrWriteSectors(&UniDriveName,pBuffer,ulLength,(ULONGLONG)ulSector,ulCount);
	if (NT_SUCCESS(Status))
	{
		return TRUE;
	}
	return FALSE;
}
NTSTATUS __stdcall SectorIo(PUNICODE_STRING pUniDriveName, \
							PCHAR pBuffer, \
							ULONG ulLength, \
							ULONGLONG ulStartSector, \
							ULONG ulCount, \
							ULONG ulFlags)
{
	HANDLE hDrive;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatus;
	LARGE_INTEGER lFilePos;
	ULONG ulObjectFlags;

	Status = STATUS_BUFFER_TOO_SMALL;
	ulObjectFlags = OBJ_CASE_INSENSITIVE;

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
		//Status = ZwCreateFile(&hDrive, \
		//    FILE_GENERIC_READ | FILE_GENERIC_WRITE, \
		//    &ObjectAttributes, \
		//    &IoStatus, \
		//    NULL, \
		//    0, \
		//    FILE_SHARE_READ | FILE_SHARE_WRITE, \
		//    FILE_OPEN, \
		//    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, \
		//    NULL, \
		//    0);
		Status = ZwOpenFile(&hDrive, \
			FILE_GENERIC_READ | FILE_GENERIC_WRITE, \
			&ObjectAttributes, \
			&IoStatus, \
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
					ulCount * BIOS_DEFAULT_SECTOR_SIZE, \
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
					ulCount * BIOS_DEFAULT_SECTOR_SIZE, \
					&lFilePos, \
					NULL);
			}
			ZwClose(hDrive);
		}
	}
	return Status;
}
NTSTATUS IrpCompletionRoutine_0(IN PDEVICE_OBJECT DeviceObject,
								IN PIRP Irp,
								IN PVOID Context)
{
	PMDL pMdl;
	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;
	if (!Context)
	{
		pMdl = Irp->MdlAddress;
		if (pMdl)
		{
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
		}
	}
	KeSetEvent(Irp->UserEvent,IO_NO_INCREMENT,0);
	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS MyIoCallDriver(PDEVICE_OBJECT DeviceObject,PIRP pIrp)//自己的IoCallDriver
{
	PIO_STACK_LOCATION pIrpStack;
	--pIrp->CurrentLocation;
	pIrpStack = IoGetNextIrpStackLocation(pIrp);
	pIrp->Tail.Overlay.CurrentStackLocation = pIrpStack;//移动堆栈
	pIrpStack->DeviceObject = DeviceObject;
	return (DeviceObject->DriverObject->MajorFunction[(ULONG)pIrpStack->MajorFunction])(DeviceObject,pIrp);
}

ULONG AtapiReadWriteDisk(PDEVICE_OBJECT dev_object,
						 ULONG MajorFunction, 
						 PVOID buffer,
						 ULONG DiskPos, 
						 int BlockCount)
{
	NTSTATUS status;
	SCSI_REQUEST_BLOCK ScsiRequestBlock;
	SENSE_DATA SenseData;
	KEVENT Event;
	PIRP irp;
	PMDL mdl;
	IO_STATUS_BLOCK isb;
	PIO_STACK_LOCATION isl;

	do 
	{
		RtlZeroMemory(&ScsiRequestBlock,sizeof(SCSI_REQUEST_BLOCK));
		RtlZeroMemory(&SenseData,sizeof(SENSE_DATA));

		// 更多关于srb,请看《SCSI 总线和IDE接口：协议、应用和编程》和《SCSI程序员指南》
		ScsiRequestBlock.Length = sizeof(SCSI_REQUEST_BLOCK);
		ScsiRequestBlock.Function = 0;
		ScsiRequestBlock.DataBuffer = buffer;

		ScsiRequestBlock.DataTransferLength = BlockCount << 9;//BlockCount << 9; //sector size*number of sector
		ScsiRequestBlock.QueueAction = SRB_FLAGS_DISABLE_AUTOSENSE;
		ScsiRequestBlock.SrbStatus = 0;
		ScsiRequestBlock.ScsiStatus = 0;
		ScsiRequestBlock.NextSrb = 0;
		ScsiRequestBlock.SenseInfoBuffer = &SenseData;
		ScsiRequestBlock.SenseInfoBufferLength = sizeof(SENSE_DATA);
		if(MajorFunction == IRP_MJ_READ)
			ScsiRequestBlock.SrbFlags = SRB_FLAGS_DATA_IN;
		else
			ScsiRequestBlock.SrbFlags = SRB_FLAGS_DATA_OUT;

		if(MajorFunction == IRP_MJ_READ)
			ScsiRequestBlock.SrbFlags |= SRB_FLAGS_ADAPTER_CACHE_ENABLE;

		ScsiRequestBlock.SrbFlags |= SRB_FLAGS_DISABLE_AUTOSENSE;
		ScsiRequestBlock.TimeOutValue = (ScsiRequestBlock.DataTransferLength>>10) + 1;
		ScsiRequestBlock.QueueSortKey = DiskPos;
		ScsiRequestBlock.CdbLength = 10;
		ScsiRequestBlock.Cdb[0] = 2*((UCHAR)MajorFunction+ 17);
		ScsiRequestBlock.Cdb[1] = ScsiRequestBlock.Cdb[1] & 0x1F | 0x80;
		ScsiRequestBlock.Cdb[2] = (unsigned char)(DiskPos>>0x18)&0xFF;     //
		ScsiRequestBlock.Cdb[3] = (unsigned char)(DiskPos>>0x10)&0xFF;     //
		ScsiRequestBlock.Cdb[4] = (unsigned char)(DiskPos>>0x08)&0xFF;     //
		ScsiRequestBlock.Cdb[5] = (UCHAR)DiskPos;           //填写sector位置
		ScsiRequestBlock.Cdb[7] = (UCHAR)BlockCount>>0x08;
		ScsiRequestBlock.Cdb[8] = (UCHAR)BlockCount;

		//By:Eros412
		KeInitializeEvent(&Event, 0, 0);
		irp = IoAllocateIrp(dev_object->StackSize, 0);
		mdl = IoAllocateMdl(buffer, BlockCount<<9, 0, 0, irp);
		irp->MdlAddress = mdl;
		if(!mdl)
		{
			if (irp)
			{
				IoFreeIrp(irp);
			}
			return STATUS_INSUFFICIENT_RESOURCES;
		} 
		MmProbeAndLockPages(mdl, KernelMode, (MajorFunction==IRP_MJ_READ?IoReadAccess:IoWriteAccess));
		ScsiRequestBlock.OriginalRequest = irp;
		irp->UserIosb = &isb;
		//IoSetCancelRoutine(irp,MyCancel);
		irp->UserEvent = &Event;
		irp->IoStatus.Status = 0;
		irp->IoStatus.Information = 0;
		irp->Flags = IRP_SYNCHRONOUS_API|IRP_NOCACHE;
		irp->AssociatedIrp.SystemBuffer = 0;
		irp->Cancel = 0;
		irp->RequestorMode = 0;
		irp->CancelRoutine = 0;
		irp->Tail.Overlay.Thread = PsGetCurrentThread();
		isl = IoGetNextIrpStackLocation(irp);
		isl->DeviceObject = dev_object;
		isl->MajorFunction = IRP_MJ_SCSI;
		isl->Parameters.Scsi.Srb = &ScsiRequestBlock;
		isl->CompletionRoutine = IrpCompletionRoutine_0;
		isl->Context = &ScsiRequestBlock;
		isl->Control = SL_INVOKE_ON_CANCEL|SL_INVOKE_ON_SUCCESS|SL_INVOKE_ON_ERROR;
		status = MyIoCallDriver(dev_object,irp);
		KeWaitForSingleObject(&Event,Executive,ExGetPreviousMode(),FALSE,0);
		if (mdl)
		{
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
		if (NT_SUCCESS(status))
		{
			return status;
		}

		//DbgPrint("Send XXX Failed..%08x\r\n", status);
		//KeStallExecutionProcessor(1u);
		//--count;
	} while (0);
	return STATUS_INSUFFICIENT_RESOURCES;
}
PDEVICE_OBJECT GetSelectDevObj(ULONG ulIndex)
{
	UNICODE_STRING unStrName;
	UNICODE_STRING unStrDiskName;
	PDRIVER_OBJECT pDiskDrvObj;
	PDEVICE_OBJECT pDevObj;
	ULONG ulRetSize;
	WCHAR wSymName[MAX_PATH_LEN];
	CHAR ObjName[MAX_PATH_LEN];
	NTSTATUS Status;

	RtlZeroMemory(wSymName,sizeof(WCHAR) * MAX_PATH_LEN);
	StringCchPrintfW(wSymName,MAX_PATH_LEN,L"\\Device\\Harddisk%d\\DR%d",ulIndex,ulIndex);
	RtlInitUnicodeString(&unStrName,wSymName);

	RtlInitUnicodeString(&unStrDiskName, L"\\Driver\\Disk");
	if(ObReferenceObjectByName(&unStrDiskName,64,0,0,*IoDriverObjectType,0,0,&pDiskDrvObj) < 0)
	{
		return NULL;
	}
	pDevObj = pDiskDrvObj->DeviceObject;
	while (pDevObj)
	{
		Status = ObQueryNameString(pDevObj,(POBJECT_NAME_INFORMATION)ObjName,MAX_PATH_LEN,&ulRetSize);
		if (NT_SUCCESS(Status))
		{
			if (RtlCompareUnicodeString(&((POBJECT_NAME_INFORMATION)ObjName)->Name,&unStrName,TRUE) == 0)
			{
				ObDereferenceObject(pDiskDrvObj);
				return pDevObj;
			}
		}
		pDevObj = pDevObj->NextDevice;
	}
	ObDereferenceObject(pDiskDrvObj);
	return NULL;
}
NTSTATUS ReadSector(ULONG ulDiskIndex,ULONG ulSectorSize,ULONG ulStartSector,PCHAR pSector,ULONG ulLength)
{
	PDEVICE_OBJECT pDiskDevice;
	ULONG ulRealLength;
	NTSTATUS Status;

	if (NULL == pSector)
	{
		return STATUS_INVALID_PARAMETER_4;
	}

	pDiskDevice = NULL;
	ulRealLength = 0;
	Status = STATUS_SUCCESS;

	pDiskDevice = GetSelectDevObj(ulDiskIndex);
	if (!pDiskDevice)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	if (ulLength % ulSectorSize == 0)
	{
		return AtapiReadWriteDisk(pDiskDevice, \
			IRP_MJ_READ, \
			(PVOID)pSector, \
			ulStartSector, \
			((ulLength - 1) / ulSectorSize + 1));
	}
	else
	{
		return STATUS_INVALID_PARAMETER;
	}
}
NTSTATUS WriteSector(ULONG ulDiskIndex,ULONG ulSectorSize,ULONG ulStartSector,PCHAR pSector,ULONG ulLength)
{
	PDEVICE_OBJECT pDiskDevice;
	ULONG ulRealLength;
	NTSTATUS Status;

	if (NULL == pSector)
	{
		return STATUS_INVALID_PARAMETER_4;
	}

	pDiskDevice = NULL;
	ulRealLength = 0;
	Status = STATUS_SUCCESS;

	pDiskDevice = GetSelectDevObj(ulDiskIndex);
	if (!pDiskDevice)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	// 整数个扇区
	if (ulLength % ulSectorSize == 0)
	{
		return AtapiReadWriteDisk(pDiskDevice, \
			IRP_MJ_WRITE, \
			(PVOID)pSector, \
			ulStartSector, \
			((ulLength - 1) / ulSectorSize + 1));
	}
	else
	{
		return STATUS_INVALID_PARAMETER;
	}
}
NTSTATUS WriteVbrFromSector(PCHAR pVbr,ULONG ulVbrSize)
{
	NTSTATUS Status;
	BOOLEAN bRet;
	PCHAR pVbs;
	ULONG uli;
	ULONG ulStartSector;
	PVBR pCheckVbr;
	WCHAR TargetDriveW[MAX_PATH];
	PPARTITION_TABLE pPartitionTable;

	bRet = FALSE;
	Status = STATUS_SUCCESS;
	pVbs = NULL;
	uli = 0;
	pCheckVbr = NULL;
	ulStartSector = 0;
	RtlZeroMemory(TargetDriveW,sizeof(WCHAR) * MAX_PATH);

	StringCchPrintfW(TargetDriveW,MAX_PATH,PARTITION,0);
	do 
	{
		do 
		{
			pVbs = (PCHAR)KernelMalloc(BIOS_DEFAULT_SECTOR_SIZE);
		} while (NULL == pVbs);
		RtlZeroMemory(pVbs,BIOS_DEFAULT_SECTOR_SIZE);
		bRet = ReadSectors(TargetDriveW,pVbs,BIOS_DEFAULT_SECTOR_SIZE,0,1);
		if (FALSE == bRet)
		{
			Status = STATUS_PARTITION_FAILURE;
			break;
		}
		if (*(PUSHORT)(pVbs + BIOS_DEFAULT_SECTOR_SIZE - sizeof(USHORT)) != BIOS_MBR_MAGIC)
		{
			Status = STATUS_PARTITION_FAILURE;
			break;
		}
		pPartitionTable = (PPARTITION_TABLE)(pVbs + BIOS_PARTITION_TABLE_OFFSET);
		while(uli < BIOS_MAX_PARTITION_COUNT && \
			(!(pPartitionTable->Entry[uli].ActiveFlag & BIOS_PARTITION_ACTIVE_FLAG) || \
			pPartitionTable->Entry[uli].Descriptor != BIOS_PARTITION_TYPE_INSTALLABLE))
		{
			uli += 1;
		}
		if (uli >= BIOS_MAX_PARTITION_COUNT)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
#ifdef	_PHYSICAL_DRIVE
		ulStartSector = pPartitionTable->Entry[uli].LBAStartSector;
#else
		StringCchPrintfW(TargetDriveW,MAX_PATH,PARTITION,(uli + 1));
		//wsprintf(TargetDriveW,PARTITION,(uli + 1));
		ulStartSector = 0;
#endif
		//bRet = ReadSectors(TargetDriveW,pVbs,BIOS_DEFAULT_SECTOR_SIZE,ulStartSector,1);
		//if (FALSE == bRet)
		//{
		//	Status = STATUS_UNSUCCESSFUL;
		//	break;
		//}
		//pCheckVbr = (PVBR)pVbs;
		//if (memcmp(&pCheckVbr->VolumeOemId,NTFS_OEM_ID,sizeof(NTFS_OEM_ID)))
		//{
		//	Status = STATUS_UNSUCCESSFUL;
		//	break;
		//}
		bRet = WriteSectors(TargetDriveW,pVbr,ulVbrSize,0,ulVbrSize / BIOS_DEFAULT_SECTOR_SIZE);
		if (FALSE == bRet)
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	} while (0);
	if (NT_ERROR(Status) && pVbs)
	{
		KernelFree(pVbs);
	}
	return Status;
}
NTSTATUS ReadVbrFromSector(PCHAR *pVbr,ULONG ulVbrSize)
{
	NTSTATUS Status;
	BOOLEAN bRet;
	ULONG uli;
	ULONG ulStartSector;
	PCHAR pVbs;
	PVBR pCheckVbr;
	WCHAR TargetDriveW[MAX_PATH];
	PPARTITION_TABLE pPartitionTable;

	bRet = FALSE;
	uli = 0;
	Status = STATUS_SUCCESS;
	pPartitionTable = NULL;
	*pVbr = NULL;
	pVbs = NULL;
	pCheckVbr = NULL;
	RtlZeroMemory(TargetDriveW,sizeof(WCHAR) * MAX_PATH);

	StringCchPrintfW(TargetDriveW,MAX_PATH,PARTITION,0);
	do 
	{
		do 
		{
			pVbs = (PCHAR)KernelMalloc(BIOS_DEFAULT_SECTOR_SIZE);
		} while (NULL == pVbs);
		RtlZeroMemory(pVbs,BIOS_DEFAULT_SECTOR_SIZE);
		bRet = ReadSectors(TargetDriveW,pVbs,BIOS_DEFAULT_SECTOR_SIZE,0,1);
		if (FALSE == bRet)
		{
			Status = STATUS_PARTITION_FAILURE;
			break;
		}
		if (*(PUSHORT)(pVbs + BIOS_DEFAULT_SECTOR_SIZE - sizeof(USHORT)) != BIOS_MBR_MAGIC)
		{
			Status = STATUS_PARTITION_FAILURE;
			break;
		}
		pPartitionTable = (PPARTITION_TABLE)(pVbs + BIOS_PARTITION_TABLE_OFFSET);
		while(uli < BIOS_MAX_PARTITION_COUNT && \
			(!(pPartitionTable->Entry[uli].ActiveFlag & BIOS_PARTITION_ACTIVE_FLAG) || \
			pPartitionTable->Entry[uli].Descriptor != BIOS_PARTITION_TYPE_INSTALLABLE))
		{
			uli += 1;
		}
		if (uli >= BIOS_MAX_PARTITION_COUNT)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
#ifdef	_PHYSICAL_DRIVE
		ulStartSector = pPartitionTable->Entry[uli].LBAStartSector;
#else
		StringCchPrintfW(TargetDriveW,MAX_PATH,PARTITION,(uli + 1));
		//wsprintf(TargetDriveW,PARTITION,(uli + 1));
		ulStartSector = 0;
#endif
		//bRet = ReadSectors(TargetDriveW,pVbs,BIOS_DEFAULT_SECTOR_SIZE,ulStartSector,1);
		//if (FALSE == bRet)
		//{
		//	Status = STATUS_UNSUCCESSFUL;
		//	break;
		//}
		//pCheckVbr = (PVBR)pVbs;
		//if (memcmp(&pCheckVbr->VolumeOemId,NTFS_OEM_ID,sizeof(NTFS_OEM_ID)))
		//{
		//	Status = STATUS_UNSUCCESSFUL;
		//	break;
		//}
		do 
		{
			*pVbr = KernelMalloc(ulVbrSize);
		} while (NULL == *pVbr);
		RtlZeroMemory(*pVbr,ulVbrSize);
		bRet = ReadSectors(TargetDriveW,*pVbr,ulVbrSize,ulStartSector,ulVbrSize / BIOS_DEFAULT_SECTOR_SIZE);
		if (FALSE == bRet)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
	} while (0);
	if (pVbs)
	{
		KernelFree(pVbs);
	}
	if (NT_ERROR(Status))
	{
		if (*pVbr)
		{
			KernelFree(*pVbr);
		}
	}
	return Status;
}
BOOLEAN VbrCheck()
{
	BOOLEAN bRet;
	PCHAR pCheckVbrDat;
	
	bRet = FALSE;
	pCheckVbrDat = NULL;

	do 
	{
		if(NULL == g_pVbr)
		{
			ReadVbrFromSector(&g_pVbr,VBR_DEFAULT_SIZE);
		}
		if(NULL == g_pVbr)
		{
			break;
		}
		ReadVbrFromSector(&pCheckVbrDat,VBR_DEFAULT_SIZE);
		if(GetSumCheck(pCheckVbrDat,VBR_DEFAULT_SIZE) == \
			GetSumCheck(g_pVbr,VBR_DEFAULT_SIZE))
		{
			break;
		}
		bRet = TRUE;
	} while (0);
	if(pCheckVbrDat)
	{
		KernelFree(pCheckVbrDat);
	}
	return bRet;
}
//NTSTATUS ReadMbrFromSector(PCHAR *pMbr,ULONG ulVbrSize)
//{
//	NTSTATUS Status;
//	UNICODE_STRING UniFsDrive;
//
//	Status = STATUS_SUCCESS;
//
//	RtlInitUnicodeString(&UniFsDrive,PHYSICALDRIVE0);
//
//
//}