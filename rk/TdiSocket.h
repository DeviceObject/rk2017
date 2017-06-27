#ifndef __TDI_SOCKET_H__
#define __TDI_SOCKET_H__

typedef struct _DataInformation
{
	char szVersion[10];
	char szServicePath[256];
	char szClientPath[256];
	DWORD dwFileSize;
	DWORD dwType;
	int nRun;
}DataInformation,*PDataInformation;
typedef struct _PROTECTFILEINFORMATION
{
	HANDLE hFile;
}PROTECTFILEINFORMATION,PPROTECTFILEINFORMATION;
typedef struct _ClientInformation
{
	char szFilePath[150];
}ClientInformation,*PClientInformation;
#define AF_INET							2

#define SOCK_STREAM						1 //TCP
#define SOCK_DGRAM						2 //UDP
#define SOCK_RAW						3 //RAW  是winsock.h中定义的

#define IPPROTO_ICMP					1
#define IPPROTO_TCP						6
#define IPPROTO_UDP						17


#define TDI_MAX_SOCKET					256
#define TDI_MAX_BACKLOG					20

#define TDI_TCP_DEVICE_NAME_W			L"\\Device\\Tcp"
#define TDI_UDP_DEVICE_NAME_W			L"\\Device\\Udp"
#define TDI_RAW_DEVICE_NAME_W			L"\\Device\\RawIp"

#define TDI_TIMEOUT_CONNECT_SEC			60
#define TDI_TIMEOUT_DISCONNECT_SEC		60
#define TDI_TIMEOUT_COMMUNICATION		60


#define SOCKET_STATUS_CLEAR				0
#define SOCKET_STATUS_ALLOCATED			1
#define SOCKET_STATUS_TRANSPORT			2
#define SOCKET_STATUS_CONNECTION		3
#define SOCKET_STATUS_CON_AND_TRANS		4
#define SOCKET_STATUS_ASSOCIATED		5
#define SOCKET_STATUS_LISTEN			6
#define SOCKET_STATUS_WAITING_INBOUND	7 
#define SOCKET_STATUS_DISCONNECTED		8
#define SOCKET_STATUS_CONNECTED			9
#define SOCKET_STATUS_CHANGING			10


#define WSA_NOT_ENOUGH_MEMORY			8
#define WSAEMFILE						10024 
#define WSAEPROTOTYPE					10041 
#define WSAEPROTONOSUPPORT				10043 
#define WSAESHUTDOWN					10058
#define WSANO_DATA						11004

#define MAXIMUM_RECV_BUFFER				0x1000

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;


#define s_addr S_un.S_addr

typedef struct _in_addr
{
	union
	{
		struct
		{
			u_char s_b1,s_b2, s_b3, s_b4;
		} S_un_b;
		struct
		{
			u_short s_w1, s_w2;
		} S_un_w;
		u_long S_addr;
	} S_un;
}in_addr,*pin_addr;

typedef struct _sockaddr_in
{
	short sin_family;
	unsigned short sin_port;
	in_addr sin_addr;
	char sin_zero[8];
}sockaddr_in,*psockaddr_in;

#define h_addr h_addr_list[0]

typedef struct _STREAM_SOCKET
{
	HANDLE connectionHandle;
	PFILE_OBJECT connectionFileObject;
	KEVENT disconnectEvent;
} STREAM_SOCKET,*PSTREAM_SOCKET;

typedef struct _SOCKET
{
	int type;
	BOOLEAN isBound;
	BOOLEAN isConnected;
	BOOLEAN isListening;
	BOOLEAN isShuttingdown;
	BOOLEAN isShared;
	HANDLE addressHandle;
	PFILE_OBJECT addressFileObject;
	PSTREAM_SOCKET streamSocket;
	sockaddr_in peer;
} SOCKET,*PSOCKET;
//Constant sized fields of the resource record structure
#pragma pack(push)
#pragma pack(1)
typedef struct _R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
}R_DATA,*PR_DATA;
#pragma pack(pop)

//Pointers to resource record contents
typedef struct _RES_RECORD
{
	unsigned char  *name;
	PR_DATA  resource;
	unsigned char  *rdata;
}RES_RECORD,*PRES_RECORD;

typedef struct _HOSTENT
{ 
	char * h_name; 
	char ** h_aliases; 
	short h_addrtype; 
	short h_length; 
	unsigned int ** h_addr_list;
} HOSTENT,*PHOSTENT;

typedef struct _DNSADDRANDURL
{
	int serveur_dns;
	int urladdr;
} DNSADDRANDURL,*PDNSADDRANDURL;

typedef struct _DNS_HEADER
{ 
	unsigned short id;       // identification number 
	unsigned char rd :1;     // recursion desired 
	unsigned char tc :1;     // truncated message 
	unsigned char aa :1;     // authoritive answer 
	unsigned char opcode :4; // purpose of message 
	unsigned char qr :1;     // query/response flag 
	unsigned char rcode :4; // response code 
	unsigned char cd :1;     // checking disabled 
	unsigned char ad :1;     // authenticated data 
	unsigned char z :1;      // its z! reserved 
	unsigned char ra :1;     // recursion available 
	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries 
	unsigned short auth_count; // number of authority entries 
	unsigned short add_count; // number of resource entries
} DNS_HEADER,*PDNS_HEADER;

//DNS Question
typedef struct _QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
} QUESTION,*PQUESTION;


typedef struct _CUSTOM_RES_RECORD
{
	unsigned short name;
	unsigned short type;
	unsigned short _class;
	unsigned short ttl_hi;
	unsigned short ttl_low;
	unsigned short data_len;
	unsigned char rdata[1];
}CUSTOM_RES_RECORD,*PCUSTOM_RES_RECORD;



#define INADDR_NONE 0xffffffff

#define htonl(l)                                \
	( ( ((l) >> 24) & 0x000000FFL ) |       \
	( ((l) >>  8) & 0x0000FF00L ) |       \
	( ((l) <<  8) & 0x00FF0000L ) |       \
	( ((l) << 24) & 0xFF000000L ) )

#define ntohs(s)                            \
	( ( ((s) >> 8) & 0x00FF ) |             \
	( ((s) << 8) & 0xFF00 ) )

#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define NTOHS(s) ((((s)>> 8) & 0x00FF)|(((s)<<8)&0xFF00))




BOOLEAN QueryDnsAddress(PUCHAR pHostNameA,ULONG *ulAddress);
char* myinet_ntoa(in_addr InAddr);
unsigned long myinet_addr(const char *cp);
int ReadDnsServerFromRegistry();
int ReadHostIPsFromRegistry();
PHOSTENT gethostbyname (char *name);
int disaquery_dns(sockaddr_in sockaddr_dns,
				  char* nom_a_resoudre,
				  char *hostent_buf,
				  int rdns);
int build_dns_query (char* URL,int* taille_buffer_dns,int rdns);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);
void ChangefromDnsNameFormat(unsigned char* name);
int __cdecl bind(int socket, sockaddr_in *addr, int addrlen);
NTSTATUS tdi_open_transport_address(PUNICODE_STRING devName, 
										   ULONG addr, 
										   USHORT port, 
										   int shared, 
										   PHANDLE addressHandle, 
										   PFILE_OBJECT *addressFileObject);
NTSTATUS tdi_set_event_handler(PFILE_OBJECT addressFileObject, 
									  LONG eventType, 
									  PVOID eventHandler, 
									  PVOID eventContext);
int __cdecl mysendto(int socket, char *buf, int len, int flags, sockaddr_in *addr, int addrlen);
int __cdecl send(int socket, const char *buf, int len, int flags);
NTSTATUS tdi_send_dgram(PFILE_OBJECT addressFileObject, 
							   ULONG addr, 
							   USHORT port, 
							   const char *buf, 
							   int len);
int __cdecl socket(int af, int type, int protocol);
NTSTATUS tdi_disconnect(PFILE_OBJECT connectionFileObject, ULONG flags);
NTSTATUS tdi_disassociate_address(PFILE_OBJECT connectionFileObject);
int __cdecl close(int socket);
int __cdecl recvfrom(int socket, char *buf, int len, int flags, sockaddr_in *addr, int *addrlen);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
NTSTATUS tdi_recv_dgram(PFILE_OBJECT addressFileObject, PULONG addr, PUSHORT port, char *buf, int len, ULONG flags);
NTSTATUS event_disconnect(PVOID TdiEventContext, \
						  PVOID ConnectionContext, \
						  LONG DisconnectDataLength, \
						  PVOID DisconnectData, \
						  LONG DisconnectInformationLength, \
						  PVOID DisconnectInformation, \
						  ULONG DisconnectFlags);
int __cdecl recv(int socket, char *buf, int len, int flags);
NTSTATUS tdi_recv_stream(PFILE_OBJECT connectionFileObject, char *buf, int len, ULONG flags);
NTSTATUS tdi_set_event_handler(PFILE_OBJECT addressFileObject, LONG eventType, PVOID eventHandler, PVOID eventContext);
NTSTATUS tdi_send_dgram(PFILE_OBJECT addressFileObject, ULONG addr, USHORT port, const char *buf, int len);
NTSTATUS tdi_send_stream(PFILE_OBJECT connectionFileObject, const char *buf, int len, ULONG flags);
NTSTATUS tdi_open_transport_address(PUNICODE_STRING devName, ULONG addr, USHORT port, int shared, PHANDLE addressHandle, PFILE_OBJECT *addressFileObject);

NTSTATUS DisConnect(PFILE_OBJECT pFileObject);
NTSTATUS Connect(PFILE_OBJECT pFileObject,ULONG ulAddr,USHORT uPort);
NTSTATUS Bind(PFILE_OBJECT pFileObject,HANDLE Address);
NTSTATUS CreateConnection(PHANDLE pHandle,PFILE_OBJECT *pFileObject);
NTSTATUS CreateAddress(PHANDLE pHandle,PFILE_OBJECT *ppFileObject);
BOOLEAN NetWorkIsOk(ULONG ulRemoteAddress,USHORT uRemotePort);
BOOLEAN GetCommandFromUrl(PUCHAR pUrlAddr,USHORT uPort);
NTSTATUS RecvCommandPacket(ULONG ulRemoteAddress,USHORT uRemotePort);
NTSTATUS GetFileData(PUNICODE_STRING pUnFileName,ULONG ulSize,PCHAR *pFileData);
BOOLEAN DownloadFileFromUrl(PCHAR pUrl,USHORT uPort,PCHAR pUri);

#endif