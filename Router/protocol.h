#pragma once
#define BYTE unsigned char
#define WORD unsigned short
#define DWORD unsigned long
#pragma pack(1)

typedef struct {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
} FrameHeader_t;	//以太帧

typedef struct {
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
} ARPFrame_t;		//ARP协议

typedef struct
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD FLAG_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	DWORD SrcIP;
	DWORD DstIP;
}IPHeader_t;		//IP数据报首部

typedef struct
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} IPFrame_t;		

typedef struct
{
	BYTE Type;		//类型
	BYTE Code;		//代码
	WORD CheckSum;	//校验和
	WORD Id;
	WORD Sequence;
} ICMPHeader_t;		//ICMP协议首部

#pragma pack()