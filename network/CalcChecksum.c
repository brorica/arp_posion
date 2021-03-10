#include "myHeader.h"

typedef struct PSEUDO_HEADER {
	u_char ip_src_addr[4];
	u_char ip_dst_addr[4];
	u_char reserved;
	u_char protocol;
	u_short tcpLength;
}PSEUDO_HEADER, *PPSEUDO_HEADER;

u_short tcpChecksum(Pip_header ipHeader, Ptcp_header tcpHeader, u_short len)
{
	u_int sum = 0;
	PSEUDO_HEADER pseudo_header;
	u_short* pseudoHeaderPointer = (u_short *)(&pseudo_header);
	u_short* tcpHeaderPointer = (u_short*)(tcpHeader);
	/* set pseudo Header */
	memcpy(&pseudo_header.ip_src_addr, ipHeader->src_addr, sizeof(u_char) * 4);
	memcpy(&pseudo_header.ip_dst_addr, ipHeader->dst_addr, sizeof(u_char) * 4);
	pseudo_header.reserved = 0;
	pseudo_header.protocol = ipHeader->protocol;
	pseudo_header.tcpLength = htons(ntohs(ipHeader->totalLen) - 20);
	/* sum pseudo Header */
	for (int i = 0; i < 6; i++)
	{
		sum += *pseudoHeaderPointer;
		pseudoHeaderPointer++;
	}
	u_int count = len >> 1;
	while (count--)
	{
		sum += *tcpHeaderPointer;
		tcpHeaderPointer++;
	}
	if (len % 2)
		sum += *tcpHeaderPointer;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum & 0xffff;
}

u_short ipChecksum(Pip_header ipHeader)
{
	u_int sum = 0;
	u_short* ipHeaderPointer = (u_short*)ipHeader;
	ipHeader->checksum = 0;
	/* common ip header length 20Byes */
	for (int i = 0; i < 10; i++)
	{
		sum += *ipHeaderPointer;
		ipHeaderPointer++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum & 0xffff;
}
