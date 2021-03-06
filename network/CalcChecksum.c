#include "arpSpoofing.h"

typedef struct PSEUDO_HEADER {
	u_char ip_src_addr[4];
	u_char ip_dst_addr[4];
	u_char reserved;
	u_char protocol;
	u_short tcpLength;
}PSEUDO_HEADER, *PPSEUDO_HEADER;

u_short checksum_tcp(PIP_HEADER ih, PTCP_HEADER th, u_short totalTcpLen)
{
	PSEUDO_HEADER ph;
	u_short* pointer;
	u_int totalTcpLenHalf;
	u_int sum = 0;
	th->checksum = 0;
	memcpy(ph.ip_src_addr, ih->sourceIP, sizeof(u_int));
	memcpy(ph.ip_dst_addr, ih->destinationIP, sizeof(u_int));
	ph.reserved = 0;
	ph.protocol = IP_PROTOCOL_TCP;
	ph.tcpLength = htons(ntohs(ih->totalLen) - IP_HEADER_SIZE);
	/* sum tcp Header */
	totalTcpLenHalf = totalTcpLen >> 1;
	pointer = (u_short *)th;
	while (totalTcpLenHalf--)
		sum += *pointer++;
	if (totalTcpLen % 2)
		sum += *pointer;
	/* sum pseudo Header */
	pointer = (u_short *)&ph;
	for (int i = 0; i < 6; i++)
		sum += *pointer++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum & 0xffff;
}

u_short checksum_ip(PIP_HEADER ih)
{
	u_int sum = 0;
	u_short* ipHeaderPointer = (u_short*)ih;
	ih->checksum = 0;
	/* sum ip Header */
	for (int i = 0; i < 10; i++)
	{
		sum += *ipHeaderPointer;
		ipHeaderPointer++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum & 0xffff;
}
