#include "myHeader.h"

typedef struct PSEUDO_HEADER {
	u_char ip_src_addr[4];
	u_char ip_dst_addr[4];
	u_char reserved;
	u_char protocol;
	u_short tcpLength;
}PSEUDO_HEADER, *PPSEUDO_HEADER;

u_short checksum_tcp(PIP_HEADER ip, PTCP_HEADER tcp, const u_int len)
{
	PSEUDO_HEADER ph;
	u_short* pointer;
	u_int count;
	u_int sum = 0;
	tcp->checksum = 0;
	memcpy(ph.ip_src_addr, ip->sourceIP, sizeof(u_int));
	memcpy(ph.ip_dst_addr, ip->destinationIP, sizeof(u_int));
	ph.reserved = 0;
	ph.protocol = IPPRO_TCP;
	ph.tcpLength = htons(ntohs(ip->totalLen) - LIBNET_IPV4_H);
	/* sum tcp Header */
	count = len >> 1;
	pointer = (u_short *)tcp;
	while (count--)
		sum += *pointer++;
	if (len % 2)
		sum += *pointer;
	/* sum pseudo Header */
	pointer = (u_short *)&ph;
	for (int i = 0; i < 6; i++)
		sum += *pointer++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return ~sum & 0xffff;
}

u_short checksum_ip(PIP_HEADER ip)
{
	u_int sum = 0;
	u_short* ipHeaderPointer = (u_short*)ip;
	ip->checksum = 0;
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
