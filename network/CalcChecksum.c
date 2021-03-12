#include "myHeader.h"

typedef struct PSEUDO_HEADER {
	u_int ip_src_addr;
	u_int ip_dst_addr;
	u_char reserved;
	u_char protocol;
	u_short tcpLength;
}PSEUDO_HEADER, *PPSEUDO_HEADER;

u_short checksum_tcp(const struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr* tcp, const u_int len)
{
	PSEUDO_HEADER ph;
	u_short* pointer;
	u_int count;
	u_int sum = 0;
	tcp->th_sum = 0;
	ph.ip_src_addr = ip->ip_src.s_addr;
	ph.ip_dst_addr = ip->ip_dst.s_addr;
	ph.reserved = 0;
	ph.protocol = IPPRO_TCP;
	ph.tcpLength = htons(ntohs(ip->ip_len) - LIBNET_IPV4_H);
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

u_short checksum_ip(struct libnet_ipv4_hdr* ip)
{
	u_int sum = 0;
	u_short* ipHeaderPointer = (u_short*)ip;
	ip->ip_sum = 0;
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
