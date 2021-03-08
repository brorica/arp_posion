#include "myHeader.h"

typedef struct PSEUDO_HEADER {
	u_char ip_src_addr[4];
	u_char ip_dst_addr[4];
	u_char reserved;
	u_char protocol;
	u_short tcpLength;
}PSEUDO_HEADER, *PPSEUDO_HEADER;

int tcpChecksum(Pip_header ipHeader, Ptcp_header tcpHeader, struct pcap_pkthdr* header, const u_char* packet, u_int redirectSiteLen)
{
	u_int sum = 0, tcpHeaderSzie;
	PSEUDO_HEADER pseudo_header;
	u_short* pseudoHeaderPointer = (u_short *)(&pseudo_header);
	u_short* tcpHeaderPointer = (u_short*)(tcpHeader);
	u_short* tcpBodyPointer;
	/* port change */
	u_short portTemp;
	portTemp = tcpHeader->src_port;
	tcpHeader->src_port = tcpHeader->dst_port;
	tcpHeader->dst_port = portTemp;
	/* seq, ack change */
	u_int shakeTemp = tcpHeader->acknowledgementNumber;
	tcpHeader->acknowledgementNumber = ntohl(tcpHeader->sequenceNumber) + (header->len - 54);
	tcpHeader->acknowledgementNumber = htonl(tcpHeader->sequenceNumber);
	tcpHeader->sequenceNumber = shakeTemp;
	/* set Flag and Calc Checksum */
	tcpHeaderSzie = sizeof(TCPHEADER);
	tcpHeader->checksum = 0;
	tcpHeader->sequenceNumber = htonl(tcpHeader->sequenceNumber) + (header->len - tcpHeaderSzie);
	tcpHeader->sequenceNumber = ntohl(tcpHeader->sequenceNumber);
	tcpHeader->flags = 0x11;
	memcpy(&pseudo_header.ip_src_addr, ipHeader->src_addr, sizeof(u_char) * 4);
	memcpy(&pseudo_header.ip_dst_addr, ipHeader->dst_addr, sizeof(u_char) * 4);
	pseudo_header.reserved = 0;
	pseudo_header.protocol = ipHeader->protocol;
	pseudo_header.tcpLength = (u_short)sizeof(tcp_header) + (u_short)redirectSiteLen;

	for (int i = 0; i < 6; i++)
	{
		sum += ntohs(*pseudoHeaderPointer);
		pseudoHeaderPointer++;
	}
	/* check data field */
	if (header->len > tcpHeaderSzie)
	{
		int dataLen = header->len - tcpHeaderSzie;
		tcpBodyPointer = (u_short*)(packet + tcpHeaderSzie);
		for (int i = 0; i < dataLen; i+=2)
		{
			sum += ntohs(*tcpBodyPointer);
			tcpBodyPointer++;
		}
	}
	for (int i = 0; i < 10; i++)
	{
		sum += ntohs(*tcpHeaderPointer);
		pseudoHeaderPointer++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

int ipChecksum(Pip_header ipHeader, u_int redirectSiteLen)
{
	u_int sum = 0;
	u_short* ipHeaderPointer = (u_short*)ipHeader;
	/* IPHEADER + TCPHEADER = 40 */
	ipHeader->totalLen = 40 + redirectSiteLen;
	/* common ip header length 20Byes */
	for (int i = 0; i < 10; i++)
	{
		sum += ntohs(*ipHeaderPointer);
		ipHeaderPointer++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}
