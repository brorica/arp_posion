#include "myHeader.h"

int swapMAC(PETHERNET_HEADER eth, PLANINFO LanInfo);
int swapIP2(u_char* src, u_char* dst);
int swapPort(u_short* src, u_short* dst);
int swapSeqAck(u_int* seq, u_int* ack);

int packet_handlerForward(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len, PLANINFO LanInfo)
{
	PETHERNET_HEADER eth;
	PIP_HEADER ip;
	PTCP_HEADER tcp;
	/* copy */
	memcpy(sendPacket, packet, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	eth = (PETHERNET_HEADER)sendPacket;
	ip = (PIP_HEADER)(sendPacket + LIBNET_ETH_H);
	tcp = (PTCP_HEADER)((char*)ip + LIBNET_IPV4_H);
	memcpy((char*)tcp + LIBNET_TCP_H, msg, msg_len);
	/* swap */
	swapMAC(eth, LanInfo);
	swapIP2(ip->sourceIP, ip->destinationIP);
	swapPort(&tcp->sourcePort, &tcp->destinationPort);
	swapSeqAck(&tcp->seq, &tcp->ack);
	/* set header */
	ip->ttl = 128;
	tcp->ack = htonl(ntohl(tcp->ack) + ntohs(ip->totalLen) - LIBNET_IPV4_H - LIBNET_TCP_H); /* acknowlegment number */
	ip->totalLen = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->flags = TH_FIN | TH_ACK;
	tcp->window = 0;
	/* set checksum */
	ip->checksum = checksum_ip(ip);
	tcp->checksum = checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
	printf("backward end\n");
	return 1;
}
int swapMAC(PETHERNET_HEADER eth, PLANINFO LanInfo)
{
	/* chagne MAC Addr */
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