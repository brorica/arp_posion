#include "myHeader.h"

int swapEthernetSrcDstAddress(Pethernet_header eh);
int swapIpAddress(Pip_header ip);
int swapPort(u_short* src, u_short* dst);
int swapSeqAck(u_int* seq, u_int* ack);

int packet_handlerBackward(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len)
{
	Pethernet_header eh;
	Pip_header ip;
	Ptcp_header tcp;
	memcpy(sendPacket, packet, 54);
	eh = (Pethernet_header)sendPacket;
	ip = (Pip_header)(sendPacket + 14);
	tcp = (Ptcp_header)((char *)ip + 20);
	memcpy((char *)tcp + 20, msg, msg_len);
	/* swap */
	swapEthernetSrcDstAddress(eh);
	swapIpAddress(ip);
	swapPort(&tcp->src_port, &tcp->dst_port);
	swapSeqAck(&tcp->seq, &tcp->ack);
	/* set Header*/
	ip->ttl = 128; /* time to live */
	tcp->ack = htonl(ntohl(tcp->ack) + ntohs(ip->totalLen) - 20 - 20);
	ip->totalLen = htons(20 + 20 + msg_len);
	tcp->flags = 0x11;	// FIN | ACK;
	tcp->windowSize = 0;
	/* set checksum */
	ip->checksum = ipChecksum(ip);
	tcp->checksum = tcpChecksum(ip, tcp, 20 + msg_len);
	/* send packet */
	printf("backward end\n");
	return 1;
}

int swapEthernetSrcDstAddress(Pethernet_header eh)
{
	u_char temp[MACLEN];
	/* chagne MAC Addr */
	memcpy(temp, eh->dst_MAC, sizeof(u_char) * MACLEN);
	memcpy(eh->dst_MAC, eh->src_MAC, sizeof(u_char) * MACLEN);
	memcpy(eh->src_MAC, temp, sizeof(u_char) * MACLEN);
	return 0;
}

int swapIpAddress(Pip_header ip)
{
	u_char ipTemp[4];
	memcpy(ipTemp, ip->src_addr, sizeof(u_char) * 4);
	memcpy(ip->src_addr, ip->dst_addr, sizeof(u_char) * 4);
	memcpy(ip->dst_addr, ipTemp, sizeof(u_char) * 4);
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