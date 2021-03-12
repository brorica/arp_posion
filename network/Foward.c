#include "myHeader.h"
#include <string.h>
int packetForward(u_char* sendPacket, const u_char* packet)
{
	PIP_HEADER ip;
	PTCP_HEADER tcp;
	const char msgForward[8] = "blocked";
	u_short msgForwardLen = (u_short)strlen(msgForward);
	/* copy */
	memcpy(sendPacket, packet, TCP_PACKET_SIZE);
	ip = (PIP_HEADER)(sendPacket + ETHERNET_HEADER_SIZE);
	tcp = (PTCP_HEADER)((char*)ip + IP_HEADER_SIZE);
	memcpy((char*)tcp + TCP_HEADER_SIZE, msgForward, msgForwardLen);
	/* set header */
	ip->identifification += 1;
	tcp->seq = htonl(ntohl(tcp->seq) + ntohs(ip->totalLen) - IP_HEADER_SIZE - TCP_HEADER_SIZE);
	ip->totalLen = htons(IP_HEADER_SIZE + TCP_HEADER_SIZE + msgForwardLen);
	tcp->flags = TH_FIN | TH_ACK;
	tcp->window = 0;
	/* set checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, TCP_HEADER_SIZE + msgForwardLen);
	printf("redirection end\n");
	return msgForwardLen + TCP_PACKET_SIZE;
}