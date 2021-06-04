#include "arpSpoofing.h"
#include <string.h>
int packetForward(u_char* sendPacket, const u_char* packet)
{
	PIP_HEADER ih;
	PTCP_HEADER th;
	const char msgForward[8] = "blocked";
	u_short msgForwardLen = (u_short)strlen(msgForward);
	/* copy */
	memcpy(sendPacket, packet, TCP_PACKET_SIZE);
	ih = (PIP_HEADER)(sendPacket + ETHERNET_HEADER_SIZE);
	th = (PTCP_HEADER)((char*)ih + IP_HEADER_SIZE);
	memcpy((char*)th + TCP_HEADER_SIZE, msgForward, msgForwardLen);
	/* set header */
	ih->identifification += 1;
	th->seq = htonl(ntohl(th->seq) + ntohs(ih->totalLen) - IP_HEADER_SIZE - TCP_HEADER_SIZE);
	ih->totalLen = htons(IP_HEADER_SIZE + TCP_HEADER_SIZE + msgForwardLen);
	th->flags = TH_FIN | TH_ACK;
	th->window = 0;
	/* set checksum */
	checksum_ip(ih);
	checksum_tcp(ih, th, TCP_HEADER_SIZE + msgForwardLen);
	printf("redirection end\n");
	return msgForwardLen + TCP_PACKET_SIZE;
}