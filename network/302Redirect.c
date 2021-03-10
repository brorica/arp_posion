#include "myHeader.h"

int packet_handlerRedirect(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len)
{
	Pip_header ih;
	Ptcp_header tcp;
	memcpy(sendPacket, packet, 54);
	ih = (Pip_header)(sendPacket + 14);
	tcp = (Ptcp_header)((char *)ih + 20);
	memcpy((char*)tcp + 20, msg, msg_len);
	/* set header */
	ih->identification += 1;
	tcp->seq = ntohl(tcp->seq) + ntohs(ih->totalLen) - 20 - 20;
	tcp->seq = htonl(tcp->seq);
	ih->totalLen = (20 + 20 + msg_len) << 8; // htons(20 + 20 + msg_len)
	tcp->windowSize = 0;
	tcp->flags = 0x11;
	tcp->windowSize = 0;
	/* set checksum */
	ih->checksum = ipChecksum(ih);
	tcp->checksum = tcpChecksum(ih, tcp, 20 + msg_len);
	printf("redirection end\n");
	return 1;
}