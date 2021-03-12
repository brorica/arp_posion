#include "myHeader.h"

int packet_handlerRedirect(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len)
{
	PIP_HEADER ip;
	PTCP_HEADER tcp;
	/* copy */
	memcpy(sendPacket, packet, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	ip = (PIP_HEADER)(sendPacket + LIBNET_ETH_H);
	tcp = (PTCP_HEADER)((char*)ip + LIBNET_IPV4_H);
	memcpy((char*)tcp + LIBNET_TCP_H, msg, msg_len);
	/* set header */
	ip->identifification += 1;
	tcp->seq = htonl(ntohl(tcp->seq) + ntohs(ip->totalLen) - LIBNET_IPV4_H - LIBNET_TCP_H); /* sequence number */
	ip->totalLen = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->flags = TH_FIN | TH_ACK;
	tcp->window = 0;
	/* set checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
	printf("redirection end\n");
	return 1;
}