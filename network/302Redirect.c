#include "myHeader.h"

int packet_handlerRedirect(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len)
{
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	/* copy */
	memcpy(sendPacket, packet, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	ip = (struct libnet_ipv4_hdr*)(sendPacket + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr*)((char*)ip + LIBNET_IPV4_H);
	memcpy((char*)tcp + LIBNET_TCP_H, msg, msg_len);
	/* set header */
	ip->ip_id += 1;
	tcp->th_seq = htonl(ntohl(tcp->th_seq) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H); /* sequence number */
	ip->ip_len = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win = 0;
	/* set checksum */
	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
	printf("redirection end\n");
	return 1;
}