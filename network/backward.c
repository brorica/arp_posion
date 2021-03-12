#include "myHeader.h"

inline int swapMAC(struct libnet_ethernet_hdr* eth, PLANINFO LanInfo);
inline int swapIP(u_long* src, u_long* dst);
inline int swapPort(u_short* src, u_short* dst);
inline int swapSeqAck(u_int* seq, u_int* ack);

int packet_handlerBackward(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len, PLANINFO LanInfo)
{
	struct libnet_ethernet_hdr* eth;
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	/* copy */
	memcpy(sendPacket, packet, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	eth = (struct libnet_ethernet_hdr*)sendPacket;
	ip = (struct libnet_ipv4_hdr*)(sendPacket + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr*)((char*)ip + LIBNET_IPV4_H);
	memcpy((char*)tcp + LIBNET_TCP_H, msg, msg_len);
	/* swap */
	swapMAC(eth, LanInfo);
	swapIP(&ip->ip_src.s_addr, &ip->ip_dst.s_addr);
	swapPort(&tcp->th_sport, &tcp->th_dport);
	swapSeqAck(&tcp->th_seq, &tcp->th_ack);
	/* set */
	ip->ip_ttl = 128;
	tcp->th_ack = htonl(ntohl(tcp->th_ack) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H); /* acknowlegment number */
	ip->ip_len = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win = 0;
	/* checksum */
	ip->ip_sum = checksum_ip(ip);
	tcp->th_sum = checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
	printf("backward end\n");
	return 1;
}

int swapMAC(struct libnet_ethernet_hdr* eth, PLANINFO LanInfo)
{
	/* chagne MAC Addr */
	memcpy(eth->ether_shost, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(eth->ether_dhost, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	return 0;
}

int swapIP(u_long* src, u_long* dst)
{
	u_long temp = *src;
	*src = *dst;
	*dst = temp;
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