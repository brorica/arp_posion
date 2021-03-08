#include "myHeader.h"

int setArpHeader(PARPHEADER header)
{
	header->ethernet.ether_Type = ntohs(0x0806);
	header->arp.Hardware_type = ntohs(0x0001);
	header->arp.Protocol_type = ntohs(0x0800);
	header->arp.Hardware_size = 0x06;
	header->arp.Protocol_size = 0x04;
	header->arp.Opcode = ntohs(0x0002); // reply
	return 0;
}
