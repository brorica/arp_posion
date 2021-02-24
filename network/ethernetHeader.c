#include "myHeader.h"

int printMAC(u_char *MAC)
{
	for (int i = 0; i <= 5; i++)
	{
		printf("%02x ", MAC[i]);
	}
	printf("\n");
	return 0;
}

int ethernetHeader(const u_char *packet)
{
	ethernet_header *eh;
	u_short ether_type;
	eh = (struct ethernet_header *)packet;
	ether_type = ntohs(eh->ether_Type);
	/* check arp Packet arp : 0x0806 */
	if (ether_type != 0x0806)
		return 2;
	
	printf("\n=========PACKET DETAIL=============\n");
	printf("\nDst MAC Addr : ");
	printMAC(eh->dst_MAC);
	printf("Src MAC Addr : ");
	printMAC(eh->src_MAC);
	printf("ether_type : 0x%04x\n\n", ether_type);
	ipHeader(packet + 14);
	tcpHeader(packet + 34);
	printf("=========PACKET DETAIL End========\n");
	return 0;
}