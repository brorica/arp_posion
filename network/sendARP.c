#include "myHeader.h"

#define ARPSIZE 42

int sendARP(pcap_t * handle, char * gateWayAddress)
{
	u_char arpPacket[ARPSIZE];
	arpPacket[0] = 1;
	for (int i = 0; i < 100; i++)
	{
		if (pcap_sendpacket(handle, ARPSIZE, 42 /* size */) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
			return 0;
		}
	}
	return 0;
}