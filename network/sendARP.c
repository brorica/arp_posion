#include "myHeader.h"

#define ARPSIZE 42

int sendARP(pcap_t * handle, char * gateWayAddress)
{
    u_char arpPacket[ARPSIZE];

    /* Fill the rest of the packet */
    for (int i = 12; i < 42; i++)
    {
        arpPacket[i] = (u_char)i;
    }

    /* Send down the packet */
    for (int i = 0; i < 42; i++)
    {
        if (pcap_sendpacket(handle, arpPacket, 42 /* size */) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
            return 0;
        }
    }
	return 0;
}