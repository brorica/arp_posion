#include "myHeader.h"

#define ARPSIZE 28
#define ETHERNETSIZE 14

int searchARP(pcap_t* handle, PDeviceInfo victimDeviceInfo);

int getVictimMAC(pcap_t * handle, PDeviceInfo myDeviceInfo, PDeviceInfo victimDeviceInfo)
{
    u_char arpPacket[ARPSIZE + ETHERNETSIZE];
    arp_header arpHeader;
    ethernet_header ethernetHeader;
    /* set Etherenet Header */
    memset(&ethernetHeader.dst_MAC, 0xFF, sizeof(u_char) * MACLEN);
    memcpy(&ethernetHeader.src_MAC, &myDeviceInfo->macAddress, sizeof(u_char) * MACLEN);
    ethernetHeader.ether_Type = ntohs(0x0806);
    /* set ARP Header */
    arpHeader.Hardware_type = ntohs(0x0001);
    arpHeader.Protocol_type = ntohs(0x0800);
    arpHeader.Hardware_size = 0x06;
    arpHeader.Protocol_size = 0x04;
    arpHeader.Opcode = ntohs(0x0001);
    memcpy(&arpHeader.src_MAC, &myDeviceInfo->macAddress, sizeof(u_char) * MACLEN);
    memcpy(&arpHeader.src_IP, &myDeviceInfo->ipAddress, sizeof(IN_ADDR));
    memcpy(&arpHeader.dst_MAC, &victimDeviceInfo->macAddress, sizeof(u_char) * MACLEN);
    memcpy(&arpHeader.dst_IP, &victimDeviceInfo->ipAddress, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, &ethernetHeader, sizeof(char) * ETHERNETSIZE);
    memcpy(arpPacket + ETHERNETSIZE, &arpHeader, sizeof(char) * ARPSIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    searchARP(handle, victimDeviceInfo);
	return 0;
}

int searchARP(pcap_t* handle, PDeviceInfo victimDeviceInfo)
{
    int res;
    struct pcap_pkthdr* header;
    Parp_header arpHeader;
    Pethernet_header ethernetHeader;
    const u_char * packet;
    while ((res = pcap_next_ex(handle, &header, &packet)) > 0)
    {
        ethernetHeader = (Pethernet_header)packet;
        if (ntohs(ethernetHeader->ether_Type) == 0x0806)
        {
            arpHeader = (Parp_header)(packet + ETHERNETSIZE);
            if (ntohs(arpHeader->Opcode) == 0x0002)
            {
                memcpy(victimDeviceInfo->macAddress, arpHeader->src_MAC, sizeof(u_char) * MACLEN);
                /* Debug Code
                for (int i = 0; i < 6; i++)
                {
                    if (i == 5)
                        printf("%.2X\n", arpHeader->src_MAC[i]);
                    else
                        printf("%.2X-", arpHeader->src_MAC[i]);
                }
                */
                break;
            }
        }
    }
    return 0;
}