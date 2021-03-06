#include "myHeader.h"

u_char arpPacket[ARPSIZE + ETHERNETSIZE];
int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, Pethernet_header ethernetHeader, Parp_header arpHeader);
int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, Pethernet_header ethernetHeader, Parp_header arpHeader);

int getMACAddress(pcap_t * handle, PLANINFO LanInfo)
{
    arp_header arpHeader;
    ethernet_header ethernetHeader;
    /* set Etherenet Header */
    memset(&ethernetHeader.dst_MAC, 0xFF, sizeof(u_char) * MACLEN);
    memcpy(&ethernetHeader.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    ethernetHeader.ether_Type = ntohs(0x0806);
    /* set ARP Header */
    arpHeader.Hardware_type = ntohs(0x0001);
    arpHeader.Protocol_type = ntohs(0x0800);
    arpHeader.Hardware_size = 0x06;
    arpHeader.Protocol_size = 0x04;
    arpHeader.Opcode = ntohs(0x0001);
    getVictimMAC(handle, LanInfo, &ethernetHeader, &arpHeader);
    Sleep(2000);
    getGatewayMAC(handle, LanInfo, &ethernetHeader, &arpHeader);
	return 0;
}

int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, Pethernet_header ethernetHeader, Parp_header arpHeader)
{
    int res, check;
    Pethernet_header replyEthernetHeader;
    Parp_header replyARPHeader;
    struct pcap_pkthdr* header;
    const u_char * packet;
    /* set header */
    memcpy(arpHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(arpHeader->src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(arpHeader->dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
    memcpy(arpHeader->dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, ethernetHeader, sizeof(char) * ETHERNETSIZE);
    memcpy(arpPacket + ETHERNETSIZE, arpHeader, sizeof(char) * ARPSIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        replyEthernetHeader = (Pethernet_header)packet;
        if (ntohs(replyEthernetHeader->ether_Type) == 0x0806)
        {
            replyARPHeader = (Parp_header)(packet + ETHERNETSIZE);
            if (ntohs(replyARPHeader->Opcode) == 0x0002)
            {
                check = 1;
                for (int i = 0; i < 6; i++)
                {
                    if (replyEthernetHeader->dst_MAC[i] != LanInfo->myMAC[i])
                    {
                        check = 0;
                        break;
                    }
                }
                if (check)
                {
                    memcpy(LanInfo->victimMAC, replyEthernetHeader->src_MAC, sizeof(u_char) * MACLEN);
                    break;
                }
            }
        }
    }
    return 0;
}

int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, Pethernet_header ethernetHeader, Parp_header arpHeader)
{
    int res, check;
    Pethernet_header replyEthernetHeader;
    Parp_header replyARPHeader;
    struct pcap_pkthdr* header;
    const u_char* packet;
    /* set header */
    memcpy(arpHeader->src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(arpHeader->src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(arpHeader->dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
    memcpy(arpHeader->dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, ethernetHeader, sizeof(char) * ETHERNETSIZE);
    memcpy(arpPacket + ETHERNETSIZE, arpHeader, sizeof(char) * ARPSIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) > 0)
    {
        replyEthernetHeader = (Pethernet_header)packet;
        if (ntohs(replyEthernetHeader->ether_Type) == 0x0806)
        {
            replyARPHeader = (Parp_header)(packet + ETHERNETSIZE);
            if (ntohs(replyARPHeader->Opcode) == 0x0002)
            {
                check = 1;
                for (int i = 0; i < 6; i++)
                {
                    if (replyEthernetHeader->dst_MAC[i] != LanInfo->myMAC[i])
                    {
                        check = 0;
                        break;
                    }
                }
                if (check)
                {
                    memcpy(LanInfo->gatewayMAC, replyEthernetHeader->src_MAC, sizeof(u_char) * MACLEN);
                    break;
                }
            }
        }
    }
    return 0;
}