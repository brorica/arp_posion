#include "myHeader.h"

int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, PARPHEADER setHeader);
int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, PARPHEADER setHeader);

int getMACAddress(pcap_t * handle, PLANINFO LanInfo)
{
    ARPHEADER setHeader;
    /* set Etherenet Header */
    memset(&(setHeader.ethernet.dst_MAC), 0xFF, sizeof(u_char) * MACLEN);
    memcpy(&(setHeader.ethernet.src_MAC), LanInfo->myMAC, sizeof(u_char) * MACLEN);
    setHeader.ethernet.ether_Type = ntohs(0x0806);
    /* set ARP Header */
    setHeader.arp.Hardware_type = ntohs(0x0001);
    setHeader.arp.Protocol_type = ntohs(0x0800);
    setHeader.arp.Hardware_size = 0x06;
    setHeader.arp.Protocol_size = 0x04;
    setHeader.arp.Opcode = ntohs(0x0001);
    getVictimMAC(handle, LanInfo, &setHeader);
    Sleep(2000);
    getGatewayMAC(handle, LanInfo, &setHeader);
	return 0;
}

int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, PARPHEADER setHeader)
{
    int res, check;
    PARPHEADER replyHeader;
    u_char arpPacket[ARPSIZE + ETHERNETSIZE];
    struct pcap_pkthdr* header;
    const u_char * packet;
    /* set header */
    memcpy(setHeader->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(setHeader->arp.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, &(setHeader->ethernet), sizeof(char) * ETHERNETSIZE);
    memcpy(arpPacket + ETHERNETSIZE, &(setHeader->arp), sizeof(char) * ARPSIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        replyHeader = (PARPHEADER)packet;
        if (ntohs(replyHeader->ethernet.ether_Type) == 0x0806)
        {
            if (ntohs(replyHeader->arp.Opcode) == 0x0002)
            {
                check = memcmp(replyHeader->arp.dst_MAC, LanInfo->myMAC,sizeof(u_char) * MACLEN);
                if (!check)
                {
                    memcpy(LanInfo->victimMAC, replyHeader->arp.src_MAC, sizeof(u_char) * MACLEN);
                    break;
                }
            }
        }
    }
    return 0;
}

int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, PARPHEADER setHeader)
{
    int res, check;
    PARPHEADER replyHeader;
    u_char arpPacket[ARPSIZE + ETHERNETSIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    /* set header */
    memcpy(setHeader->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(setHeader->arp.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, &(setHeader->ethernet), sizeof(char) * ETHERNETSIZE);
    memcpy(arpPacket + ETHERNETSIZE, &(setHeader->arp), sizeof(char) * ARPSIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARPSIZE + ETHERNETSIZE /* size */) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) > 0)
    {
        replyHeader = (PARPHEADER)packet;
        if (ntohs(replyHeader->ethernet.ether_Type) == 0x0806)
        {
            if (ntohs(replyHeader->arp.Opcode) == 0x0002)
            {
                check = memcmp(replyHeader->arp.dst_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
                if (!check)
                {
                    memcpy(LanInfo->gatewayMAC, replyHeader->arp.src_MAC, sizeof(u_char) * MACLEN);
                    break;
                }
            }
        }
    }
    return 0;
}