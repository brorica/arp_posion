#include "myHeader.h"

int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, PARP_PACKET setHeader);
int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, PARP_PACKET setHeader);

int getMACAddress(pcap_t * handle, PLANINFO LanInfo)
{
    ARP_PACKET setHeader;
    /* set Etherenet Header */
    memset(&(setHeader.ethernet.dst_MAC), 0xFF, sizeof(u_char) * MACLEN);
    memcpy(&(setHeader.ethernet.src_MAC), LanInfo->myMAC, sizeof(u_char) * MACLEN);
    setHeader.ethernet.ether_Type = ntohs(ARP);
    /* set ARP Header */
    setHeader.arp.Hardware_type = ntohs(0x0001);
    setHeader.arp.Protocol_type = ntohs(0x0800);
    setHeader.arp.Hardware_size = 0x06;
    setHeader.arp.Protocol_size = 0x04;
    setHeader.arp.Opcode = ntohs(REQUEST);
    getVictimMAC(handle, LanInfo, &setHeader);
    Sleep(1000);
    getGatewayMAC(handle, LanInfo, &setHeader);
	return 0;
}

int getVictimMAC(pcap_t* handle, PLANINFO LanInfo, PARP_PACKET setHeader)
{
    int res, check;
    PARP_PACKET replyHeader;
    u_char arpPacket[ARP_PACKET_SIZE];
    struct pcap_pkthdr* header;
    const u_char * packet;
    /* set header */
    memcpy(setHeader->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(setHeader->arp.dst_MAC, LanInfo->victimMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.dst_IP, &LanInfo->victimIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, &(setHeader->ethernet), sizeof(char) * ETHERNET_SIZE);
    memcpy(arpPacket + ETHERNET_SIZE, &(setHeader->arp), sizeof(char) * ARP_SIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARP_SIZE + ETHERNET_SIZE) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        replyHeader = (PARP_PACKET)packet;
        if (ntohs(replyHeader->ethernet.ether_Type) == ARP)
        {
            if (ntohs(replyHeader->arp.Opcode) == REPLY)
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

int getGatewayMAC(pcap_t* handle, PLANINFO LanInfo, PARP_PACKET setHeader)
{
    int res, check;
    PARP_PACKET replyHeader;
    u_char arpPacket[ARP_PACKET_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    /* set header */
    memcpy(setHeader->arp.src_MAC, LanInfo->myMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.src_IP, &LanInfo->myIP, sizeof(IN_ADDR));
    memcpy(setHeader->arp.dst_MAC, LanInfo->gatewayMAC, sizeof(u_char) * MACLEN);
    memcpy(setHeader->arp.dst_IP, &LanInfo->gatewayIP, sizeof(IN_ADDR));
    /* fill Pacekt */
    memcpy(arpPacket, &(setHeader->ethernet), sizeof(char) * ETHERNET_SIZE);
    memcpy(arpPacket + ETHERNET_SIZE, &(setHeader->arp), sizeof(char) * ARP_SIZE);
    /* Send down the packet */
    if (pcap_sendpacket(handle, arpPacket, ARP_SIZE + ETHERNET_SIZE) != 0)
    {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
        return 0;
    }
    /* get reply packet */
    while ((res = pcap_next_ex(handle, &header, &packet)) > 0)
    {
        replyHeader = (PARP_PACKET)packet;
        if (ntohs(replyHeader->ethernet.ether_Type) == ARP)
        {
            if (ntohs(replyHeader->arp.Opcode) == REPLY)
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