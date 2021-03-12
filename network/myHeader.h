#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winsock2.h>

#define MACLEN 6
#define ARP_HEADER_SIZE 28
#define ETHERNET_HEADER_SIZE 14
#define ARP_PACKET_SIZE (ARP_HEADER_SIZE + ETHERNET_HEADER_SIZE)
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20
#define TCP_PACKET_SIZE (ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE)

typedef struct ethernet_header
{
	u_char dst_MAC[MACLEN];
	u_char src_MAC[MACLEN];
	u_short etherType;
#define IPV4 0x0800
#define ARP 0x0806
}ETHERNET_HEADER, *PETHERNET_HEADER;

typedef struct arp_header
{
	u_short Hardware_type;
	u_short Protocol_type;
	u_char Hardware_size;
	u_char Protocol_size;
	u_short Opcode;	// 1 : request, 2 : reply
#define REQUEST 0x0001
#define REPLY 0x0002
	u_char src_MAC[MACLEN];
	u_char src_IP[4];
	u_char dst_MAC[MACLEN];
	u_char dst_IP[4];
}ARP_HEADER, *PARP_HEADER;

typedef struct lanInfo
{
	IN_ADDR  myIP;
	u_char myMAC[MACLEN];
	IN_ADDR  victimIP;
	u_char victimMAC[MACLEN];
	IN_ADDR gatewayIP;
	u_char gatewayMAC[MACLEN];
}LANINFO, * PLANINFO;

typedef struct arp_packet
{
    ETHERNET_HEADER ethernet;
    ARP_HEADER arp;
}ARP_PACKET, * PARP_PACKET;


typedef struct ip_header {
 #if (REG_DWORD  == REG_DWORD_LITTLE_ENDIAN)
    u_char  ipHeaderLength:4,
        ipVersion:4;
#endif
#if (REG_DWORD == REG_DWORD_BIG_ENDIAN)
    u_char  ipVersion:4,
        ipHeaderLength:4;
#endif
    u_char  typeOfService;
    u_short totalLen;
    u_short identifification;
    u_short flags;
    u_char  ttl;
    u_char  protocol;
#define IP_PROTOCOL_TCP 6
    u_short checksum;
    u_char  sourceIP[4];
    u_char  destinationIP[4];
}IP_HEADER, * PIP_HEADER;

typedef struct tcp_header
{
    u_short sourcePort;
    u_short destinationPort;
    u_int seq;
    u_int ack;
#if (REG_DWORD  == REG_DWORD_LITTLE_ENDIAN)
    u_char  reserved:4,
        dataOffset:4;
#endif
#if (REG_DWORD == REG_DWORD_BIG_ENDIAN)
    u_char  dataOffset:4,
        reserved:4;
#endif
    u_char flags;
#ifndef TH_FIN
#define TH_FIN    0x01
#endif
#ifndef TH_ACK
#define TH_ACK    0x10
#endif
    u_short window;
    u_short checksum;
    u_short urgentPointer;
}TCP_HEADER, * PTCP_HEADER;

typedef struct TCP_PACKET
{
    ETHERNET_HEADER ethernet;
    IP_HEADER ip;
    TCP_HEADER tcp;
}TCP_PACKET, * PTCP_PACKET;

/* ChoiceDev.c */
pcap_if_t * ChoiceDev(pcap_if_t * alldevs);
int checkARP(pcap_t* handle, const u_char *packet, PLANINFO LanInfo);
int ipHeader(const u_char *packet);
int tcpHeader(const u_char *packet);
/* getGateWayAddress */
int getGateWayAddress(pcap_if_t * choiceDev, PLANINFO LanInfo);
char *iptos(u_long in);
/* getMACAddress.c */
int getMACAddress(pcap_t *handle, PLANINFO LanInfo);
/* sendFakeARP.c */
int setArpHeader(PARP_HEADER arpHeader);
int attackvictim(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo);
int attackRouter(pcap_t* handle, PARP_PACKET arpPacket, PLANINFO LanInfo);
/* checkARP */
int checkVictim(PETHERNET_HEADER eh, PLANINFO LanInfo);
int checkGateWay(PETHERNET_HEADER eh, PLANINFO LanInfo);
/* packetRedirect.c */
int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet, PLANINFO LanInfo);
/* 302 Redirect.c */
int packet302Redirect(u_char* sendPacket, const u_char* packet, PLANINFO LanInfo);
/* forward.c */
int packetForward(u_char* sendPacket, const u_char* packet);
/* CalcChecksum.c */
u_short checksum_ip(PIP_HEADER ip);
u_short checksum_tcp(PIP_HEADER ip, PTCP_HEADER tcp, u_short totalTcpLen);