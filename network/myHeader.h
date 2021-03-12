#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <winsock2.h>
#include "win32/libnet.h"

#define MACLEN 6
#define ARPSIZE 28
#define ETHERNETSIZE 14
#define IPPRO_TCP 6

typedef struct ethernet_header
{
	u_char dst_MAC[MACLEN];
	u_char src_MAC[MACLEN];
	u_short ether_Type;
}ethernet_header, *Pethernet_header;

typedef struct arp_header
{
	u_short Hardware_type;
	u_short Protocol_type;
	u_char Hardware_size;
	u_char Protocol_size;
	u_short Opcode;	// 1 : request, 2 : reply
	u_char src_MAC[MACLEN];
	u_char src_IP[4];
	u_char dst_MAC[MACLEN];
	u_char dst_IP[4];
}arp_header, *Parp_header;

typedef struct LANINFO
{
	IN_ADDR  myIP;
	u_char myMAC[MACLEN];
	IN_ADDR  victimIP;
	u_char victimMAC[MACLEN];
	IN_ADDR gatewayIP;
	u_char gatewayMAC[MACLEN];
}LANINFO, * PLANINFO;

typedef struct ARPHEADER
{
	ethernet_header ethernet;
	arp_header arp;
}ARPHEADER, * PARPHEADER;


typedef struct ip_header {
    u_char  version;        // Version (4 bits) + Internet header length (4 bits)
    u_char  typeOfService;            // Type of service 
    u_short totalLen;           // Total length 
    u_short identification; // Identification
    u_short flags;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  protocol;       // Protocol
    u_short checksum;            // Header checksum
    u_char  src_addr[4];    // Source address
    u_char  dst_addr[4];    // Destination address
}ip_header, * Pip_header;

typedef struct tcp_header
{
    u_short src_port; // Source port
    u_short dst_port; // Destination port
    u_int seq;
    u_int ack;
    u_char th_x2 : 4, th_off : 4;
    u_char flags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
}tcp_header, * Ptcp_header;

typedef struct TCPHEADER
{
    ethernet_header ethernet;
    ip_header ip;
    tcp_header tcp;
}TCPHEADER, * PTCPHEADER;

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
int setArpHeader(PARPHEADER header);
int attackvictim(pcap_t* handle, PARPHEADER header, PLANINFO LanInfo);
int attackRouter(pcap_t* handle, PARPHEADER header, PLANINFO LanInfo);
/* checkARP */
int checkVictim(Pethernet_header eh, PLANINFO LanInfo);
int checkGateWay(Pethernet_header eh, PLANINFO LanInfo);
int checkVictim2(struct libnet_ethernet_hdr* eth, PLANINFO LanInfo);
int checkGateWay2(struct libnet_ethernet_hdr* eth, PLANINFO LanInfo);
/* packetRedirect.c */
int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet, PLANINFO LanInfo);
/* 302 Redirect.c */
int packet_handlerRedirect(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len);
/* backward.c */
int packet_handlerBackward(u_char* sendPacket, u_char* packet, const u_char* msg, const u_short msg_len, PLANINFO LanInfo);
/* CalcChecksum.c */
u_short checksum_ip(struct libnet_ipv4_hdr* ip);
u_short checksum_tcp(const struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr* tcp, const u_int len);