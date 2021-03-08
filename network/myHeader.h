#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <winsock2.h>

#define MACLEN 6
#define ARPSIZE 28
#define ETHERNETSIZE 14

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

/* IPv4 header */
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
}ip_header, *Pip_header;

typedef struct tcp_header
{
	u_short src_port; // Source port
	u_short dst_port; // Destination port
	u_int sequenceNumber;
	u_int acknowledgementNumber;
	u_char headerLength;
	u_char flags;
	u_short windowSize;
	u_short checksum;
	u_short urgentPointer;
}tcp_header, *Ptcp_header;

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
/* packetRedirect.c */
int packetRedirect(pcap_t* handle, struct pcap_pkthdr* pktHeader, const u_char* packet, PLANINFO LanInfo);
/* 320Redirect.c */
int packet_handler_redirect(pcap_t* handle, u_char* packet, struct pcap_pkthdr* header);
/* CalcChecksum.c */
int tcpChecksum(Pip_header ipHeader, Ptcp_header tcpHeader, struct pcap_pkthdr* header, const u_char* packet, u_int redirectSiteLen);
int ipChecksum(Pip_header ipHeader, u_int redirectSiteLen);