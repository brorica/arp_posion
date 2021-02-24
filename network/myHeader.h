#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef struct ethernet_header
{
	u_char dst_MAC[6];
	u_char src_MAC[6];
	u_short ether_Type;
}ethernet_header;


/* 4 bytes IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  src_addr;      // Source address
	ip_address  dst_addr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct tcp_header
{
	u_short src_port; // Source port
	u_short dst_port; // Destination port
}tcp_header;


/* ChoiceDev.c */
pcap_if_t * ChoiceDev(pcap_if_t * alldevs);
int ethernetHeader(const u_char *packet);
int ipHeader(const u_char *packet);
int tcpHeader(const u_char *packet);