#include "myHeader.h"

int packet_handler_redirect(pcap_t* handle, u_char* packet, struct pcap_pkthdr* header)
{
	PTCPHEADER tcpHeader;
	tcpHeader = (PTCPHEADER)(packet);
	/* check packet is null */
	if (packet == NULL)
		return 0;
	/* only get http */
	if (ntohs(tcpHeader->tcp.dst_port) != 0x0050)				// http 통신이 아니면 버림
		return 0;

	char* redirectSite = "HTTP / 1.1 302 Found\r\nLocation: http://en.wikipedia.org/wiki/HTTP_302\r\n";
	u_int redirectSiteLen = strlen(redirectSite);
	tcpHeader->tcp.checksum = tcpChecksum(&tcpHeader->ip, &tcpHeader->tcp, header, packet, redirectSiteLen);
	swapEthernetSrcDstAddress(&tcpHeader->ethernet);
	tcpHeader->ip.checksum = ipChecksum(&tcpHeader->ip, redirectSiteLen);
	/* send packet */
	u_char redirectPacket[4096];
	memcpy(redirectPacket, tcpHeader, sizeof(TCPHEADER));
	memcpy(redirectPacket + 54 , redirectSite, redirectSiteLen);
	pcap_sendpacket(handle, redirectPacket, 4096);
	return 0;
}

int swapEthernetSrcDstAddress(Pethernet_header eh)
{
	u_char temp[MACLEN];
	/* chagne MAC Addr */
	memcpy(temp, eh->dst_MAC, sizeof(u_char) * MACLEN);
	memcpy(eh->dst_MAC, eh->src_MAC, sizeof(u_char) * MACLEN);
	memcpy(eh->src_MAC, temp, sizeof(u_char) * MACLEN);
}
