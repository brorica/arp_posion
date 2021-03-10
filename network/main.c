#include "myHeader.h"

int http_capture(const u_char* packet) {
	Pethernet_header eth;
	Pip_header ip;
	Ptcp_header tcp;

	/* ethernet header */
	eth = (Pethernet_header)packet;
	/* ip header */
	if (ntohs(eth->ether_Type) != 0x0800) 
		return 0;
	ip = (Pip_header)(packet + 14);
	/* tcp header */
	if (ntohs(ip->totalLen) <= 40 || ip->protocol != 6) 
		return 0;
	/* tcp body */
	const char* body = packet + 54;
	if (memcmp(body, "GET", 3))
		return 0;
	printf("1\n");
	return 1;
}

int main()
{
	LANINFO LanInfo;
	pcap_if_t *alldevs, *choiceDev;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char victimIP[16] = "192.168.50.135";

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	choiceDev = ChoiceDev(alldevs);

	/* Get Handle From choice Device */
	handle = pcap_open_live(choiceDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", choiceDev->name, errbuf);
		exit(1);
	}
	/* now, we don't need any more the devices list */
	pcap_freealldevs(alldevs);
	/*
	memset(&LanInfo, 0, sizeof(LanInfo));
	// find Device's GateWay IP address 
	getGateWayAddress(choiceDev, &LanInfo);
	LanInfo.victimIP.S_un.S_addr = inet_addr(victimIP);
	getMACAddress(handle, &LanInfo);
	printf("victim MAC : ");
	for (int i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%.2X\n", LanInfo.victimMAC[i]);
		else
			printf("%.2X-", LanInfo.victimMAC[i]);
	}
	printf("Gateway MAC : ");
	for (int i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%.2X\n", LanInfo.gatewayMAC[i]);
		else
			printf("%.2X-", LanInfo.gatewayMAC[i]);
	}
	ARPHEADER TEST_header;
	setArpHeader(&TEST_header);
	attackvictim(handle, &TEST_header, &LanInfo);
	Sleep(500);
	attackRouter(handle, &TEST_header, &LanInfo);
	*/
	// sniff packet 
	struct pcap_pkthdr* header;
	const u_char* packet;
	u_char sendPacket[1024] = { 0 };
	u_char msg_forward[MSG_FORWARD_LEN + 1] = MSG_FORWARD;          /* blocked message */
	u_char msg_backward[MSG_BACKWARD_LEN + 1] = MSG_BACKWARD; /*  */
	printf("listen...");
	while (1)
	{
		if (pcap_next_ex(handle, &header, &packet) == 1)
		{
			if (http_capture(packet))
			{
				packet_handlerBackward(sendPacket, packet, msg_backward, MSG_BACKWARD_LEN);
				pcap_sendpacket(handle, sendPacket, 14 + 20 + 20 + MSG_BACKWARD_LEN);
				packet_handlerRedirect(sendPacket, packet, msg_forward, MSG_FORWARD_LEN);
				pcap_sendpacket(handle, sendPacket, 14 + 20 + 20 + MSG_FORWARD_LEN);
			}
			//packet_handlerForward(handle, packet, header);
			//packet_handlerRedirect(handle, packet, header);
			//if (res == 0)
			//	continue;
			//if (checkARP(handle, packet, &LanInfo))
			//	continue;
			//else
			//{
			//	packetRedirect(handle, header, packet, &LanInfo);
			//}
		}
	}
	pcap_close(handle);
	return 0;
}