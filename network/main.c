#include "myHeader.h"

int main()
{
	DeviceInfo myDeviceInfo, victimDeviceInfo;
	pcap_if_t* alldevs, * choiceDev;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char victimIP[16] = "192.168.50.146";

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

	/* find Device's GateWay IP address */
	getGateWayAddress(choiceDev, &myDeviceInfo);


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
	memset(&victimDeviceInfo, 0, sizeof(DeviceInfo));
	victimDeviceInfo.ipAddress.S_un.S_addr = inet_addr(victimIP);
	getVictimMAC(handle, &myDeviceInfo, &victimDeviceInfo);
	pcap_close(handle);
	return 0;
}