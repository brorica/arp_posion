#include "myHeader.h"

int main()
{
	pcap_if_t *alldevs, *choiceDev;
	pcap_t *handle;
	char gateWayAddr[32];
	char errbuf[PCAP_ERRBUF_SIZE];

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

	/* interpret packet */
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
	getGateWayAddress(choiceDev, gateWayAddr);
	pcap_close(handle);
	return 0;
}