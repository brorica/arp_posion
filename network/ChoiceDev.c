#include <pcap.h>

#define IPTOSBUFFERS    12
char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
short which;

char *iptos(u_long in)
{
	u_char *p;
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

pcap_if_t * ChoiceDev(pcap_if_t * alldevs)
{
	pcap_if_t *alldevsTemp;
	pcap_addr_t * dev_address;
	u_int i, choice, devNumber = 1;

	alldevsTemp = alldevs;
	/* Print the list */
	while (alldevsTemp != NULL)
	{
		for (dev_address = alldevsTemp->addresses; dev_address != NULL; dev_address = dev_address->next) {
			if (dev_address->addr->sa_family == AF_INET && dev_address->addr) {
				printf("%d. %s\n", devNumber++, alldevsTemp->description);
				/* find IP Address copy */
				memcpy(alldevsTemp->addresses->addr, dev_address->addr, sizeof(struct sockaddr_in));
				printf("IP Address : %s\n",iptos(((struct sockaddr_in *)alldevsTemp->addresses->addr)->sin_addr.s_addr));
			}
		}
		alldevsTemp = alldevsTemp->next;
	}

	if (devNumber == 0)
	{
		fprintf(stderr, "\nNo interfaces found! Make sure WinPcap is installed.\n");
		exit(1);
	}

	/* choice Device */
	pcap_if_t *choiceDev;
	while (1)
	{
		printf("Choice Device Number : ");
		scanf("%u", &choice);
		/* check input */
		if (choice < 1 || choice >= devNumber)
			fprintf(stderr, "please Input correct number\n");
		else
			break;
	}
	for (choiceDev = alldevs, i = 0; i < choice - 1; choiceDev = choiceDev->next, i++);
	return choiceDev;
}