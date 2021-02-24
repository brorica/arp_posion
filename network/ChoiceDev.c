#include <pcap.h>

pcap_if_t * ChoiceDev(pcap_if_t * alldevs)
{
	pcap_if_t *alldevsTemp;
	u_int choice, devNumber = 1;

	alldevsTemp = alldevs;
	/* Print the list */
	while (alldevsTemp->next != NULL)
	{
		printf("%d. %s\n", devNumber, alldevsTemp->description);
		alldevsTemp = alldevsTemp->next;
		devNumber++;
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
	choiceDev = alldevs;
	for (u_int i = 0; i < choice; i++)
		choiceDev = choiceDev->next;
	return choiceDev;
}