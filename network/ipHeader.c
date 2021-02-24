#include "myHeader.h"

int ipHeader(const u_char *packet)
{

	struct ip_header *ih;
	char buffer[20];
	ih = (struct ip_header *)(packet + 12);
	printf("src ip : %s\n", inet_ntop(AF_INET, &ih->src_addr, buffer, sizeof(buffer)));
	printf("dst ip : %s\n", inet_ntop(AF_INET, &ih->dst_addr, buffer, sizeof(buffer)));
	return 0;
}
