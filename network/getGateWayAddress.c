#include "myHeader.h"
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

int getGateWayAddress(pcap_if_t * choiceDev, char * gateWayAddress)
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	struct sockaddr_in * dev_address = (struct sockaddr_in *)choiceDev->addresses->addr;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	/* copy choiceDev's IP address */
	char choiceDevIP[32];
	memcpy(choiceDevIP, iptos(dev_address->sin_addr.s_addr), sizeof(choiceDevIP));
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		for(pAdapter = pAdapterInfo; pAdapter!=NULL; pAdapter = pAdapter->Next) {
			/* find choiced dev's gateway IP */
			if (strcmp(pAdapter->IpAddressList.IpAddress.String, choiceDevIP) == 0)
			{
				//printf("choiceDev->addresses : %s\n", choiceDevIP);
				//printf("pAdapter->IpAddressList.IpAddress.String : %s\n", pAdapter->IpAddressList.IpAddress.String);
				memcpy(gateWayAddress, pAdapter->GatewayList.IpAddress.String, sizeof(pAdapter->GatewayList.IpAddress.String));
				//printf("gateWayAddr : %s\n", gateWayAddress);
			}
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	}
	if (pAdapterInfo)
		free(pAdapterInfo);
	return 0;
}