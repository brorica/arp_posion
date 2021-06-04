#include "arpSpoofing.h"
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

int getGateWayAddress(pcap_if_t * choiceDev)
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
	/* copy choiceDev's Info */
	char choiceDevIP[16];
	memcpy(choiceDevIP, iptos(dev_address->sin_addr.s_addr), sizeof(choiceDevIP));
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		for(pAdapter = pAdapterInfo; pAdapter!=NULL; pAdapter = pAdapter->Next) {
			/* find choiced dev's gateway IP */
			if (strncmp(pAdapter->IpAddressList.IpAddress.String, choiceDevIP, sizeof(choiceDevIP)) == 0)
			{
				LanInfo->gatewayIP.S_un.S_addr = inet_addr(pAdapter->GatewayList.IpAddress.String);
				LanInfo->myIP.S_un.S_addr = inet_addr(pAdapter->IpAddressList.IpAddress.String);
				printf("MAC ADDRESS : ");
				for (UINT i = 0; i < pAdapter->AddressLength; i++) {
					LanInfo->myMAC[i] = (int)pAdapter->Address[i];
					if (i == (pAdapter->AddressLength - 1))
						printf("%.2X\n", LanInfo->myMAC[i]);
					else
						printf("%.2X-", LanInfo->myMAC[i]);
				}
				printf("gateWayAddr : %s\n", inet_ntoa(LanInfo->gatewayIP));
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