#include "myHeader.h"

int tcpHeader(const u_char *packet)
{
	tcp_header *th;
	u_short src_port;
	u_short dst_port;
	th = (struct tcp_header *)packet;

	src_port = ntohs(th->src_port);
	dst_port = ntohs(th->dst_port);
	if (src_port != 0 || dst_port != 0)
	{
		printf("Src Port Num : %d\n", src_port);
		printf("Dst Port Num : %d\n", dst_port);
	}
	else
		return -1;

	return 0;
}