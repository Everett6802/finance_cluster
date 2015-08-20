#include <stdio.h>
#include <stdlib.h>
#include "msg_cluster_mgr.h"
#include "msg_cluster_common.h"


int main()
{
	MsgClusterMgr msg_cluster_mgr;
	printf("Start the Node...\n");

	unsigned short ret = msg_cluster_mgr.start();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to initialize...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	ret = msg_cluster_mgr.wait_to_stop();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to waiting for stop...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	printf("The Node is Stopped......\n");

	exit(EXIT_SUCCESS);
}
