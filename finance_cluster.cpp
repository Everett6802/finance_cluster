#include <stdio.h>
#include <stdlib.h>
#include "cluster_mgr.h"
#include "common_definition.h"


extern ClusterMgr cluster_mgr;

int main()
{
	ClusterMgr cluster_mgr;
	printf("Start the Node...\n");

	unsigned short ret = cluster_mgr.start();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to initialize...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	ret = cluster_mgr.wait_to_stop();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to waiting for stop...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	printf("The Node is Stopped......\n");

	exit(EXIT_SUCCESS);
}
