#include "msg_cluster_node_base.h"


MsgClusterNodeBase::MsgClusterNodeBase() :
	local_ip(NULL)
{
	IMPLEMENT_MSG_DUMPER()
}

MsgClusterNodeBase::~MsgClusterNodeBase()
{
	if (local_ip != NULL)
	{
		delete[] local_ip;
		local_ip = NULL;
	}

	RELEASE_MSG_DUMPER()
}
