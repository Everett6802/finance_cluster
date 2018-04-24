#include "finance_cluster_node_base.h"


//DECLARE_MSG_DUMPER_PARAM();

FinanceClusterNodeBase::FinanceClusterNodeBase() :
	local_ip(NULL)
{
//	IMPLEMENT_MSG_DUMPER()
}

FinanceClusterNodeBase::~FinanceClusterNodeBase()
{
	if (local_ip != NULL)
	{
		delete[] local_ip;
		local_ip = NULL;
	}

//	RELEASE_MSG_DUMPER()
}
