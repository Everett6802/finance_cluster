#ifndef FINANCE_CLUSTER_NODE_BASE_H
#define FINANCE_CLUSTER_NODE_BASE_H

#include "finance_cluster_common.h"


class FinanceClusterNodeBase : public MsgNotifyObserverInf
{
//	DECLARE_MSG_DUMPER()

protected:
	char* local_ip;

public:
	FinanceClusterNodeBase();
	virtual ~FinanceClusterNodeBase();

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short check_keepalive()=0;
};
typedef FinanceClusterNodeBase* PFINANCE_CLUSTER_NODE_BASE;

#endif
