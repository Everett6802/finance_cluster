#ifndef FINANCE_CLUSTER_KEEPALIVE_TIMER_TASK_H
#define FINANCE_CLUSTER_KEEPALIVE_TIMER_TASK_H

#include "finance_cluster_common.h"


class FinanceClusterKeepaliveTimerTask
{
//	DECLARE_MSG_DUMPER()
private:
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;

public:
	FinanceClusterKeepaliveTimerTask();
	~FinanceClusterKeepaliveTimerTask();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer);
	unsigned short deinitialize();
	void run();
};

#endif
