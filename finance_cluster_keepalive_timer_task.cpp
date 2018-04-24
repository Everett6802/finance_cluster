#include "finance_cluster_keepalive_timer_task.h"


//DECLARE_MSG_DUMPER_PARAM();

FinanceClusterKeepaliveTimerTask::FinanceClusterKeepaliveTimerTask()
{
//	IMPLEMENT_MSG_DUMPER()
}

FinanceClusterKeepaliveTimerTask::~FinanceClusterKeepaliveTimerTask()
{
//	RELEASE_MSG_DUMPER()
}

unsigned short FinanceClusterKeepaliveTimerTask::initialize(PMSG_NOTIFY_OBSERVER_INF observer)
{
	msg_notify_observer = observer;

	return RET_SUCCESS;
}

unsigned short FinanceClusterKeepaliveTimerTask::deinitialize()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer = NULL;

	return RET_SUCCESS;
}

void FinanceClusterKeepaliveTimerTask::run()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer->notify(NOTIFY_CHECK_KEEPALIVE);
}
