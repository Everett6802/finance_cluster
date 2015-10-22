#include "msg_cluster_keepalive_timer_task.h"


//DECLARE_MSG_DUMPER_PARAM();

MsgClusterKeepaliveTimerTask::MsgClusterKeepaliveTimerTask()
{
//	IMPLEMENT_MSG_DUMPER()
}

MsgClusterKeepaliveTimerTask::~MsgClusterKeepaliveTimerTask()
{
//	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterKeepaliveTimerTask::initialize(PMSG_NOTIFY_OBSERVER_INF observer)
{
	msg_notify_observer = observer;

	return RET_SUCCESS;
}

unsigned short MsgClusterKeepaliveTimerTask::deinitialize()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer = NULL;

	return RET_SUCCESS;
}

void MsgClusterKeepaliveTimerTask::run()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer->notify(NOTIFY_CHECK_KEEPALIVE);
}
