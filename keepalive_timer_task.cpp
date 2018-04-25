#include "keepalive_timer_task.h"


//DECLARE_MSG_DUMPER_PARAM();

KeepaliveTimerTask::KeepaliveTimerTask()
{
//	IMPLEMENT_MSG_DUMPER()
}

KeepaliveTimerTask::~KeepaliveTimerTask()
{
//	RELEASE_MSG_DUMPER()
}

unsigned short KeepaliveTimerTask::initialize(PMSG_NOTIFY_OBSERVER_INF observer)
{
	msg_notify_observer = observer;

	return RET_SUCCESS;
}

unsigned short KeepaliveTimerTask::deinitialize()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer = NULL;

	return RET_SUCCESS;
}

void KeepaliveTimerTask::run()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer->notify(NOTIFY_CHECK_KEEPALIVE);
}
