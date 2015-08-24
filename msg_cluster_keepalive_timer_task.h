#ifndef MSG_CLUSTER_KEEPALIVE_TIMER_TASK_H
#define MSG_CLUSTER_KEEPALIVE_TIMER_TASK_H

#include "msg_cluster_common.h"


class MsgClusterKeepaliveTimerTask
{
	DECLARE_MSG_DUMPER()
private:
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;

public:
	MsgClusterKeepaliveTimerTask();
	~MsgClusterKeepaliveTimerTask();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer);
	unsigned short deinitialize();
	void run();
};

#endif
