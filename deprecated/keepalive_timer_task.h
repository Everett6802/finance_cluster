#ifndef KEEPALIVE_TIMER_TASK_H
#define KEEPALIVE_TIMER_TASK_H

#include "common.h"


class KeepaliveTimerTask
{
//	DECLARE_MSG_DUMPER()
private:
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;

public:
	KeepaliveTimerTask();
	~KeepaliveTimerTask();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer);
	unsigned short deinitialize();
	void run();
};

#endif
