#ifndef MSG_CLUSTER_LEADER_SEND_THREAD
#define MSG_CLUSTER_LEADER_SEND_THREAD

#include <pthread.h>
#include "msg_cluster_common.h"


class MsgClusterLeaderSendThread
{
	DECLARE_MSG_DUMPER()

private:
	class MsgCfg;

	pthread_t t;
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();

public:
	MsgClusterLeaderSendThread();
	~MsgClusterLeaderSendThread();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer);
	unsigned short deinitialize();
};
typedef MsgClusterLeaderSendThread* PMSG_CLUSTER_LEADER_SEND_THREAD;

#endif
