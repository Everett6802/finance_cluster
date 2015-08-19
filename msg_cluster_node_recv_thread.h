#ifndef MSG_CLUSTER_NODE_RECV_THREAD
#define MSG_CLUSTER_NODE_RECV_THREAD

#include <pthread.h>
#include "msg_cluster_common.h"


class MsgClusterNodeRecvThread
{
	DECLARE_MSG_DUMPER()

private:
	pthread_t t;
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;

public:
	MsgClusterNodeRecvThread();
	~MsgClusterNodeRecvThread();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer, int recv_socket);
	unsigned short deinitialize();
};
typedef MsgClusterNodeRecvThread* PMSG_CLUSTER_NODE_RECV_THREAD;

#endif
