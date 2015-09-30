#ifndef MSG_CLUSTER_NODE_RECV_THREAD
#define MSG_CLUSTER_NODE_RECV_THREAD

#include <pthread.h>
#include "msg_cluster_common.h"


class MsgClusterLeaderNode;
class MsgClusterFollowerNode;

class MsgClusterNodeRecvThread
{
	friend class MsgClusterLeaderNode;
	friend class MsgClusterFollowerNode;

	DECLARE_MSG_DUMPER()
	static const char* thread_tag;

private:
	volatile int exit;
    std::string node_ip;
	pthread_t pid;
	int node_socket;
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;
	unsigned short thread_ret;

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();
	void clearall();

	MsgClusterNodeRecvThread();
	~MsgClusterNodeRecvThread();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer, int recv_socket, const char* ip);
	unsigned short deinitialize();
	void notify_exit();
	const std::string get_ip()const{return node_ip;}
};
typedef MsgClusterNodeRecvThread* PMSG_CLUSTER_NODE_RECV_THREAD;

#endif
