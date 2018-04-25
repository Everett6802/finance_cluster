#ifndef NODE_RECV_THREAD
#define NODE_RECV_THREAD

#include <pthread.h>
#include "common_definition.h"


class LeaderNode;
class FollowerNode;

class NodeRecvThread
{
	friend class LeaderNode;
	friend class FollowerNode;

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

	NodeRecvThread();
	~NodeRecvThread();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer, int recv_socket, const char* ip);
	unsigned short deinitialize();
	void notify_exit();
	const std::string get_ip()const{return node_ip;}
};
typedef NodeRecvThread* PNODE_RECV_THREAD;

#endif
