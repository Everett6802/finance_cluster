#ifndef MSG_CLUSTER_LEADER_SEND_THREAD
#define MSG_CLUSTER_LEADER_SEND_THREAD

#include <pthread.h>
#include <list>
#include <pthread.h>
#include <string>
#include "msg_cluster_common.h"


class MsgClusterLeaderSendThread
{
	DECLARE_MSG_DUMPER()
	static const char* thread_tag;

private:
	class MsgCfg;

	volatile int exit;
	pthread_t pid;
	std::deque<std::string> client_deque;
	std::deque<int> dead_client_index_deque;
	std::deque<int> client_socket_deque;
	int client_size;
	std::list<MsgCfg*> buffer_list;
	std::list<MsgCfg*> access_list;
	unsigned short thread_ret;
	volatile bool is_follower_connected;
	PMSG_NOTIFY_OBSERVER_INF msg_notify_observer;
	pthread_mutex_t mtx_client_socket;
	pthread_mutex_t mtx_buffer;
	pthread_cond_t cond_buffer;
	bool new_data_trigger;

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();
	void clearall();

public:
	MsgClusterLeaderSendThread();
	~MsgClusterLeaderSendThread();

	unsigned short initialize(PMSG_NOTIFY_OBSERVER_INF observer);
	unsigned short deinitialize();
	void notify_exit();
	unsigned short add_client(const char* ip, int socket);
	unsigned short send_msg(std::string src_ip, std::string data);
	unsigned short try_to_transmit_msg(int index, std::string data);
	unsigned short send_msg_to_remote();
};
typedef MsgClusterLeaderSendThread* PMSG_CLUSTER_LEADER_SEND_THREAD;

#endif
