#ifndef NODE_CHANNEL
#define NODE_CHANNEL

#include <pthread.h>
#include "common.h"


class LeaderNode;
class FollowerNode;

class NodeChannel
{
	friend class LeaderNode;
	friend class FollowerNode;

	DECLARE_MSG_DUMPER()
	static const char* thread_tag;

private:
	volatile int exit;
    std::string node_ip;
    std::string remote_ip;
	pthread_t send_tid;
	pthread_t recv_tid;
	int node_socket;
	std::list<char*> send_buffer_list;
	std::list<char*> send_access_list;

	pthread_mutex_t mtx_buffer;
	pthread_cond_t cond_buffer;

	PIMSG_NOTIFY_OBSERVER msg_notify_observer;
	unsigned short thread_ret;
	bool send_data_trigger;

	static void* send_thread_handler(void* pvoid);
	unsigned short send_thread_handler_internal();
	static void* recv_thread_handler(void* pvoid);
	unsigned short recv_thread_handler_internal();
	void clearall();

	NodeChannel();
	~NodeChannel();

	unsigned short initialize(PIMSG_NOTIFY_OBSERVER observer, int socketfd, const char* ip);
	unsigned short deinitialize();
	void notify_exit();
	const char* get_ip()const{return node_ip.c_str();}
	const char* get_remote_ip()const{return remote_ip.c_str();}

	unsigned short send_msg(const char* msg_data);
};
typedef NodeChannel* PNODE_CHANNEL;

#endif