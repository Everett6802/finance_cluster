#ifndef NODE_CHANNEL
#define NODE_CHANNEL

#include <pthread.h>
#include <string>
#include "common.h"


class LeaderNode;
class FollowerNode;

class NodeChannel
{
	friend class LeaderNode;
	friend class FollowerNode;

	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
	static const int WAIT_DATA_TIMEOUT;

private:
	PINODE observer;
	volatile int action_freeze;
	volatile int exit;
    std::string node_token;
    std::string remote_token;
	pthread_t send_tid;
	pthread_t recv_tid;
	int node_socket;
	std::list<char*> send_buffer_list;
	std::list<char*> send_access_list;

	pthread_mutex_t mtx_buffer;
	pthread_cond_t cond_buffer;

	unsigned short send_thread_ret;
	unsigned short recv_thread_ret;
	bool send_msg_trigger;

	static void* send_thread_handler(void* pvoid);
	unsigned short send_thread_handler_internal();
	static void send_thread_cleanup_handler(void* pvoid);
	void send_thread_cleanup_handler_internal();
	static void* recv_thread_handler(void* pvoid);
	unsigned short recv_thread_handler_internal();
	void clearall();

	NodeChannel(PINODE node);
	~NodeChannel();

	unsigned short initialize(int channel_socket, const char* channel_token, const char* channel_remote_token);
	unsigned short deinitialize();
	void notify_exit();
	const char* get_token()const;
	const char* get_remote_token()const;
	void freeze_action();

// Don't treat the data content as string. It's required to know the data size
	unsigned short send_msg(const char* msg_data, int msg_data_size);
};
typedef NodeChannel* PNODE_CHANNEL;

#endif
