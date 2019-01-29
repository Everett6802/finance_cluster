#ifndef LEADER_NODE_H
#define LEADER_NODE_H

#include <pthread.h>
//#include <list>
#include <deque>
#include <string>
#include "common.h"
#include "node_base.h"
#include "node_channel.h"


// class NodeRecvThread;
// class LeaderSendThread;

class LeaderNode : public INode
{
	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
	static const int WAIT_CONNECTION_TIMEOUT;
private:
	int socketfd;
	char* local_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_node_id;
	int cluster_node_cnt;
	ClusterMap cluster_map;

	volatile int exit;
	pthread_t listen_tid;

	// std::deque<PNODE_CHANNEL> node_channel_deque;
	std::map<std::string, PNODE_CHANNEL> node_channel_map;
	std::map<std::string, int> node_keepalive_map;

	volatile unsigned short thread_ret;
	pthread_mutex_t mtx_node_channel;
	// pthread_mutex_t mtx_cluster_map;

	unsigned short become_leader();
	unsigned short send_data(MessageType message_type, const char* data=NULL, const char* remote_ip=NULL);
// events
// recv
	unsigned short recv_check_keepalive(const std::string& message_data);
	unsigned short recv_update_cluster_map(const std::string& message_data);
	unsigned short recv_transmit_text(const std::string& message_data);
// send
	unsigned short send_check_keepalive(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_update_cluster_map(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_transmit_text(void* param1=NULL, void* param2=NULL, void* param3=NULL);

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();
	static void thread_cleanup_handler(void* pvoid);
	void thread_cleanup_handler_internal();

public:
	LeaderNode(const char* ip);
	virtual ~LeaderNode();

// Interface
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short recv(MessageType message_type, const std::string& message_data);
	virtual unsigned short send(MessageType message_type, void* param1=NULL, void* param2=NULL, void* param3=NULL);
    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL);
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL);
};
typedef LeaderNode* PLEADER_NODE;

#endif
