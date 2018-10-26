#ifndef FOLLOWER_NODE_H
#define FOLLOWER_NODE_H

// #include <pthread.h>
#include <string>
#include "common.h"
#include "node_base.h"
#include "node_channel.h"


// class NodeRecvThread;

class FollowerNode : public INode
{
	DECLARE_MSG_DUMPER()

private:
	static const int WAIT_CONNECTION_TIMEOUT; // 5 seconds
	static const int TRY_TIMES;
	static const int CHECK_KEEPALIVE_TIMES;
	static const int TOTAL_KEEPALIVE_PERIOD;

	// CHAR_LIST server_list;
	int socketfd;
	char* local_ip;
	char* cluster_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_node_id;
	ClusterMap cluster_map;
	int keepalive_cnt;
	PNODE_CHANNEL node_channel;

	pthread_mutex_t mtx_cluster_map;
	pthread_mutex_t mtx_node_channel;
//	class FinanceClusterNodeRecvThread; // Caution: Fail to compile
	// NodeRecvThread* msg_recv_thread;
	// int server_candidate_id;

	unsigned short connect_leader();
	unsigned short become_follower();
	unsigned short send_data(const char* data);
	// unsigned short check_keepalive();
	// // unsigned short find_leader();
	// bool is_keepalive_packet(const std::string message)const;
// events
// recv
	unsigned short recv_check_keepalive(const std::string& message_data);
	unsigned short recv_update_cluster_map(const std::string& message_data);//{UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_UPDATE_CLUSUTER_MAP);}
// send
	unsigned short send_check_keepalive(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_update_cluster_map(void* param1=NULL, void* param2=NULL, void* param3=NULL); //{UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_UPDATE_CLUSUTER_MAP);}

public:
	FollowerNode(const char* server_ip, const char* ip);
	virtual ~FollowerNode();

// Interface
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short recv(MessageType message_type, const std::string& message_data);
	virtual unsigned short send(MessageType message_type, void* param1=NULL, void* param2=NULL, void* param3=NULL);
    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL);
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL);
};
typedef FollowerNode* PFOLLOWER_NODE;

#endif
