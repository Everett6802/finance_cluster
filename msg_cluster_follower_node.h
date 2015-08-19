#ifndef MSG_CLUSTER_FOLLOWER_NODE_H
#define MSG_CLUSTER_FOLLOWER_NODE_H

#include <pthread.h>
#include <string>
#include "msg_cluster_node_base.h"
#include "msg_cluster_common.h"


class MsgClusterNodeRecvThread;

class MsgClusterFollowerNode : public MsgClusterNodeBase
{
	DECLARE_MSG_DUMPER()

private:
	static const int WAIT_CONNECTION_TIMEOUT; // 5 seconds
	static const int TRY_TIMES;
	static const int CHECK_KEEPALIVE_TIMES;
	static const int TOTAL_KEEPALIVE_PERIOD;

//	class MsgClusterNodeRecvThread; // Caution: Fail to compile
	MsgClusterNodeRecvThread* msg_recv_thread;
	CHAR_LIST server_list;
	int follower_socket;
	int server_candidate_id;

	unsigned short connect_leader(const char* server_ip);
	unsigned short become_follower(const char* server_ip);
	unsigned short find_leader();
	bool is_keepalive_packet(const std::string message)const;

public:
	MsgClusterFollowerNode(const PCHAR_LIST alist, char* ip);
	virtual ~MsgClusterFollowerNode();

// From MsgClusterNodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const char* ip, const char* message);
	virtual unsigned short notify(short notify_type);

	int get_server_candidate_id(){return server_candidate_id;}
};
typedef MsgClusterFollowerNode* PMSG_CLUSTER_FOLLOWER_NODE;

#endif
