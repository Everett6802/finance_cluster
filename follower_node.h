#ifndef FOLLOWER_NODE_H
#define FOLLOWER_NODE_H

#include <pthread.h>
#include <string>
#include "node_base.h"
#include "common.h"


class NodeRecvThread;

class FollowerNode : public NodeBase
{
	DECLARE_MSG_DUMPER()

private:
	static const int WAIT_CONNECTION_TIMEOUT; // 5 seconds
	static const int TRY_TIMES;
	static const int CHECK_KEEPALIVE_TIMES;
	static const int TOTAL_KEEPALIVE_PERIOD;

	CHAR_LIST server_list;
	int follower_socket;
//	class FinanceClusterNodeRecvThread; // Caution: Fail to compile
	NodeRecvThread* msg_recv_thread;
	int keepalive_counter;
	int server_candidate_id;

	unsigned short connect_leader(const char* server_ip);
	unsigned short become_follower(const char* server_ip);
	unsigned short find_leader();
	bool is_keepalive_packet(const std::string message)const;

public:
	FollowerNode(const PCHAR_LIST alist, char* ip);
	virtual ~FollowerNode();

// From NodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const std::string ip, const std::string message);
	virtual unsigned short notify(NotifyType notify_type);

	int get_server_candidate_id()const{return server_candidate_id;}
};
typedef FollowerNode* PFOLLOWER_NODE;

#endif
