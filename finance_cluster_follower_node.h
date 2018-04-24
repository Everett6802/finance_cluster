#ifndef FINANCE_CLUSTER_FOLLOWER_NODE_H
#define FINANCE_CLUSTER_FOLLOWER_NODE_H

#include <pthread.h>
#include <string>
#include "finance_cluster_node_base.h"
#include "finance_cluster_common.h"


class FinanceClusterNodeRecvThread;

class FinanceClusterFollowerNode : public FinanceClusterNodeBase
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
	FinanceClusterNodeRecvThread* msg_recv_thread;
	int keepalive_counter;
	int server_candidate_id;

	unsigned short connect_leader(const char* server_ip);
	unsigned short become_follower(const char* server_ip);
	unsigned short find_leader();
	bool is_keepalive_packet(const std::string message)const;

public:
	FinanceClusterFollowerNode(const PCHAR_LIST alist, char* ip);
	virtual ~FinanceClusterFollowerNode();

// From FinanceClusterNodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const std::string ip, const std::string message);
	virtual unsigned short notify(NotifyType notify_type);

	int get_server_candidate_id()const{return server_candidate_id;}
};
typedef FinanceClusterFollowerNode* PFINANCE_CLUSTER_FOLLOWER_NODE;

#endif
