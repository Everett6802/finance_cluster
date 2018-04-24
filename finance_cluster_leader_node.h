#ifndef FINANCE_CLUSTER_LEADER_NODE_H
#define FINANCE_CLUSTER_LEADER_NODE_H

//#include <list>
#include <deque>
#include <string>
#include "finance_cluster_node_base.h"
#include "finance_cluster_common.h"


class FinanceClusterNodeRecvThread;
class FinanceClusterLeaderSendThread;

class FinanceClusterLeaderNode : public FinanceClusterNodeBase
{
	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
private:
	volatile bool exit;
	pthread_t pid;
	int leader_socket;
	//	class FinanceClusterNodeRecvThread; // Caution: Fail to compile
	//	class FinanceClusterLeaderSendThread; // Caution: Fail to compile
	std::deque<FinanceClusterNodeRecvThread*>* client_recv_thread_deque;
	FinanceClusterLeaderSendThread* client_send_thread;
	volatile unsigned short thread_ret;
	pthread_mutex_t mtx_thread_list;

	unsigned short become_leader();

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();

public:
	FinanceClusterLeaderNode(char* ip);
	virtual ~FinanceClusterLeaderNode();

// From FinanceClusterNodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const std::string ip, const std::string message);
	virtual unsigned short notify(NotifyType notify_type);
};
typedef FinanceClusterLeaderNode* PFINANCE_CLUSTER_LEADER_NODE;

#endif
