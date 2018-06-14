#ifndef LEADER_NODE_H
#define LEADER_NODE_H

//#include <list>
#include <deque>
#include <string>
#include "node_base.h"
#include "common.h"


class NodeRecvThread;
class LeaderSendThread;

class LeaderNode : public NodeBase
{
	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
private:
	int leader_socket;
	int cluster_node_cnt;

	volatile bool exit;
	pthread_t pid;
	//	class NodeRecvThread; // Caution: Fail to compile
	//	class LeaderSendThread; // Caution: Fail to compile
	std::deque<NodeRecvThread*>* client_recv_thread_deque;
	LeaderSendThread* client_send_thread;
	volatile unsigned short thread_ret;
	pthread_mutex_t mtx_thread_list;

	unsigned short become_leader();

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();

public:
	LeaderNode(const char* ip);
	virtual ~LeaderNode();

// From NodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const std::string ip, const std::string message);
	virtual unsigned short notify(NotifyType notify_type);
};
typedef LeaderNode* PLEADER_NODE;

#endif
