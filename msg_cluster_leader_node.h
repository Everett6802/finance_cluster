#ifndef MSG_CLUSTER_LEADER_NODE_H
#define MSG_CLUSTER_LEADER_NODE_H

#include <list>
#include <string>
#include "msg_cluster_node_base.h"
#include "msg_cluster_common.h"


class MsgClusterNodeRecvThread;
class MsgClusterLeaderSendThread;

class MsgClusterLeaderNode : public MsgClusterNodeBase
{
	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
private:
	volatile bool exit;
	pthread_t pid;
	int leader_socket;
	//	class MsgClusterNodeRecvThread; // Caution: Fail to compile
	//	class MsgClusterLeaderSendThread; // Caution: Fail to compile
	std::list<MsgClusterNodeRecvThread*>* client_recv_thread_list;
	MsgClusterLeaderSendThread* client_send_thread;
	volatile unsigned short thread_ret;
	pthread_mutex_t mtx_thread_list;

	unsigned short become_leader();

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();

public:
	MsgClusterLeaderNode(char* ip);
	virtual ~MsgClusterLeaderNode();

// From MsgClusterNodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const char* ip, const std::string message);
	virtual unsigned short notify(NotifyType notify_type);
};
typedef MsgClusterLeaderNode* PMSG_CLUSTER_LEADER_NODE;

#endif
