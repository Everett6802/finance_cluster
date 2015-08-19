#ifndef MSG_CLUSTER_LEADER_NODE_H
#define MSG_CLUSTER_LEADER_NODE_H

#include <list>
#include "msg_cluster_node_base.h"


class MsgClusterNodeRecvThread;
class MsgClusterLeaderSendThread;

class MsgClusterLeaderNode : public MsgClusterNodeBase
{
	DECLARE_MSG_DUMPER()

private:
	//	class MsgClusterNodeRecvThread; // Caution: Fail to compile
	//	class MsgClusterLeaderSendThread; // Caution: Fail to compile
	std::list<MsgClusterNodeRecvThread*> client_recv_thread_list;
	MsgClusterLeaderSendThread* client_send_thread;
	int leader_socket;

public:
	MsgClusterLeaderNode(char* ip);
	virtual ~MsgClusterLeaderNode();

// From MsgClusterNodeBase
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short check_keepalive();
// From MsgNotifyObserverInf
	virtual unsigned short update(const char* ip, const char* message);
	virtual unsigned short notify(short notify_type);
};
typedef MsgClusterLeaderNode* PMSG_CLUSTER_LEADER_NODE;

#endif
