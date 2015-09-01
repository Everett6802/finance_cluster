#ifndef MSG_CLUSTER_MGR_H
#define MSG_CLUSTER_MGR_H

#include <pthread.h>
#include <list>
#include <string>
#include "msg_cluster_common.h"


class MsgClusterNodeBase;

class MsgClusterMgr : public MsgNotifyObserverInf
{
	enum NodeType{LEADER, FOLLOWER, NONE};
	DECLARE_MSG_DUMPER()

	static const char* SERVER_LIST_CONF_FILENAME;
	static const int RETRY_WAIT_CONNECTION_TIME;
	static const int TRY_TIMES;

private:
	std::list<char*> server_list;
	char* local_ip;
	PMSG_TRANSFER_INF msg_trasnfer;
	MsgClusterNodeBase* msg_cluster_node;
	pthread_t t;
	unsigned short runtime_ret;

	unsigned short find_local_ip();
	void set_keepalive_timer_interval(int delay=0, int period=0);
	unsigned short start_keepalive_timer();
	void stop_keepalive_timer();
	unsigned short become_leader();
	unsigned short become_follower();
	unsigned short start_connection();
	unsigned short stop_connection();
	unsigned short try_reconnection();
	unsigned short initialize();
	unsigned short deinitialize();

protected:
	NodeType node_type;

	void check_keepalive();
	void notify_exit(unsigned short exit_reason);

public:
	MsgClusterMgr();
	~MsgClusterMgr();

	bool is_leader()const{return node_type == LEADER;}
	unsigned short start();
	unsigned short wait_to_stop();
// From MsgNotifyObserverInf
	virtual unsigned short update(const char* ip, const std::string message){}
	virtual unsigned short notify(NotifyType notify_type);
};

#endif
