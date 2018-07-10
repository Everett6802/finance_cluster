#ifndef CLUSTER_MGR_H
#define CLUSTER_MGR_H

#include <pthread.h>
#include <list>
#include <string>
#include "common.h"


class NodeBase;

class ClusterMgr : public MsgNotifyObserverInf
{
	enum NodeType{LEADER, FOLLOWER, NONE};
	DECLARE_MSG_DUMPER()

	static const char* SERVER_LIST_CONF_FILENAME;
	static const int RETRY_WAIT_CONNECTION_TIME;
	static const int TRY_TIMES;

private:
// config
	std::string cluster_network;
	int cluster_netmask_digits;

	char* local_ip;
// Only for the follower
	char* cluster_ip;
	// std::list<char*> cluster_list;
	NodeType node_type;
	NodeBase* cluster_node;
	PMSG_TRANSFER_INF msg_trasnfer;
	pthread_t pid;
	unsigned short runtime_ret;
	pthread_mutex_t mtx_runtime_ret;
	pthread_cond_t cond_runtime_ret;

	unsigned short parse_config();

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
	void check_keepalive();
	void notify_exit(unsigned short exit_reason);

	static void* thread_handler(void* pvoid);
	unsigned short thread_handler_internal();

protected:


public:
	ClusterMgr();
	~ClusterMgr();

	unsigned short set_cluster_ip(const char* ip);


	bool is_leader()const{return node_type == LEADER;}
	unsigned short start();
	unsigned short wait_to_stop();
// From MsgNotifyObserverInf
	virtual unsigned short update(const std::string ip, const std::string message){return RET_FAILURE_INCORRECT_OPERATION;}
	virtual unsigned short notify(NotifyType notify_type);
};

#endif
