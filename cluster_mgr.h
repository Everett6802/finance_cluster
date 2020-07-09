#ifndef CLUSTER_MGR_H
#define CLUSTER_MGR_H

#include <pthread.h>
#include <list>
#include <string>
#include "common.h"
#include "interactive_server.h"
#include "simulator_handler.h"


class ClusterMgr : public IManager
{
	DECLARE_MSG_DUMPER()

	static const char* SERVER_LIST_CONF_FILENAME;
	static const int RETRY_WAIT_CONNECTION_TIME;
	static const int TRY_TIMES;

private:
// config
	std::string cluster_network;
	int cluster_netmask_digits;

	PNOTIFY_THREAD notify_thread;
	char* local_ip;
	char* cluster_ip; // Only for the follower
	NodeType node_type;
	PINODE cluster_node;

// parameters related to session
	InteractiveServer* interactive_server;
	pthread_mutex_t interactive_session_mtx[MAX_INTERACTIVE_SESSION];
	pthread_cond_t interactive_session_cond[MAX_INTERACTIVE_SESSION];
	std::list<PNOTIFY_CFG> interactive_session_data_list[MAX_INTERACTIVE_SESSION];

	SimulatorHandler* simulator_handler;
	bool simulator_installed;

	unsigned short parse_config();
	unsigned short find_local_ip();
	void set_keepalive_timer_interval(int delay=0, int period=0);
	unsigned short start_keepalive_timer();
	void stop_keepalive_timer();
	unsigned short become_leader();
	unsigned short become_follower(bool need_rebuild_cluster=false);
	// unsigned short start_connection();
	unsigned short stop_connection();
	unsigned short rebuild_cluster();
	void check_keepalive();
	void dump_interactive_session_data_list(int session_id)const;

public:
	ClusterMgr();
	~ClusterMgr();

	unsigned short initialize();
	unsigned short deinitialize();
	unsigned short set_cluster_ip(const char* ip);
	unsigned short transmit_text(const char* data, const char* remote_ip=NULL);

	bool is_leader()const{return node_type == LEADER;}
// Interface
// IParam
    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL);
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL);

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};

#endif
