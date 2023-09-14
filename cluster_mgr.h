#ifndef CLUSTER_MGR_H
#define CLUSTER_MGR_H

#include <pthread.h>
#include <list>
#include <string>
#include "common.h"
#include "interactive_server.h"
#include "simulator_handler.h"
#include "system_operator.h"


class ClusterMgr : public IManager
{
	DECLARE_MSG_DUMPER()

	static const char* SERVER_LIST_CONF_FILENAME;
	static const int WAIT_RETRY_CONNECTION_TIME;
	static const int TRY_TIMES;
	static const int WAIT_MESSAGE_RESPONSE_TIME;
	static const int WAIT_FILE_TRANSFER_TIME;

	struct InteractiveSessionConcurrentParam
	{
		pthread_mutex_t mtx; 
		pthread_cond_t cond;
		std::list<PNOTIFY_CFG> data_list;
		int event_count;
		int follower_node_amount;
	};

private:
// config
	std::string cluster_network;
	int cluster_netmask_digits;
	bool local_cluster;
	int system_monitor_period;
	std::string sync_folderpath;

	PNOTIFY_THREAD notify_thread;
	char* local_token;
	char* cluster_token; // Only for the follower
	NodeType node_type;
	PINODE cluster_node;
	FileTxType file_tx_type;
	PIFILETX file_tx;

// parameters related to session
	InteractiveServer* interactive_server;
	InteractiveSessionConcurrentParam interactive_session_param[MAX_INTERACTIVE_SESSION];

	SimulatorHandler* simulator_handler;
	bool simulator_installed;

	SystemOperator* system_operator;

	unsigned short parse_config();
	bool check_interface_exist(const char* network_interface)const;
	unsigned short find_local_ip(bool need_check_network=false);
	void set_keepalive_timer_interval(int delay=0, int period=0);
	unsigned short start_keepalive_timer();
	void stop_keepalive_timer();
	unsigned short become_leader();
	unsigned short become_follower(bool need_rebuild_cluster=false);
	unsigned short become_file_sender();
	unsigned short become_file_receiver();
	// unsigned short start_connection();
	unsigned short stop_connection();
	unsigned short rebuild_cluster(int new_leader_node_id=-1);
	unsigned short initialize_components(unsigned short component_mask);
	unsigned short deinitialize_components(unsigned short component_mask);
	void check_keepalive();
	void dump_interactive_session_data_list(int session_id)const;
	unsigned short close_console();

public:
	ClusterMgr();
	~ClusterMgr();

	unsigned short initialize();
	unsigned short deinitialize();
	unsigned short set_cluster_token(const char* token=NULL);
	unsigned short is_local_follower(bool& local_follower)const;
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
