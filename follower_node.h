#ifndef FOLLOWER_NODE_H
#define FOLLOWER_NODE_H

// #include <pthread.h>
#include <string>
#include "common.h"
#include "node_base.h"
#include "node_channel.h"
#include "file_channel.h"


class FollowerNode : public INode
{
	DECLARE_MSG_DUMPER()

private:
	static const int WAIT_CONNECTION_TIMEOUT; // 5 seconds
	static const int TRY_CONNECTION_TIMES;
	static const int TRY_CONNECTION_SLEEP_TIMES;
	static const int CHECK_KEEPALIVE_TIMES;
	static const int TOTAL_KEEPALIVE_PERIOD;

	// CHAR_LIST server_list;
	PIMANAGER observer;
	int socketfd;
	int tx_socketfd; // For file transfer
	char* local_ip;
	char* cluster_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_id;
	ClusterMap cluster_map;
	int keepalive_cnt;
	bool connection_retry;
	PNODE_CHANNEL node_channel;
	PNOTIFY_THREAD notify_thread;
	PFILE_CHANNEL file_channel;

	pthread_mutex_t cluster_map_mtx;
	pthread_mutex_t node_channel_mtx;

	unsigned short connect_leader();
	unsigned short become_follower();
	unsigned short connect_file_sender();
	unsigned short send_data(MessageType message_type, const char* data=NULL);
// events
// recv
	unsigned short recv_check_keepalive(const std::string& message_data);
	unsigned short recv_update_cluster_map(const std::string& message_data);//{UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_UPDATE_CLUSUTER_MAP);}
	unsigned short recv_transmit_text(const std::string& message_data);
	unsigned short recv_get_system_info(const std::string& message_data);
	unsigned short recv_get_simulator_version(const std::string& message_data);
	unsigned short recv_install_simulator(const std::string& message_data);
	unsigned short recv_apply_fake_acspt_config(const std::string& message_data);
	unsigned short recv_apply_fake_usrept_config(const std::string& message_data);
	unsigned short recv_control_fake_acspt(const std::string& message_data);
	unsigned short recv_control_fake_usrept(const std::string& message_data);
	unsigned short recv_get_fake_acspt_state(const std::string& message_data);
	unsigned short recv_request_file_transfer(const std::string& message_data);
	unsigned short recv_complete_file_transfer(const std::string& message_data);
// send
	unsigned short send_check_keepalive(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_update_cluster_map(void* param1=NULL, void* param2=NULL, void* param3=NULL); //{UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_UPDATE_CLUSUTER_MAP);}
	unsigned short send_transmit_text(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_system_info(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_simulator_version(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_install_simulator(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_apply_fake_acspt_config(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_apply_fake_usrept_config(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_control_fake_acspt(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_control_fake_usrept(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_fake_acspt_state(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_request_file_transfer(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_complete_file_transfer(void* param1=NULL, void* param2=NULL, void* param3=NULL);

public:
	FollowerNode(PIMANAGER parent, const char* server_ip, const char* ip);
	virtual ~FollowerNode();

// Interface
// INode
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
	virtual unsigned short recv(MessageType message_type, const std::string& message_data);
	virtual unsigned short send(MessageType message_type, void* param1=NULL, void* param2=NULL, void* param3=NULL);
// IParam
    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL);
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL);
// INotify
    virtual unsigned short notify(NotifyType notify_type, void* notify_param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef FollowerNode* PFOLLOWER_NODE;

#endif
