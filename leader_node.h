#ifndef LEADER_NODE_H
#define LEADER_NODE_H

#include <pthread.h>
#include <vector>
#include <deque>
#include <string>
#include "common.h"
#include "node_base.h"
#include "node_channel.h"
#include "file_channel.h"


class LeaderNode : public INode
{
	DECLARE_MSG_DUMPER()

private:
	static const char* listen_thread_tag;
	static const char* tx_listen_thread_tag;
	static const int WAIT_CONNECTION_TIMEOUT;

	PIMANAGER observer;
	int socketfd;
	int tx_socketfd; // For file transfer
	char* local_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_id;
	int cluster_node_cnt;
	ClusterMap cluster_map;
	PNOTIFY_THREAD notify_thread;

	volatile int listen_exit;
	pthread_t listen_tid;
	volatile unsigned short listen_thread_ret;
// For file transfer
	pthread_mutex_t tx_mtx;
	volatile int tx_listen_exit;
	pthread_t tx_listen_tid;
	volatile unsigned short tx_listen_thread_ret;
	int tx_session_id;
	char* tx_filepath;

	// std::deque<PNODE_CHANNEL> node_channel_deque;
	std::map<std::string, PNODE_CHANNEL> node_channel_map;
	std::map<std::string, int> node_keepalive_map;
	std::map<std::string, PFILE_CHANNEL> file_channel_map;

	pthread_mutex_t node_channel_mtx;
	pthread_mutex_t file_channel_mtx;
	// pthread_mutex_t mtx_cluster_map;

	unsigned short become_leader();
	unsigned short send_data(MessageType message_type, const char* data=NULL, const char* remote_ip=NULL);
	unsigned short remove_follower(const std::string& node_ip);
	unsigned short remove_file_channel(const std::string& node_ip);
	unsigned short become_file_sender();
	unsigned short start_file_transfer();
	unsigned short stop_file_transfer();
// events
// recv
	unsigned short recv_check_keepalive(const std::string& message_data);
	unsigned short recv_update_cluster_map(const std::string& message_data);
	unsigned short recv_transmit_text(const std::string& message_data);
	unsigned short recv_get_system_info(const std::string& message_data);
	unsigned short recv_get_simulator_version(const std::string& message_data);
	unsigned short recv_install_simulator(const std::string& message_data);
	unsigned short recv_apply_fake_acspt_config(const std::string& message_data);
	unsigned short recv_control_fake_acspt(const std::string& message_data);
	unsigned short recv_control_fake_usrept(const std::string& message_data);
	unsigned short recv_get_fake_acspt_state(const std::string& message_data);
	unsigned short recv_request_file_transfer(const std::string& message_data);
	unsigned short recv_complete_file_transfer(const std::string& message_data);
// send
	unsigned short send_check_keepalive(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_update_cluster_map(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_transmit_text(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_system_info(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_simulator_version(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_install_simulator(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_apply_fake_acspt_config(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_control_fake_acspt(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_control_fake_usrept(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_get_fake_acspt_state(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_request_file_transfer(void* param1=NULL, void* param2=NULL, void* param3=NULL);
	unsigned short send_complete_file_transfer(void* param1=NULL, void* param2=NULL, void* param3=NULL);

	void dump_node_channel_map()const;
	void dump_node_keepalive_map()const;

	static void* listen_thread_handler(void* pvoid);
	unsigned short listen_thread_handler_internal();
	static void listen_thread_cleanup_handler(void* pvoid);
	void listen_thread_cleanup_handler_internal();

	static void* tx_listen_thread_handler(void* pvoid);
	unsigned short tx_listen_thread_handler_internal();
	static void tx_listen_thread_cleanup_handler(void* pvoid);
	void tx_listen_thread_cleanup_handler_internal();

public:
	LeaderNode(PIMANAGER parent, const char* ip);
	virtual ~LeaderNode();

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
typedef LeaderNode* PLEADER_NODE;

#endif
