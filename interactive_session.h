#ifndef INTERACTIVE_SESSION_H
#define INTERACTIVE_SESSION_H

// This header file contains definitions of a number of data types used in system calls. These types are used in the next two include files.
#include <sys/types.h> 
// The header file socket.h includes a number of definitions of structures needed for sockets.
#include <sys/socket.h>
// The header file in.h contains constants and structures needed for internet domain addresses.
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include "common.h"

#define SESSION_TAG_SIZE 64


class InteractiveSession : public INotify
{
	DECLARE_MSG_DUMPER()
	DECLARE_EVT_RECORDER()

private:
	static const int REQ_BUF_SIZE;
	static const int RSP_BUF_VERY_SHORT_SIZE;
	static const int RSP_BUF_SHORT_SIZE;
	static const int RSP_BUF_SIZE;
	static const int RSP_BUF_LONG_SIZE;
	static const int RSP_BUF_VERY_LONG_SIZE;
	static const int MAX_ARGC;

	// static const char* session_thread_tag;
	static const int WAIT_SESSION_TIMEOUT;

	static void init_command_map();

	PINOTIFY observer; // To InteractiveServer
	PIMANAGER manager; // To ClusterMgr

	volatile int session_exit;
	pthread_t session_tid;
	volatile unsigned short session_thread_ret;
	pthread_t multi_clis_tid;
	volatile unsigned short multi_clis_thread_ret;
	char* multi_clis_filepath;

	int sock_fd;
	sockaddr_in sock_addr;
	char session_tag[64];
	int session_id;
	bool is_root;
	bool is_leader;
	char* node_token;
	unsigned char authority_mask;
	bool system_monitor;
	PMONITOR_SYSTEM_TIMER_THREAD monitor_system_timer_thread;
	int system_monitor_period;

	bool check_command_authority(int command_type);
	unsigned short get_complete_sync_folderpath(std::string& complete_sync_folderpath)const;

	static void* session_thread_handler(void* void_tr);
	unsigned short session_thread_handler_internal();
	static void* multi_clis_thread_handler(void* void_tr);
	unsigned short multi_clis_thread_handler_internal();
	static void multi_clis_thread_cleanup_handler(void* pvoid);
	void multi_clis_thread_cleanup_handler_internal();

	// unsigned short print_single_stock_support_resistance_string(const char* stock_support_resistance_entry, int stock_support_resistance_entry_len);
	// void reset_search_param();
// Handle command related fundtions
	unsigned short handle_command(int argc, char **argv);
	unsigned short handle_help_command(int argc, char **argv);
	unsigned short handle_exit_command(int argc, char **argv);
	unsigned short handle_get_role_command(int argc, char **argv);
	unsigned short handle_get_cluster_detail_command(int argc, char **argv);
	unsigned short handle_get_system_info_command(int argc, char **argv);
	unsigned short handle_search_event_command(int argc, char **argv);
	// unsigned short handle_get_node_system_info_command(int argc, char **argv);
	unsigned short handle_get_configuration_setup_command(int argc, char **argv);
	unsigned short handle_start_system_monitor_command(int argc, char **argv);
	unsigned short handle_stop_system_monitor_command(int argc, char **argv);
	unsigned short handle_sync_folder_command(int argc, char **argv);
	unsigned short handle_sync_file_command(int argc, char **argv);
	unsigned short handle_get_simulator_version_command(int argc, char **argv);
	unsigned short handle_trasnfer_simulator_package_command(int argc, char **argv);
	unsigned short handle_install_simulator_command(int argc, char **argv);
	unsigned short handle_apply_fake_acspt_config_command(int argc, char **argv);
	unsigned short handle_get_fake_acspt_config_value_command(int argc, char **argv);
	unsigned short handle_apply_fake_usrept_config_command(int argc, char **argv);
	unsigned short handle_start_fake_acspt_command(int argc, char **argv);
	unsigned short handle_stop_fake_acspt_command(int argc, char **argv);
	unsigned short handle_start_fake_usrept_command(int argc, char **argv);
	unsigned short handle_stop_fake_usrept_command(int argc, char **argv);
	unsigned short handle_get_fake_acspt_state_command(int argc, char **argv);
	unsigned short handle_get_fake_acspt_detail_command(int argc, char **argv);
	unsigned short handle_run_multi_clis_command(int argc, char **argv);
	unsigned short handle_switch_leader_command(int argc, char **argv);
	unsigned short handle_remove_follower_command(int argc, char **argv);
	unsigned short print_to_console(const std::string& response)const;
	unsigned short print_prompt_to_console()const;

public:
	InteractiveSession(PINOTIFY notify, PIMANAGER mgr, int client_fd, const sockaddr_in& sock_addraddress, int interactive_session_id);
	~InteractiveSession();

	unsigned short initialize(int system_monitor_period_value);
	unsigned short deinitialize();
	const char* get_session_tag()const;
	unsigned short print_console(const std::string& console_string)const;

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef InteractiveSession* PINTERACTIVE_SESSION;

#endif
