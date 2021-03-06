#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <list>
#include <deque>
#include <string>
#include <map>
#include <vector>
#include <stdexcept>
#include "msg_dumper_wrapper.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro

// This constant is used for allocating array size
#define DEF_VERY_SHORT_STRING_SIZE 		16U
#define DEF_SHORT_STRING_SIZE 			32U
#define DEF_STRING_SIZE 				64U
#define DEF_LONG_STRING_SIZE			256U
#define DEF_VERY_LONG_STRING_SIZE		DEF_LONG_STRING_SIZE * 2

#ifndef CHECK_SUCCESS
#define CHECK_SUCCESS(X) (X == RET_SUCCESS ? true : false)
#endif

#ifndef CHECK_FAILURE
#define CHECK_FAILURE(X) (X >= RET_FAILURE_BASE && X <= RET_FAILURE_END ? true : false)
#endif

#ifndef CHECK_FAILURE_CONNECTION
#define CHECK_FAILURE_CONNECTION(X) (X >= RET_FAILURE_CONNECTION_BASE && X <= RET_FAILURE_CONNECTION_END ? true : false)
#endif

#ifndef CHECK_WARN
#define CHECK_WARN(X) (X >= RET_WARN_BASE && X <= RET_WARN_END ? true : false)
#endif

#ifndef IS_TRY_CONNECTION_TIMEOUT
#define IS_TRY_CONNECTION_TIMEOUT(X) (X == RET_FAILURE_CONNECTION_TRY_TIMEOUT ? true : false)
#endif

#ifndef IS_KEEP_ALIVE_TIMEOUT
#define IS_KEEP_ALIVE_TIMEOUT(X) (X == RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT ? true : false)
#endif

#ifndef PRINT
#define PRINT(...)\
do{\
	if (SHOW_CONSOLE) printf(__VA_ARGS__);\
}while(0)
#endif

#ifndef FPRINT
#define FPRINT(stream, ...)\
do{\
    if (SHOW_CONSOLE) fprintf(stream, __VA_ARGS__);\
}while(0)
#endif

#ifndef FRPINT_ERROR
#define FPRINT_ERROR(...)\
FPRINT(stderr, __VA_ARGS__)
#endif

#ifndef CREATE_PROJECT_FILEPATH
#define CREATE_PROJECT_FILEPATH(variable_name, foldername, filename)\
const int variable_name##_buf_size = 256;\
char variable_name[variable_name##_buf_size];\
do{\
	static const int FILE_PATH_SIZE = 256;\
	char current_working_directory[FILE_PATH_SIZE];\
	getcwd(current_working_directory, FILE_PATH_SIZE);\
	snprintf(variable_name, variable_name##_buf_size, "%s/%s/%s", current_working_directory, foldername, filename);\
}while(0);
#endif

#define MAX_INTERACTIVE_SESSION 5

#ifndef SAFE_RELEASE
#define SAFE_RELEASE(x)\
if (x != NULL)\
{\
	x->release(__FILE__, __LINE__);\
	x = NULL;\
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants

extern const unsigned short VERY_SHORT_STRING_SIZE;
extern const unsigned short SHORT_STRING_SIZE;
extern const unsigned short STRING_SIZE;
extern const unsigned short LONG_STRING_SIZE;
extern const unsigned short VERY_LONG_STRING_SIZE;

// Return values
extern const unsigned short RET_SUCCESS;

extern const unsigned short RET_FAILURE_BASE;
extern const unsigned short RET_FAILURE_UNKNOWN;
extern const unsigned short RET_FAILURE_RUNTIME;
extern const unsigned short RET_FAILURE_INVALID_ARGUMENT;
extern const unsigned short RET_FAILURE_INVALID_POINTER;
extern const unsigned short RET_FAILURE_INSUFFICIENT_MEMORY;
extern const unsigned short RET_FAILURE_INCORRECT_OPERATION;
extern const unsigned short RET_FAILURE_OPEN_FILE;
extern const unsigned short RET_FAILURE_NOT_FOUND;
extern const unsigned short RET_FAILURE_INCORRECT_CONFIG;
extern const unsigned short RET_FAILURE_INCORRECT_PATH;
extern const unsigned short RET_FAILURE_IO_OPERATION;
extern const unsigned short RET_FAILURE_HANDLE_THREAD;
extern const unsigned short RET_FAILURE_SYSTEM_API;
extern const unsigned short RET_FAILURE_INTERNAL_ERROR;
extern const unsigned short RET_FAILURE_END;

extern const unsigned short RET_FAILURE_CONNECTION_BASE;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL;
extern const unsigned short RET_FAILURE_CONNECTION_CLOSE;
extern const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_NO_SERVER;
extern const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE;
extern const unsigned short RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE;
extern const unsigned short RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_END;

extern const unsigned short RET_WARN_BASE;
extern const unsigned short RET_WARN_INTERACTIVE_COMMAND;
extern const unsigned short RET_WARN_SIMULATOR_NOT_INSTALLED;
extern const unsigned short RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND;
extern const unsigned short RET_WARN_FILE_TRANSFER_IN_PROCESS;
extern const unsigned short RET_WARN_END;

const char* GetErrorDescription(unsigned short ret);

extern bool SHOW_CONSOLE;

extern const int MESSAGE_TYPE_LEN;
extern const std::string END_OF_MESSAGE;
extern const int END_OF_MESSAGE_LEN;

extern const int KEEPALIVE_DELAY_TIME;
extern const int KEEPALIVE_PERIOD;
extern const int MAX_KEEPALIVE_CNT;
extern const int MAX_CONNECTED_CLIENT;
// extern const int MAX_INTERACTIVE_SESSION;

extern const char* CONF_FODLERNAME;
extern const char* FINANCE_CLUSTER_CONF_FILENAME;
extern const int CLUSTER_PORT_NO;
extern const int SESSION_PORT_NO;
extern const int FILE_TRANSFER_PORT_NO;
extern const int RECV_BUF_SIZE;

extern const char* CONFIG_FOLDER_NAME;
extern const char* CONF_FIELD_CLUSTER_NETWORK;
extern const char* CONF_FIELD_CLUSTER_NETMASK_DIGITS;

extern const int PAYLOAD_SESSION_ID_DIGITS;
extern const char* PAYLOAD_SESSION_ID_STRING_FORMAT;
extern const int PAYLOAD_CLUSTER_ID_DIGITS;
extern const char* PAYLOAD_CLUSTER_ID_STRING_FORMAT;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Enumeration

enum NodeType{
	LEADER, 
	FOLLOWER, 
	NONE
};

enum MessageType{
	MSG_CAN_NOT_USE = 0, // 0 can NOT use, due to serialization/deserialization
	MSG_CHECK_KEEPALIVE, // Bi-Direction, Leader <-> Follower 
	MSG_UPDATE_CLUSUTER_MAP, // Uni-Direction, Leader -> Follower
	MSG_TRANSMIT_TEXT, // Uni-Direction, Leader -> Follower or Follower -> Leader
	MSG_GET_SYSTEM_INFO, // Bi-Direction, Leader -> Follower, then Follower -> Leader
	MSG_GET_SIMULATOR_VERSION, // Bi-Direction, Leader -> Follower, then Follower -> Leader
	MSG_INSTALL_SIMULATOR, // Uni-Direction, Leader -> Follower
	MSG_APPLY_FAKE_ACSPT_CONFIG, // Uni-Direction, Leader -> Follower
	MSG_APPLY_FAKE_USREPT_CONFIG, // Uni-Direction, Leader -> Follower
	MSG_CONTROL_FAKE_ACSPT, // Uni-Direction, Leader -> Follower
	MSG_CONTROL_FAKE_USREPT, // Uni-Direction, Leader -> Follower
	MSG_GET_FAKE_ACSPT_STATE, // Bi-Direction, Leader -> Follower, then Follower -> Leader
	MSG_REQUEST_FILE_TRANSFER, // Uni-Direction, Leader -> Follower
	MSG_COMPLETE_FILE_TRANSFER, // Bi-Direction, Leader -> Follower, then Follower -> Leader
	MSG_SIZE
};

enum ParamType{
	PARAM_CLUSTER_MAP,
	PARAM_CLUSTER_NODE_COUNT,
	PARAM_CLUSTER_IP2ID,
	PARAM_CLUSTER_ID2IP,
	PARAM_NODE_ID,
	PARAM_CONNECTION_RETRY,
	PARAM_CLUSTER_DETAIL,
	PARAM_SYSTEM_INFO,
	// PARAM_NODE_SYSTEM_INFO,
	PARAM_SIMULATOR_VERSION,
	PARAM_FAKE_ACSPT_CONFIG_VALUE,
	PARAM_FAKE_ACSPT_STATE,
	PARAM_FILE_TRANSFER,
	PARAM_FILE_TRANSFER_DONE,
	// PARAM_NODE_FILE_TRANSFER_DONE,
	PARAM_SIZE
};

// Some NotifyType doesn't need to carry parameters
enum NotifyType{
	NOTIFY_CHECK_KEEPALIVE,
	NOTIFY_NODE_DIE,
	NOTIFY_SESSION_EXIT,
/*	NOTIFY_RECV_DATA,*/
	NOTIFY_GET_SYSTEM_INFO,
	NOTIFY_GET_SIMULATOR_VERSION,
	NOTIFY_INSTALL_SIMULATOR,
	NOTIFY_APPLY_FAKE_ACSPT_CONFIG,
	NOTIFY_APPLY_FAKE_USREPT_CONFIG,
	NOTIFY_CONTROL_FAKE_ACSPT,
	NOTIFY_CONTROL_FAKE_USREPT,
	NOTIFY_GET_FAKE_ACSPT_STATE,
	NOTIFY_ABORT_FILE_TRANSFER,  // Receiver of file transfer
	NOTIFY_COMPLETE_FILE_TRANSFER,  // Sender of file transfer
	NOTIFY_SEND_FILE_DONE,
	NOTIFY_SIZE
};

enum FakeAcsptControlType{
	FAKE_ACSPT_START, 
	FAKE_ACSPT_STOP, 
	FAKE_ACSPT_CONTROL_SIZE
};

enum FakeUsreptControlType{
	FAKE_USREPT_START, 
	FAKE_USREPT_STOP, 
	FAKE_USREPT_CONTROL_SIZE
};

enum UsreptConfigType{
	NORMAL, 
	PKT_PROFILE, 
	WLAN_PROFILE
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro
#define GET_MSG_TYPE(x) int((*x) & 0xFF)

#define UNDEFINED_MSG_EXCEPTION(Node, Direction, message_type)\
do{\
	static int ERRMSG_SIZE = 256;\
    char undefined_errmsg[ERRMSG_SIZE];\
    snprintf(undefined_errmsg, ERRMSG_SIZE, "%s Message[%s:%d] is NOT defined", Node, Direction, message_type);\
    throw std::runtime_error(undefined_errmsg);\
}while(0)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Typedef

typedef std::list<char*> CHAR_LIST;
typedef CHAR_LIST* PCHAR_LIST;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions

unsigned short get_local_interface_ip(std::map<std::string, std::string>& interface_ip_map);
bool check_file_exist(const char* filepath); // folder or file
bool check_config_file_exist(const char* config_filename);
unsigned short get_file_line_count(unsigned int &line_count, const char* filepath);
unsigned short read_file_lines_ex(std::list<std::string>& line_list, const char* filepath, const char* file_read_attribute="r", char data_seperate_character=',', bool ignore_comment=true);
unsigned short read_config_file_lines_ex(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_file_read_attribute, const char* config_folderpath=NULL);
unsigned short read_config_file_lines(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_folderpath=NULL);
unsigned short write_file_lines_ex(const std::list<std::string>& line_list, const char* filepath, const char* file_write_attribute="w", const char* newline_character="\n");
unsigned short get_linux_platform(std::string& linux_distribution);
unsigned short get_system_info(std::string& system_info);
bool check_string_is_number(const char* input);
const char *get_username();
bool is_root_user();
void print_curtime(const char* title=NULL);
const char* pthread_cond_timedwait_err(int ret);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface

class IParam
{
public:
    // virtual ~IParam();

    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL)=0;
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL)=0;
};
typedef IParam* PIPARAM;

class NotifyCfg;

class INotify
{
public:
	virtual unsigned short notify(NotifyType notify_type, void* notify_param=NULL)=0;
	virtual unsigned short async_handle(NotifyCfg* notify_cfg)=0;
};
typedef INotify* PINOTIFY;

class INode : public IParam, public INotify
{
public:
	virtual ~INode(){}

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short recv(MessageType message_type, const std::string& message_data)=0;
	virtual unsigned short send(MessageType message_type, void* param1=NULL, void* param2=NULL, void* param3=NULL)=0;
};
typedef INode* PINODE;

class IManager : public IParam, public INotify
{
public:
	virtual ~IManager(){}
};
typedef IManager* PIMANAGER;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Class

class IPv4Addr
{
public:
	static unsigned short ipv4_value2str(const unsigned char ipv4_value[], char** ipv4_str);
	static unsigned short ipv4_str2value(const char* ipv4_str, unsigned char ipv4_value[]);
	static unsigned short get_netmask(int netmask_digits, unsigned char ipv4_mask[]);
	static unsigned short get_network(const unsigned char ipv4_value[], int netmask_digits, unsigned char ipv4_network[]);

private:
	unsigned char addr_value[4];
	char* addr_str;

public:
	IPv4Addr(unsigned char ipv4_value[]);
	IPv4Addr(const char* ipv4_str);

	~IPv4Addr();

	bool is_same_network(int netmask_digits, unsigned char ipv4_network[])const;
	bool is_same_network(int netmask_digits, const char* ipv4_network_str)const;
};

///////////////////////////////////////////////////

class NodeMessageAssembler
{
private:
	char* full_message_buf;

public:
	NodeMessageAssembler();
	~NodeMessageAssembler();

	unsigned short assemble(MessageType message_type, const char* message=NULL);

    const char* get_full_message()const;
};

class NodeMessageParser
{
private:
	bool full_message_found;
	std::string data_buffer;
	size_t data_end_pos;
	MessageType message_type;

public:
	NodeMessageParser();
	~NodeMessageParser();

	unsigned short parse(const char* new_message);
	unsigned short remove_old();

	bool is_cur_message_empty()const;
	const char* cur_get_message()const;
    const char* get_message()const;
    MessageType get_message_type()const;
};

///////////////////////////////////////////////////

class ClusterNode
{
public:
	int node_id;
	std::string node_ip;

	ClusterNode(int id, std::string ip);

    // friend bool operator== (const ClusterNode &n1, const ClusterNode &n2);
    // friend bool operator== (const ClusterNode* p1, const ClusterNode* p2);
    bool operator== (const ClusterNode &n);
    bool operator== (const ClusterNode* p);
    // bool operator== (const ClusterNode* p1, const ClusterNode* p2);	
};
typedef ClusterNode* PCLUSTER_NODE;
typedef std::list<ClusterNode*>::iterator CLUSTER_NODE_ITER;

// bool operator== (const ClusterNode &n1, const ClusterNode &n2); 
// bool operator== (const ClusterNode* p1, const ClusterNode* p2);

///////////////////////////////////////////////////

class ClusterMap
{
private:
	std::list<ClusterNode*> cluster_map;
	char* cluster_map_str;

	void reset_cluster_map_str();

public:
	ClusterMap();
	~ClusterMap();

	class const_iterator
	{
	private:
		CLUSTER_NODE_ITER iter;

	public:
		const_iterator(CLUSTER_NODE_ITER iterator);
		const_iterator operator++();
		bool operator==(const const_iterator& another);
		bool operator!=(const const_iterator& another);
		const ClusterNode* operator->();
		const ClusterNode& operator*();
	};

	const_iterator begin();
	const_iterator end();

    size_t size()const;
    bool is_empty()const;
    unsigned short copy(const ClusterMap& another_cluster_map);
	unsigned short add_node(int node_id, std::string node_ip);
	unsigned short add_node(const char* node_id_ip_str);
	unsigned short delete_node(int node_id);
	unsigned short delete_node_by_ip(std::string node_ip);
	unsigned short pop_node(ClusterNode** first_node);
	unsigned short cleanup_node();
	unsigned short get_first_node(int& first_node_id, std::string& first_node_ip, bool peek_only=false);
	unsigned short get_first_node_ip(std::string& first_node_ip, bool peek_only=false);
	unsigned short get_node_id(const std::string& node_ip, int& node_id);
	unsigned short get_last_node_id(int& node_id);
	unsigned short get_node_ip(int node_id, std::string& node_ip);
	const char* to_string();
	unsigned short from_string(const char* cluster_map_str);
	// unsigned short from_object(const ClusterMap& cluster_map_obj);
};

///////////////////////////////////////////////////

class KeepaliveTimerTask
{
//	DECLARE_MSG_DUMPER()
private:
	PINOTIFY notify_observer;

public:
	KeepaliveTimerTask();
	~KeepaliveTimerTask();

	unsigned short initialize(PINOTIFY observer);
	unsigned short deinitialize();
	unsigned short trigger();
};

///////////////////////////////////////////////////

class ClusterDetailParam
{
public:
	NodeType node_type;
	int node_id;
	char local_ip[16];
	char cluster_ip[16];
	ClusterMap cluster_map;

	ClusterDetailParam();
	~ClusterDetailParam();
};
typedef ClusterDetailParam* PCLUSTER_DETAIL_PARAM;

class SystemInfoParam
{
public:
	int session_id;
	char node_ip_buf[DEF_VERY_SHORT_STRING_SIZE]; // the string of node ip or id
	std::string system_info;

	SystemInfoParam();
	~SystemInfoParam();
};
typedef SystemInfoParam* PSYSTEM_INFO_PARAM;

class ClusterSystemInfoParam
{
public:
	int session_id;
// (cluster id, system info)
	std::map<int, std::string> clusuter_system_info_map;

	ClusterSystemInfoParam();
	~ClusterSystemInfoParam();

};
typedef ClusterSystemInfoParam* PCLUSTER_SYSTEM_INFO_PARAM;

class SimulatorVersionParam
{
public:
	int simulator_version_buf_size;
	char* simulator_version;

	SimulatorVersionParam(int simulator_version_bufsize=DEF_VERY_SHORT_STRING_SIZE);
	~SimulatorVersionParam();
};
typedef SimulatorVersionParam* PSIMULATOR_VERSION_PARAM;

class ClusterSimulatorVersionParam
{
public:
	int session_id;
// (cluster id, simulator version)
	std::map<int, std::string> clusuter_simulator_version_map;

	ClusterSimulatorVersionParam();
	~ClusterSimulatorVersionParam();

};
typedef ClusterSimulatorVersionParam* PCLUSTER_SIMULATOR_VERSION_PARAM;

class FakeAcsptStateParam
{
public:
	int fake_acspt_state_buf_size;
	char* fake_acspt_state;

	FakeAcsptStateParam(int fake_acspt_state_bufsize=DEF_VERY_LONG_STRING_SIZE);
	~FakeAcsptStateParam();
};
typedef FakeAcsptStateParam* PFAKE_ACSPT_STATE_PARAM;

class ClusterFakeAcsptStateParam
{
public:
	int session_id;
// (cluster id, fake acspt state)
	std::map<int, std::string> cluster_fake_acspt_state_map;

	ClusterFakeAcsptStateParam();
	~ClusterFakeAcsptStateParam();

};
typedef ClusterFakeAcsptStateParam* PCLUSTER_FAKE_ACSPT_STATE_PARAM;

class FileTransferParam
{
public:
	int session_id;
	char* filepath;

	FileTransferParam();
	~FileTransferParam();
};
typedef FileTransferParam* PFILE_TRANSFER_PARAM;

class ClusterFileTransferParam
{
public:
	int session_id;
// (cluster id, system info)
	std::map<int, std::string> clusuter_file_transfer_map;

	ClusterFileTransferParam();
	~ClusterFileTransferParam();

};
typedef ClusterFileTransferParam* PCLUSTER_FILE_TRANSFER_PARAM;

class FakeAcsptConfigValueParam
{
public:
	std::list<std::string> config_list;
	std::list<std::string> config_line_list;

	FakeAcsptConfigValueParam();
	~FakeAcsptConfigValueParam();
};
typedef FakeAcsptConfigValueParam* PFAKE_ACSPT_CONFIG_VALUE_PARAM;

///////////////////////////////////////////////////

class NotifyCfg
{
protected:
	NotifyType notify_type;
	void* notify_param;
	int ref_count;

public:
	NotifyCfg(NotifyType type, const void* param=NULL, size_t param_size=0);
	virtual ~NotifyCfg();

	int addref(const char* callable_file_name, unsigned long callable_line_no);
	int release(const char* callable_file_name, unsigned long callable_line_no);
	int getref()const;

	NotifyType get_notify_type()const;
	const void* get_notify_param()const;
};
typedef NotifyCfg* PNOTIFY_CFG;

///////////////////////////

class NotifyNodeDieCfg : public NotifyCfg
{
private:
	char* remote_ip;

public:
	NotifyNodeDieCfg(const void* param, size_t param_size);
	virtual ~NotifyNodeDieCfg();

	const char* get_remote_ip()const;
};
typedef NotifyNodeDieCfg* PNOTIFY_NODE_DIE_CFG;

///////////////////////////

class NotifySessionExitCfg : public NotifyCfg
{
private:
	int session_id;

public:
	NotifySessionExitCfg(const void* param, size_t param_size);
	virtual ~NotifySessionExitCfg();

	int get_session_id()const;
};
typedef NotifySessionExitCfg* PNOTIFY_SESSION_EXIT_CFG;

///////////////////////////

class NotifySystemInfoCfg : public NotifyCfg
{
private:
	int session_id;
	int cluster_id;
	char* system_info;

public:
	NotifySystemInfoCfg(const void* param, size_t param_size);
	virtual ~NotifySystemInfoCfg();

	int get_session_id()const;
	int get_cluster_id()const;
	const char* get_system_info()const;
};
typedef NotifySystemInfoCfg* PNOTIFY_SYSTEM_INFO_CFG;

///////////////////////////////////////////////////

class NotifySimulatorVersionCfg : public NotifyCfg
{
private:
	int session_id;
	int cluster_id;
	char* simulator_version;

public:
	NotifySimulatorVersionCfg(const void* param, size_t param_size);
	virtual ~NotifySimulatorVersionCfg();

	int get_session_id()const;
	int get_cluster_id()const;
	const char* get_simulator_version()const;
};
typedef NotifySimulatorVersionCfg* PNOTIFY_SIMULATOR_VERSION_CFG;

///////////////////////////////////////////////////

class NotifySimulatorInstallCfg : public NotifyCfg
{
private:
	char* simulator_package_filepath;

public:
	NotifySimulatorInstallCfg(const void* param, size_t param_size);
	virtual ~NotifySimulatorInstallCfg();

	const char* get_simulator_package_filepath()const;
};
typedef NotifySimulatorInstallCfg* PNOTIFY_SIMULATOR_INSTALL_CFG;

///////////////////////////////////////////////////

class NotifyFakeAcsptConfigApplyCfg : public NotifyCfg
{
private:
	char* fake_acspt_config_line_list_str;

public:
	NotifyFakeAcsptConfigApplyCfg(const void* param, size_t param_size);
	virtual ~NotifyFakeAcsptConfigApplyCfg();

	const char* get_fake_acspt_config_line_list_str()const;
};
typedef NotifyFakeAcsptConfigApplyCfg* PNOTIFY_FAKE_ACSPT_CONFIG_APPLY_CFG;

///////////////////////////////////////////////////

class NotifyFakeUsreptConfigApplyCfg : public NotifyCfg
{
private:
	char* fake_usrept_config_line_list_str;

public:
	NotifyFakeUsreptConfigApplyCfg(const void* param, size_t param_size);
	virtual ~NotifyFakeUsreptConfigApplyCfg();

	const char* get_fake_usrept_config_line_list_str()const;
};
typedef NotifyFakeUsreptConfigApplyCfg* PNOTIFY_FAKE_USREPT_CONFIG_APPLY_CFG;

///////////////////////////

class NotifyFakeAcsptControlCfg : public NotifyCfg
{
private:
	FakeAcsptControlType fake_acspt_control_type;

public:
	NotifyFakeAcsptControlCfg(const void* param, size_t param_size);
	virtual ~NotifyFakeAcsptControlCfg();

	FakeAcsptControlType get_fake_acspt_control_type()const;
};
typedef NotifyFakeAcsptControlCfg* PNOTIFY_FAKE_ACSPT_CONTROL_CFG;

///////////////////////////////////////////////////

class NotifyFakeUsreptControlCfg : public NotifyCfg
{
private:
	FakeUsreptControlType fake_usrept_control_type;

public:
	NotifyFakeUsreptControlCfg(const void* param, size_t param_size);
	virtual ~NotifyFakeUsreptControlCfg();

	FakeUsreptControlType get_fake_usrept_control_type()const;
};
typedef NotifyFakeUsreptControlCfg* PNOTIFY_FAKE_USREPT_CONTROL_CFG;

///////////////////////////////////////////////////

class NotifyFakeAcsptStateCfg : public NotifyCfg
{
private:
	int session_id;
	int cluster_id;
	char* fake_acspt_state;

public:
	NotifyFakeAcsptStateCfg(const void* param, size_t param_size);
	virtual ~NotifyFakeAcsptStateCfg();

	int get_session_id()const;
	int get_cluster_id()const;
	const char* get_fake_acspt_state()const;
};
typedef NotifyFakeAcsptStateCfg* PNOTIFY_FAKE_ACSPT_STATE_CFG;

///////////////////////////

class NotifyFileTransferAbortCfg : public NotifyCfg
{
private:
	char* remote_ip;

public:
	NotifyFileTransferAbortCfg(const void* param, size_t param_size);
	virtual ~NotifyFileTransferAbortCfg();

	const char* get_remote_ip()const;
};
typedef NotifyFileTransferAbortCfg* PNOTIFY_FILE_TRANSFER_ABORT_CFG;

///////////////////////////

class NotifyFileTransferCompleteCfg : public NotifyCfg
{

private:
	int session_id;
	int cluster_id;
	unsigned short return_code;

public:
	NotifyFileTransferCompleteCfg(const void* param, size_t param_size);
	virtual ~NotifyFileTransferCompleteCfg();

	int get_session_id()const;
	int get_cluster_id()const;
	unsigned short get_return_code()const;
};
typedef NotifyFileTransferCompleteCfg* PNOTIFY_FILE_TRANSFER_COMPLETE_CFG;

///////////////////////////

class NotifySendFileDoneCfg : public NotifyCfg
{
private:
	char* remote_ip;

public:
	NotifySendFileDoneCfg(const void* param, size_t param_size);
	virtual ~NotifySendFileDoneCfg();

	const char* get_remote_ip()const;
};
typedef NotifySendFileDoneCfg* PNOTIFY_SEND_FILE_DONE_CFG;

///////////////////////////////////////////////////

class NotifyThread
{
	DECLARE_MSG_DUMPER()
	static const char* default_notify_thread_tag;

private:
	PINOTIFY notify_observer;

	volatile int notify_exit;
	pthread_t notify_tid;
	volatile unsigned short notify_thread_ret;
	bool new_notify_trigger;
	char* notify_thread_tag;

	std::vector<PNOTIFY_CFG> notify_buffer_vector;
	std::vector<PNOTIFY_CFG> notify_execute_vector;

	pthread_mutex_t notify_mtx;
	pthread_cond_t notify_cond;

	static void* notify_thread_handler(void* pvoid);
	unsigned short notify_thread_handler_internal();
	static void notify_thread_cleanup_handler(void* pvoid);
	void notify_thread_cleanup_handler_internal();

public:
	NotifyThread(PINOTIFY observer, const char* thread_tag=NULL);
	~NotifyThread();

	unsigned short initialize();
	unsigned short deinitialize();
	unsigned short add_event(const PNOTIFY_CFG notify_cfg);
};
typedef NotifyThread* PNOTIFY_THREAD;

#endif
