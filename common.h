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
#include <stdexcept>
#include "msg_dumper_wrapper.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro

// This constant is used for allocating array size
#define DEF_SHORT_STRING_SIZE 			32U
#define DEF_STRING_SIZE 				64U
#define DEF_LONG_STRING_SIZE			256U
#define DEF_EX_LONG_STRING_SIZE		LONG_STRING_SIZE * 2

#ifndef CHECK_SUCCESS
#define CHECK_SUCCESS(X) (X == RET_SUCCESS ? true : false)
#endif

#ifndef CHECK_FAILURE
#define CHECK_FAILURE(X) !CHECK_SUCCESS(X)
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants

extern const unsigned short SHORT_STRING_SIZE;
extern const unsigned short STRING_SIZE;
extern const unsigned short LONG_STRING_SIZE;
extern const unsigned short EX_LONG_STRING_SIZE;

// Return values
extern const unsigned short RET_SUCCESS;

extern const unsigned short RET_FAILURE_UNKNOWN;
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

extern const unsigned short RET_FAILURE_CONNECTION_BASE;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL;
extern const unsigned short RET_FAILURE_CONNECTION_CLOSE;
extern const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_NO_SERVER;
extern const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE;

const char* GetErrorDescription(unsigned short ret);

extern bool SHOW_CONSOLE;

// extern const char* CHECK_KEEPALIVE_TAG;
// extern const std::string CHECK_SERVER_CANDIDATE_TAG;
// extern const int CHECK_KEEPALIVE_TAG_LEN;
// extern const int CHECK_SERVER_CANDIDATE_TAG_LEN;
extern const char* END_OF_PACKET;
extern const int KEEPALIVE_DELAY_TIME;
extern const int KEEPALIVE_PERIOD;
extern const int MAX_KEEPALIVE_CNT;
extern const int MAX_CONNECTED_CLIENT;

extern const char* CONF_FODLERNAME;
extern const char* FINANCE_CLUSTER_CONF_FILENAME;
extern const int PORT_NO;
extern const int RECV_BUF_SIZE;

extern const char* CONFIG_FOLDER_NAME;
extern const char* CONF_FIELD_CLUSTER_NETWORK;
extern const char* CONF_FIELD_CLUSTER_NETMASK_DIGITS;

//extern const unsigned short NOTIFY_DEAD_CLIENT;
//extern const unsigned short NOTIFY_CHECK_KEEPALIVE;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Enumeration

enum MessageType{MSG_CHECK_KEEPALIVE, MSG_UPDATE_CLUSTER_MAP, MSG_SIZE};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro
#define GET_MSG_TYPE(x) int((*x) & 0xFF)


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Typedef

typedef std::list<char*> CHAR_LIST;
typedef CHAR_LIST* PCHAR_LIST;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions

unsigned short get_local_interface_ip(std::map<std::string, std::string>& interface_ip_map);
bool check_file_exist(const char* filepath);
bool check_config_file_exist(const char* config_filename);
unsigned short get_file_line_count(unsigned int &line_count, const char* filepath);
unsigned short read_file_lines_ex(std::list<std::string>& line_list, const char* filepath, const char* file_read_attribute, char data_seperate_character=',');
unsigned short read_config_file_lines_ex(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_file_read_attribute, const char* config_folderpath=NULL);
unsigned short read_config_file_lines(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_folderpath=NULL);


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface

class IMsgObserver
{
public:
	virtual unsigned short recv(MessageType message_type, const str::string& message_data)=0;
	virtual unsigned short send(MessageType message_type, void* param1=NULL, void* param2=NULL, void* param3=NULL)=0;
};
typedef IMsgObserver* PIMSG_OBSERVER;

class INode : public IMsgObserver
{
public:
	virtual ~INode();

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
};
typedef INode* PINODE;

// class MsgTransferInf
// {
// public:
// 	virtual short send(unsigned char* buf)=0;
// 	virtual short recv(unsigned char** buf)=0;
// //	virtual ~MsgTransferInf();
// };
// typedef MsgTransferInf* PMSG_TRANSFER_INF;


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

	unsigned short add_node(int node_id, std::string node_ip);
	unsigned short add_node(const char* node_id_ip_str);
	unsigned short delete_node(int node_id);
	unsigned short delete_node_by_ip(std::string node_ip);
	unsigned short pop_node(ClusterNode** first_node);
	unsigned short cleanup_node();
	unsigned short get_first_node_ip(std::string& first_node_ip, bool peek_only=false);
	unsigned short get_node_id(const std::string& first_node_ip, int& node_id);
	const char* to_string();
	unsigned short from_string(const char* cluster_map_str);
};

///////////////////////////////////////////////////

class KeepaliveTimerTask
{
//	DECLARE_MSG_DUMPER()
private:
	PIMSG_NOTIFY_OBSERVER msg_notify_observer;

public:
	KeepaliveTimerTask();
	~KeepaliveTimerTask();

	unsigned short initialize(PIMSG_NOTIFY_OBSERVER observer);
	unsigned short deinitialize();
	void trigger();
};

#endif
