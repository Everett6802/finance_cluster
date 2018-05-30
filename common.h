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

extern const std::string CHECK_KEEPALIVE_TAG;
extern const std::string CHECK_SERVER_CANDIDATE_TAG;
extern const int CHECK_KEEPALIVE_TAG_LEN;
extern const int CHECK_SERVER_CANDIDATE_TAG_LEN;
extern const std::string END_OF_PACKET;
extern const int KEEPALIVE_DELAY_TIME;
extern const int KEEPALIVE_PERIOD;
extern const int MAX_CONNECTED_CLIENT;

extern const char* CONF_FODLERNAME;
extern const int PORT_NO;
extern const int RECV_BUF_SIZE;

//extern const unsigned short NOTIFY_DEAD_CLIENT;
//extern const unsigned short NOTIFY_CHECK_KEEPALIVE;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Enumeration

enum NotifyType{NOTIFY_DEAD_CLIENT, NOTIFY_CHECK_KEEPALIVE};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Typedef

typedef std::list<char*> CHAR_LIST;
typedef CHAR_LIST* PCHAR_LIST;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Functions

unsigned short get_local_interface_ip(std::map<std::string, std::string>& interface_ip_map);


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface

class MsgTransferInf
{
public:
	virtual short send(unsigned char* buf)=0;
	virtual short recv(unsigned char** buf)=0;
//	virtual ~MsgTransferInf();
};
typedef MsgTransferInf* PMSG_TRANSFER_INF;

class MsgNotifyObserverInf
{
public:
	virtual unsigned short update(const std::string ip, const std::string message)=0;
	virtual unsigned short notify(NotifyType notify_type)=0;
//	virtual ~MsgNotifyObserverInf();
};
typedef MsgNotifyObserverInf* PMSG_NOTIFY_OBSERVER_INF;


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

#endif
