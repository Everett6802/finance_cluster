#ifndef MSG_CLUSTER_COMMON_H
#define MSG_CLUSTER_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <list>
#include <deque>
#include <string>
#include "msg_dumper_wrapper.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro

// This constant is used for allocating array size
#define DEF_SHORT_STRING_SIZE 			32U
#define DEF_STRING_SIZE 				64U
#define DEF_LONG_STRING_SIZE			256U
#define DEF_EX_LONG_STRING_SIZE			LONG_STRING_SIZE * 2

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
// Functions
typedef std::list<char*> CHAR_LIST;
typedef CHAR_LIST* PCHAR_LIST;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Interface
//class MsgRecvObserverInf
//{
//public:
//	virtual unsigned short update(const char* ip, const char* message)=0;
//	virtual ~MsgRecvObserverInf();
//};
//typedef MsgRecvObserverInf* PMSG_RECV_OBSERVER_INF;

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
	virtual unsigned short update(const char* ip, const std::string message)=0;
	virtual unsigned short notify(NotifyType notify_type)=0;
//	virtual ~MsgNotifyObserverInf();
};
typedef MsgNotifyObserverInf* PMSG_NOTIFY_OBSERVER_INF;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Write log through syslog

#define DECLARE_MSG_DUMPER()\
MsgDumperWrapper* msg_dumper;

#define IMPLEMENT_MSG_DUMPER()\
msg_dumper = MsgDumperWrapper::get_instance();

#define RELEASE_MSG_DUMPER()\
if (msg_dumper != NULL)\
{\
	msg_dumper->release();\
	msg_dumper = NULL;\
}

#define SHOW_MSG_DUMPER

#define WRITE_MSG_DUMPER_BEGIN()\
do{\
char title[DEF_STRING_SIZE];\
snprintf(title, DEF_STRING_SIZE, "%s:%d", __FILE__, __LINE__);\
openlog(title, LOG_PID | LOG_CONS, LOG_USER);

#define WRITE_MSG_DUMPER_END()\
closelog();\
}while(0)

#define WRITE_MSG_DUMPER(priority, message)\
WRITE_MSG_DUMPER_BEGIN()\
msg_dumper->write(priority, message);\
WRITE_MSG_DUMPER_END()

#define WRITE_FORMAT_MSG_DUMPER(buf_size, priority, message_format, ...)\
WRITE_MSG_DUMPER_BEGIN()\
char buf[buf_size];\
snprintf(buf, buf_size, message_format, __VA_ARGS__);\
msg_dumper->write(priority, buf);\
WRITE_MSG_DUMPER_END()

#if defined SHOW_MSG_DUMPER

#define WRITE_DEBUG(message) WRITE_MSG_DUMPER(LOG_DEBUG, message)
#define WRITE_INFO(message) WRITE_MSG_DUMPER(LOG_INFO, message)
#define WRITE_WARN(message) WRITE_MSG_DUMPER(LOG_WARNING, message)
#define WRITE_ERROR(message) WRITE_MSG_DUMPER(LOG_ERR, message)

#define WRITE_FORMAT_DEBUG(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_DEBUG, message_format, __VA_ARGS__)
#define WRITE_FORMAT_INFO(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_INFO, message_format, __VA_ARGS__)
#define WRITE_FORMAT_WARN(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_WARNING, message_format, __VA_ARGS__)
#define WRITE_FORMAT_ERROR(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_ERR, message_format, __VA_ARGS__)

#else

#define WRITE_DEBUG(message)
#define WRITE_INFO(message)
#define WRITE_WARN(message)
#define WRITE_ERROR(message)

#define WRITE_FORMAT_DEBUG(buf_size, message_format, ...)
#define WRITE_FORMAT_INFO(buf_size, message_format, ...)
#define WRITE_FORMAT_WARN(buf_size, message_format, ...)
#define WRITE_FORMAT_ERROR(buf_size, message_format, ...)

#endif

#endif
