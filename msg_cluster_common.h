#ifndef MSG_CLUSTER_COMMON_H
#define MSG_CLUSTER_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return values
extern const unsigned short RET_SUCCESS;

extern const unsigned short RET_FAILURE_UNKNOWN;
extern const unsigned short RET_FAILURE_INVALID_ARGUMENT;
extern const unsigned short RET_FAILURE_INVALID_POINTER;
extern const unsigned short RET_FAILURE_INSUFFICIENT_MEMORY;
extern const unsigned short RET_FAILURE_INCORRECT_OPERATION;
extern const unsigned short RET_FAILURE_NOT_FOUND;
extern const unsigned short RET_FAILURE_INCORRECT_CONFIG;
extern const unsigned short RET_FAILURE_HANDLE_THREAD;
extern const unsigned short RET_FAILURE_INCORRECT_PATH;
extern const unsigned short RET_FAILURE_IO_OPERATION;

extern const unsigned short RET_FAILURE_CONNECTION_BASE;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL;
extern const unsigned short RET_FAILURE_CONNECTION_CLOSE;
extern const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
extern const unsigned short RET_FAILURE_CONNECTION_NO_SERVER;
extern const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE;

#define CHECK_SUCCESS(X) (X == RET_SUCCESS ? true : false)
#define CHECK_FAILURE(X) !CHECK_SUCCESS(X)
#define IS_TRY_CONNECTION_TIMEOUT(X) (X == RET_FAILURE_CONNECTION_TRY_TIMEOUT ? true : false)
#define IS_KEEP_ALIVE_TIMEOUT(X) (X == RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT ? true : false)

extern const char *RetDescription[];
extern const char *ConnectionRetDescription[];

const char* GetErrorDescription(short error_code);

extern const char* CHECK_KEEPALIVE_TAG;
extern const char* CHECK_SERVER_CANDIDATE_TAG;
extern const int CHECK_KEEPALIVE_TAG_LEN;
extern const char* END_OF_PACKET;
extern const int KEEPALIVE_DELAY_TIME;
extern const int KEEPALIVE_PERIOD;

extern const char* CONF_FODLERNAME;
extern const int PORT_NO;
extern const int RECV_BUF_SIZE;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Write log through syslog

#define DECLARE_MSG_DUMPER()\
MsgDumperWrapper* msg_dumper;

#define IMPLEMENT_MSG_DUMPER()\
msg_dumper = MsgDumperWrapper::get_instance();

#define RELEASE_MSG_DUMPER()\
if (error_writer != NULL)\
{\
	msg_dumper->release();\
	msg_dumper = NULL;\
}

#define SHOW_MSG_DUMPER

#define WRITE_MSG_DUMPER_BEGIN()\
do{\
char title[64];\
snprintf(title, 64, "%s:%d", __FILE__, __LINE__);\
openlog(title, LOG_PID | LOG_CONS, LOG_USER);

#define WRITE_MSG_DUMPER_END()\
closelog();\
}while(0)

#define WRITE_MSG_DUMPER(priority, message)\
WRITE_MSG_DUMPER_BEGIN()\
syslog(priority, message);\
if (msg_dumper != NULL) msg_dumper->write(priority, message);\
WRITE_MSG_DUMPER_END()

#define WRITE_FORMAT_MSG_DUMPER(buf_size, priority, message_format, ...)\
WRITE_MSG_DUMPER_BEGIN()\
char buf[buf_size];\
snprintf(buf, buf_size, message_format, __VA_ARGS__);\
syslog(priority, buf);\
if (msg_dumper != NULL) msg_dumper->write(priority, buf);\
WRITE_MSG_DUMPER_END()

#if defined SHOW_MSG_DUMPER

#define WRITE_DEBUG_MSG_DUMPER(message) WRITE_MSG_DUMPER(LOG_DEBUG, message)
#define WRITE_INFO_MSG_DUMPER(message) WRITE_MSG_DUMPER(LOG_INFO, message)
#define WRITE_ERR_MSG_DUMPER(message) WRITE_MSG_DUMPER(LOG_ERR, message)

#define WRITE_DEBUG_FORMAT_MSG_DUMPER(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_DEBUG, message_format, __VA_ARGS__)
#define WRITE_INFO_FORMAT_MSG_DUMPER(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_INFO, message_format, __VA_ARGS__)
#define WRITE_ERR_FORMAT_MSG_DUMPER(buf_size, message_format, ...) WRITE_FORMAT_MSG_DUMPER(buf_size, LOG_ERR, message_format, __VA_ARGS__)

#else

#define WRITE_DEBUG_MSG_DUMPER(message)
#define WRITE_INFO_MSG_DUMPER(message)
#define WRITE_ERR_MSG_DUMPER(message)

#define WRITE_DEBUG_FORMAT_MSG_DUMPER(buf_size, message_format, ...)
#define WRITE_INFO_FORMAT_MSG_DUMPER(buf_size, message_format, ...)
#define WRITE_ERR_FORMAT_MSG_DUMPER(buf_size, message_format, ...)

#endif

#endif
