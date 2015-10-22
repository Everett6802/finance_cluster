#ifndef MSG_DUMPER_WRAPPER_H
#define MSG_DUMPER_WRAPPER_H

#include "msg_dumper.h"


#define MSG_DUMPER_BUF_SIZE 512

#define DECLARE_MSG_DUMPER()\
MsgDumperWrapper* msg_dumper;

#define DECLARE_MSG_DUMPER_PARAM()\
static int __msg_dumper_title_len__;\
static int __msg_dumper_message_len__;\
static char __msg_dumper_message__[MSG_DUMPER_BUF_SIZE];

#define IMPLEMENT_MSG_DUMPER()\
msg_dumper = MsgDumperWrapper::get_instance();\

#define RELEASE_MSG_DUMPER()\
if (msg_dumper != NULL)\
{\
	msg_dumper->release();\
	msg_dumper = NULL;\
}

#define SHOW_MSG_DUMPER

#define WRITE_MSG_DUMPER_BEGIN()\
do{\
snprintf(__msg_dumper_message__, MSG_DUMPER_BUF_SIZE, "(%s:%d) ", __FILE__, __LINE__);\
__msg_dumper_title_len__ = strlen(__msg_dumper_message__);\
__msg_dumper_message_len__ = MSG_DUMPER_BUF_SIZE - __msg_dumper_title_len__;

#define WRITE_MSG_DUMPER_END()\
}while(0)

#define WRITE_MSG_DUMPER(priority, message)\
WRITE_MSG_DUMPER_BEGIN()\
snprintf(&__msg_dumper_message__[__msg_dumper_title_len__], __msg_dumper_message_len__, "%s", message);\
msg_dumper->write(priority, __msg_dumper_message__);\
WRITE_MSG_DUMPER_END()

#define WRITE_FORMAT_MSG_DUMPER(priority, message_format, ...)\
WRITE_MSG_DUMPER_BEGIN()\
snprintf(&__msg_dumper_message__[__msg_dumper_title_len__], __msg_dumper_message_len__, message_format, __VA_ARGS__);\
msg_dumper->write(priority, __msg_dumper_message__);\
WRITE_MSG_DUMPER_END()

#if defined SHOW_MSG_DUMPER

#define WRITE_DEBUG(message) WRITE_MSG_DUMPER(LOG_DEBUG, message)
#define WRITE_INFO(message) WRITE_MSG_DUMPER(LOG_INFO, message)
#define WRITE_WARN(message) WRITE_MSG_DUMPER(LOG_WARNING, message)
#define WRITE_ERROR(message) WRITE_MSG_DUMPER(LOG_ERR, message)

#define WRITE_FORMAT_DEBUG(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_DEBUG, message_format, __VA_ARGS__)
#define WRITE_FORMAT_INFO(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_INFO, message_format, __VA_ARGS__)
#define WRITE_FORMAT_WARN(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_WARNING, message_format, __VA_ARGS__)
#define WRITE_FORMAT_ERROR(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_ERR, message_format, __VA_ARGS__)

#else

#define WRITE_DEBUG(message)
#define WRITE_INFO(message)
#define WRITE_WARN(message)
#define WRITE_ERROR(message)

#define WRITE_FORMAT_DEBUG(message_format, ...)
#define WRITE_FORMAT_INFO(message_format, ...)
#define WRITE_FORMAT_WARN(message_format, ...)
#define WRITE_FORMAT_ERROR(message_format, ...)

#endif


class MsgDumperWrapper
{
private:
	static MsgDumperWrapper* instance;
	static const char* MSG_DUMPER_ERROR_COLOR;
	static const char* FACILITY_NAME[];
	static const int FACILITY_NAME_SIZE;
	static const unsigned short FACILITY_FLAG[];
	static const char* SEVERITY_NAME[];
	static const int SEVERITY_NAME_SIZE;
	static const char* CONF_FOLDER;
	static const char* CONF_FILENAME;

	int ref_count;
	void* api_handle;
	FP_msg_dumper_initialize fp_msg_dumper_initialize;
	FP_msg_dumper_get_version fp_msg_dumper_get_version;
	FP_msg_dumper_set_severity fp_msg_dumper_set_severity;
	FP_msg_dumper_set_facility fp_msg_dumper_set_facility;
	FP_msg_dumper_write_msg fp_msg_dumper_write_msg;
	FP_msg_dumper_deinitialize fp_msg_dumper_deinitialize;
	FP_msg_dumper_get_error_description fp_msg_dumper_get_error_description;

	unsigned short facility_flag;

	MsgDumperWrapper();
	MsgDumperWrapper(const MsgDumperWrapper&);
	MsgDumperWrapper& operator=(const MsgDumperWrapper&);

	unsigned short initialize();
	void deinitialize();
	bool export_api();
	unsigned short parse_config();

public:
	static const int STRING_BUF_SIZE;
	~MsgDumperWrapper(){deinitialize();}

	static MsgDumperWrapper* get_instance();
	int addref();
	int release();

	unsigned short write(unsigned short syslog_priority, const char* msg);
	const char* get_error_description()const;
};

#endif
