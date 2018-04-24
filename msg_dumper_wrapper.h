#ifndef MSG_DUMPER_WRAPPER_H
#define MSG_DUMPER_WRAPPER_H

#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>
#include "msg_dumper.h"


#define MSG_DUMPER_BUF_SIZE 512
#define MSG_DUMPER_CODE_POS_FORMAT "(%s:%ld) "

#define DECLARE_MSG_DUMPER()\
MsgDumperWrapper* msg_dumper;

#define IMPLEMENT_MSG_DUMPER()\
msg_dumper = MsgDumperWrapper::get_instance();\

// Can be used for functions
#define DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER()\
static MsgDumperWrapper* msg_dumper = MsgDumperWrapper::get_instance();\

#define RELEASE_MSG_DUMPER()\
if (msg_dumper != NULL)\
{\
	msg_dumper->release();\
	msg_dumper = NULL;\
}

#define SET_SEVERITY(func_name, func_value)\
msg_dumper->func_name(func_value);

#define GET_SEVERITY(func_name)\
msg_dumper->func_name();

#define STATIC_SET_SEVERITY(func_name, func_value)\
do{\
DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER();\
SET_SEVERITY(func_name, func_value);\
RELEASE_MSG_DUMPER();\
}while(0);

#define WRITE_MSG_DUMPER(priority, message)\
msg_dumper->write(__FILE__, __LINE__, priority, message)

#define WRITE_FORMAT_MSG_DUMPER(priority, message_format, ...)\
msg_dumper->format_write(__FILE__, __LINE__, priority, message_format, __VA_ARGS__)

#define STATIC_WRITE_MSG_DUMPER(priority, message)\
do{\
DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER();\
WRITE_MSG_DUMPER(priority, message);\
RELEASE_MSG_DUMPER();\
}while(0);

#define STATIC_WRITE_FORMAT_MSG_DUMPER(priority, message_format, ...)\
do{\
DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER();\
WRITE_FORMAT_MSG_DUMPER(priority, message_format, __VA_ARGS__);\
RELEASE_MSG_DUMPER();\
}while(0);

#define SHOW_MSG_DUMPER

#if defined SHOW_MSG_DUMPER

#define SET_LOG_SEVERITY(linux_severity) SET_SEVERITY(set_log_severity, linux_severity)
#define SET_SYSLOG_SEVERITY(linux_severity) SET_SEVERITY(set_syslog_severity, linux_severity)
#define GET_LOG_SEVERITY() GET_SEVERITY(get_log_severity)
#define GET_SYSLOG_SEVERITY() GET_SEVERITY(get_syslog_severity)

#define SET_LOG_SEVERITY_BY_NAME(severity_name) SET_SEVERITY(set_log_severity_by_name, severity_name)
#define SET_SYSLOG_SEVERITY_BY_NAME(severity_name) SET_SEVERITY(set_syslog_severity_by_name, severity_name)
#define GET_LOG_SEVERITY_BY_NAME() GET_SEVERITY(get_log_severity_by_name)
#define GET_SYSLOG_SEVERITY_BY_NAME() GET_SEVERITY(get_syslog_severity_by_name)

#define SET_LOG_SEVERITY_CONFIG(linux_severity) SET_SEVERITY(set_log_severity_config, linux_severity)
#define SET_SYSLOG_SEVERITY_CONFIG(linux_severity) SET_SEVERITY(set_syslog_severity_config, linux_severity)
#define GET_LOG_SEVERITY_CONFIG() GET_SEVERITY(get_log_severity_config)
#define GET_SYSLOG_SEVERITY_CONFIG() GET_SEVERITY(get_syslog_severity_config)

#define STATIC_SET_LOG_SEVERITY(linux_severity) STATIC_SET_SEVERITY(set_log_severity, linux_severity)
#define STATIC_SET_SYSLOG_SEVERITY(linux_severity) STATIC_SET_SEVERITY(set_syslog_severity, linux_severity)

#define STATIC_SET_LOG_SEVERITY_BY_NAME(severity_name) STATIC_SET_SEVERITY(set_log_severity_by_name, severity_name)
#define STATIC_SET_SYSLOG_SEVERITY_BY_NAME(severity_name) STATIC_SET_SEVERITY(set_syslog_severity_by_name, severity_name)

#define STATIC_SET_LOG_SEVERITY_CONFIG(linux_severity) STATIC_SET_SEVERITY(set_log_severity_config, linux_severity)
#define STATIC_SET_SYSLOG_SEVERITY_CONFIG(linux_severity) STATIC_SET_SEVERITY(set_syslog_severity_config, linux_severity)

#define WRITE_DEBUG(message) WRITE_MSG_DUMPER(LOG_DEBUG, message)
#define WRITE_INFO(message) WRITE_MSG_DUMPER(LOG_INFO, message)
#define WRITE_WARN(message) WRITE_MSG_DUMPER(LOG_WARNING, message)
#define WRITE_ERROR(message) WRITE_MSG_DUMPER(LOG_ERR, message)

#define WRITE_FORMAT_DEBUG(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_DEBUG, message_format, __VA_ARGS__)
#define WRITE_FORMAT_INFO(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_INFO, message_format, __VA_ARGS__)
#define WRITE_FORMAT_WARN(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_WARNING, message_format, __VA_ARGS__)
#define WRITE_FORMAT_ERROR(message_format, ...) WRITE_FORMAT_MSG_DUMPER(LOG_ERR, message_format, __VA_ARGS__)

#define STATIC_WRITE_DEBUG(message) STATIC_WRITE_MSG_DUMPER(LOG_DEBUG, message)
#define STATIC_WRITE_INFO(message) STATIC_WRITE_MSG_DUMPER(LOG_INFO, message)
#define STATIC_WRITE_WARN(message) STATIC_WRITE_MSG_DUMPER(LOG_WARNING, message)
#define STATIC_WRITE_ERROR(message) STATIC_WRITE_MSG_DUMPER(LOG_ERR, message)

#define STATIC_WRITE_FORMAT_DEBUG(message_format, ...) STATIC_WRITE_FORMAT_MSG_DUMPER(LOG_DEBUG, message_format, __VA_ARGS__)
#define STATIC_WRITE_FORMAT_INFO(message_format, ...) STATIC_WRITE_FORMAT_MSG_DUMPER(LOG_INFO, message_format, __VA_ARGS__)
#define STATIC_WRITE_FORMAT_WARN(message_format, ...) STATIC_WRITE_FORMAT_MSG_DUMPER(LOG_WARNING, message_format, __VA_ARGS__)
#define STATIC_WRITE_FORMAT_ERROR(message_format, ...) STATIC_WRITE_FORMAT_MSG_DUMPER(LOG_ERR, message_format, __VA_ARGS__)

#else

#define SET_LOG_SEVERITY(linux_severity) 
#define SET_SYSLOG_SEVERITY(linux_severity) 
#define GET_LOG_SEVERITY() 
#define GET_SYSLOG_SEVERITY()

#define SET_LOG_SEVERITY_BY_NAME(severity_name)
#define SET_SYSLOG_SEVERITY_BY_NAME(severity_name)
#define GET_LOG_SEVERITY_BY_NAME()
#define GET_SYSLOG_SEVERITY_BY_NAME()

#define SET_LOG_SEVERITY_CONFIG(linux_severity)
#define SET_SYSLOG_SEVERITY_CONFIG(linux_severity)
#define GET_LOG_SEVERITY_CONFIG()
#define GET_SYSLOG_SEVERITY_CONFIG()

#define STATIC_SET_LOG_SEVERITY(linux_severity)
#define STATIC_SET_SYSLOG_SEVERITY(linux_severity)

#define STATIC_SET_LOG_SEVERITY_BY_NAME(severity_name)
#define STATIC_SET_SYSLOG_SEVERITY_BY_NAME(severity_name)

#define STATIC_SET_LOG_SEVERITY_CONFIG(linux_severity)
#define STATIC_SET_SYSLOG_SEVERITY_CONFIG(linux_severity)

#define WRITE_DEBUG(message)
#define WRITE_INFO(message)
#define WRITE_WARN(message)
#define WRITE_ERROR(message)

#define WRITE_FORMAT_DEBUG(message_format, ...)
#define WRITE_FORMAT_INFO(message_format, ...)
#define WRITE_FORMAT_WARN(message_format, ...)
#define WRITE_FORMAT_ERROR(message_format, ...)

#define STATIC_WRITE_DEBUG(message)
#define STATIC_WRITE_INFO(message)
#define STATIC_WRITE_WARN(message)
#define STATIC_WRITE_ERROR(message)

#define STATIC_WRITE_FORMAT_DEBUG(message_format, ...)
#define STATIC_WRITE_FORMAT_INFO(message_format, ...)
#define STATIC_WRITE_FORMAT_WARN(message_format, ...)
#define STATIC_WRITE_FORMAT_ERROR(message_format, ...)

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
	FP_msg_dumper_get_severity fp_msg_dumper_get_severity;
	FP_msg_dumper_get_facility fp_msg_dumper_get_facility;
	FP_msg_dumper_write_msg fp_msg_dumper_write_msg;
	FP_msg_dumper_deinitialize fp_msg_dumper_deinitialize;
	FP_msg_dumper_get_error_description fp_msg_dumper_get_error_description;

	pthread_mutex_t write_msg_mut;
	unsigned short facility;
	char *fmt_msg_buf;
	int fmt_msg_buf_size;

	static unsigned short get_msg_dumper_severity_from_string(const char* severity_name);
	static unsigned short get_linux_severity_from_string(const char* severity_name);
	static unsigned short get_facility_index_from_string(const char* facility_name);
	static unsigned short get_facility_from_string(const char* facility_name);
	static unsigned short transform_linux_severity_to_msg_dumper_severity(unsigned short linux_severity);
	static unsigned short transform_msg_dumper_severity_to_linux_severity(unsigned short msg_dumper_severity);

	MsgDumperWrapper();
	MsgDumperWrapper(const MsgDumperWrapper&);
	MsgDumperWrapper& operator=(const MsgDumperWrapper&);
	~MsgDumperWrapper();

	unsigned short initialize();
	void deinitialize();
	bool export_api();
	unsigned short parse_config();
	unsigned short set_severity(unsigned short linux_severity, unsigned short facility);
	unsigned short get_severity(unsigned short facility)const;
	unsigned short set_severity_by_name(const char* severity_name, const char* facility_name);
	unsigned short get_severity_by_name(const char* facility_name)const;
	unsigned short set_config(const char* config_name, const char* config_value);
	unsigned short get_config(const char* config_name, char* config_value)const;
	// unsigned short format_write_va(unsigned short linux_severity, const char* msg_fmt, va_list ap);
// Not thread-safe
	const char* get_code_pos_str(const char* file_name, unsigned long line_no);
	const char* get_format_str_va(const char* msg_fmt, va_list ap);

public:
	static const int STRING_BUF_SIZE;

	static MsgDumperWrapper* get_instance();

	int addref();
	int release();

	static const char** get_severity_name_list(int& severity_size);
	static const char** get_facility_name_list(int& facility_size);
	static unsigned short check_severity_name(const char* severity_name);
	static unsigned short check_facility_name(const char* facility_name);

	unsigned short set_log_severity(unsigned short linux_severity);
	unsigned short set_syslog_severity(unsigned short linux_severity);
	unsigned short get_log_severity()const;
	unsigned short get_syslog_severity()const;
	unsigned short set_log_severity_by_name(const char* severity_name);
	unsigned short set_syslog_severity_by_name(const char* severity_name);
	const char* get_log_severity_by_name()const;
	const char* get_syslog_severity_by_name()const;
	unsigned short set_log_severity_config(unsigned short linux_severity);
	unsigned short set_syslog_severity_config(unsigned short linux_severity);
	unsigned short get_log_severity_config()const;
	unsigned short get_syslog_severity_config()const;

	unsigned short write(const char* file_name, unsigned long line_no, unsigned short linux_severity, const char* msg);
	unsigned short format_write(const char* file_name, unsigned long line_no, unsigned short linux_severity, const char* msg_fmt, ...);
	// unsigned short format_write_ex(unsigned short linux_severity, const char* msg_fmt, ...);

	// unsigned short error(const char* msg);
	// unsigned short format_error(const char* msg_fmt, ...);
	// unsigned short warn(const char* msg);
	// unsigned short format_warn(const char* msg_fmt, ...);
	// unsigned short info(const char* msg);
	// unsigned short format_info(const char* msg_fmt, ...);
	// unsigned short debug(const char* msg);
	// unsigned short format_debug(const char* msg_fmt, ...);

	const char* get_error_description()const;
};

#endif

