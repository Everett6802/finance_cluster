#ifndef MSG_DUMPER_H
#define MSG_DUMPER_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return values
static const unsigned short MSG_DUMPER_SUCCESS = 0;

static const unsigned short MSG_DUMPER_FAILURE_UNKNOWN = 1;
static const unsigned short MSG_DUMPER_FAILURE_INVALID_ARGUMENT = 2;
static const unsigned short MSG_DUMPER_FAILURE_INVALID_POINTER = 3;
static const unsigned short MSG_DUMPER_FAILURE_INSUFFICIENT_MEMORY = 4;
static const unsigned short MSG_DUMPER_FAILURE_SYSTEM_API = 5;
static const unsigned short MSG_DUMPER_FAILURE_NOT_FOUND = 6;
static const unsigned short MSG_DUMPER_FAILURE_OUT_OF_RANGE = 7;
static const unsigned short MSG_DUMPER_FAILURE_INCORRECT_CONFIG = 8;
static const unsigned short MSG_DUMPER_FAILURE_INCORRECT_OPERATION = 9;
static const unsigned short MSG_DUMPER_FAILURE_COM_PORT = 10;
static const unsigned short MSG_DUMPER_FAILURE_MYSQL = 11;
static const unsigned short MSG_DUMPER_FAILURE_SOCKET = 12;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Constants

static const unsigned short MSG_DUMPER_SEVERITY_ERROR = 0;
static const unsigned short MSG_DUMPER_SEVERITY_WARN = 1;
static const unsigned short MSG_DUMPER_SEVERITY_INFO = 2;
static const unsigned short MSG_DUMPER_SEVERITY_DEBUG = 3;
static const unsigned short MSG_DUMPER_SEVERITY_LIST[] = {MSG_DUMPER_SEVERITY_ERROR, MSG_DUMPER_SEVERITY_WARN, MSG_DUMPER_SEVERITY_INFO, MSG_DUMPER_SEVERITY_DEBUG};
static const unsigned short MSG_DUMPER_SEVERITY_LIST_SIZE = sizeof(MSG_DUMPER_SEVERITY_LIST) / sizeof(MSG_DUMPER_SEVERITY_LIST[0]);
static const unsigned short MSG_DUMPER_SEVERITY_NOSET = 999;

static const unsigned short MSG_DUMPER_FACILITY_FLAG_NONE = 0x0;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_LOG = 0x1;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_COM = 0x1 << 1;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_SQL = 0x1 << 2;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_REMOTE = 0x1 << 3;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_SYSLOG = 0x1 << 4;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_STDOUT = 0x1 << 5;
static const unsigned short MSG_DUMPER_FACILITY_FLAG_ALL = (MSG_DUMPER_FACILITY_FLAG_LOG | MSG_DUMPER_FACILITY_FLAG_COM | MSG_DUMPER_FACILITY_FLAG_SQL | MSG_DUMPER_FACILITY_FLAG_REMOTE | MSG_DUMPER_FACILITY_FLAG_SYSLOG | MSG_DUMPER_FACILITY_FLAG_STDOUT);
// static const unsigned short MSG_DUMPER_FACILITY_FLAG_LIST[] = {MSG_DUMPER_FACILITY_FLAG_LOG, MSG_DUMPER_FACILITY_FLAG_COM, MSG_DUMPER_FACILITY_FLAG_SQL, MSG_DUMPER_FACILITY_FLAG_REMOTE, MSG_DUMPER_FACILITY_FLAG_SYSLOG, MSG_DUMPER_FACILITY_FLAG_STDOUT, MSG_DUMPER_FACILITY_FLAG_ALL};
// static const unsigned short MSG_DUMPER_FACILITY_FLAG_LIST_SIZE = sizeof(MSG_DUMPER_FACILITY_FLAG_LIST) / sizeof(MSG_DUMPER_FACILITY_FLAG_LIST[0]);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// APIs

extern "C"
{

unsigned short msg_dumper_get_version(unsigned char* major_version, unsigned char* minor_version, unsigned char* build_version);
// unsigned short msg_dumper_set_severity(unsigned short linux_severity, unsigned short facility);
// unsigned short msg_dumper_set_severity_all(unsigned short linux_severity);
// unsigned short msg_dumper_set_facility(unsigned short facility);
// unsigned short msg_dumper_get_severity(unsigned short facility);
// unsigned short msg_dumper_get_facility();
unsigned short msg_dumper_set_severity_index(const char* facility, int severity_index);
unsigned short msg_dumper_set_severity(const char* facility, const char* severity);
// severity must be released outside the function
unsigned short msg_dumper_get_severity_index(const char* facility, int* severity_index);
unsigned short msg_dumper_get_severity(const char* facility, char** severity);
unsigned short msg_dumper_initialize();
// unsigned short msg_dumper_write_msg(unsigned short linux_severity, const char* msg);
// unsigned short msg_dumper_write_format_msg(unsigned short linux_severity, const char* fmt, ...);
unsigned short msg_dumper_write_msg(int severity_index, const char* msg);
unsigned short msg_dumper_write_format_msg(int severity_index, const char* fmt, ...);
unsigned short msg_dumper_deinitialize();
const char* msg_dumper_get_error_description();

}

typedef unsigned short (*FP_msg_dumper_get_version)(unsigned char* major_version, unsigned char* minor_version, unsigned char* build_version);
// typedef unsigned short (*FP_msg_dumper_set_severity)(unsigned short severity, unsigned short facility);
// typedef unsigned short (*FP_msg_dumper_set_severity_all)(unsigned short severity);
// typedef unsigned short (*FP_msg_dumper_set_facility)(unsigned short facility);
// typedef unsigned short (*FP_msg_dumper_get_severity)(unsigned short facility);
// typedef unsigned short (*FP_msg_dumper_get_facility)();
typedef unsigned short (*FP_msg_dumper_set_severity_index)(const char* facility, int severity_index);
typedef unsigned short (*FP_msg_dumper_set_severity)(const char* facility, const char* severity);
typedef unsigned short (*FP_msg_dumper_get_severity_index)(const char* facility, int* severity_index);
typedef unsigned short (*FP_msg_dumper_get_severity)(const char* facility, char** severity);
typedef unsigned short (*FP_msg_dumper_initialize)();
// typedef unsigned short (*FP_msg_dumper_write_msg)(unsigned short severity, const char* msg);
// typedef unsigned short (*FP_msg_dumper_write_format_msg)(unsigned short severity, const char* fmt, ...);
typedef unsigned short (*FP_msg_dumper_write_msg)(int severity_index, const char* msg);
typedef unsigned short (*FP_msg_dumper_write_format_msg)(int severity_index, const char* fmt, ...);
typedef unsigned short (*FP_msg_dumper_deinitialize)();
typedef const char* (*FP_msg_dumper_get_error_description)();


#endif
