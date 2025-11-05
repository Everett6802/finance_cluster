#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <stdexcept>
#include "msg_dumper_wrapper.h"


using namespace std;

#define CHECK_FAILURE(x) ((x != MSG_DUMPER_SUCCESS) ? true : false)
// #define DO_DEBUG

MsgDumperWrapper* MsgDumperWrapper::instance = NULL;
const char* MsgDumperWrapper::MSG_DUMPER_ERROR_COLOR = "\x1B[31m";
const char* MsgDumperWrapper::FACILITY_NAME[] = {"Log", "Com", "Sql", "Remote", "Syslog"};
const int MsgDumperWrapper::FACILITY_NAME_SIZE = sizeof(FACILITY_NAME) / sizeof(FACILITY_NAME[0]);
const unsigned short MsgDumperWrapper::FACILITY_FLAG[] = {MSG_DUMPER_FACILITY_LOG, MSG_DUMPER_FACILITY_COM, MSG_DUMPER_FACILITY_SQL, MSG_DUMPER_FACILITY_REMOTE, MSG_DUMPER_FACILITY_SYSLOG};
const char* MsgDumperWrapper::SEVERITY_NAME[] = {"ERROR", "WARN", "INFO", "DEBUG"};
const int MsgDumperWrapper::SEVERITY_NAME_SIZE = sizeof(SEVERITY_NAME) / sizeof(SEVERITY_NAME[0]);
const char* MsgDumperWrapper::CONF_FOLDER = "conf";
const char* MsgDumperWrapper::CONF_FILENAME = "dumper_param.conf";

unsigned short MsgDumperWrapper::get_msg_dumper_severity_from_string(const char* severity_name)
{
	assert(severity_name != NULL && "severity_name should NOT be NULL");
	unsigned short msg_dumper_severity;
	bool found = false;
	for (int i = 0 ; i < SEVERITY_NAME_SIZE ; i++)
	{
// #ifdef DO_DEBUG
// 		fprintf(stderr, "%s, %s, %d\n", severity_name, SEVERITY_NAME[i], strcmp(severity_name, SEVERITY_NAME[i]));
// #endif
		if (strcmp(severity_name, SEVERITY_NAME[i]) == 0)
		{
			msg_dumper_severity = (unsigned short)i;
			found = true;
			break;
		}
	}
	if (!found)
	{
		char exception[64];
		snprintf(exception, 64, "Unknown severity: %s", severity_name);
		throw invalid_argument(string(exception));
	}
	return msg_dumper_severity;
}

unsigned short MsgDumperWrapper::get_linux_severity_from_string(const char* severity_name)
{
	assert(severity_name != NULL && "severity_name should NOT be NULL");
	unsigned short msg_dumper_severity;
	bool found = false;
	for (int i = 0 ; i < SEVERITY_NAME_SIZE ; i++)
	{
// #ifdef DO_DEBUG
// 		fprintf(stderr, "%s, %s, %d\n", severity_name, SEVERITY_NAME[i], strcmp(severity_name, SEVERITY_NAME[i]));
// #endif
		if (strcmp(severity_name, SEVERITY_NAME[i]) == 0)
		{
			msg_dumper_severity = (unsigned short)i;
			found = true;
			break;
		}
	}
	if (!found)
	{
		char exception[64];
		snprintf(exception, 64, "Unknown severity: %s", severity_name);
		throw invalid_argument(string(exception));
	}
#if 0
static const unsigned short MSG_DUMPER_SEVIRITY_ERROR = 0;
static const unsigned short MSG_DUMPER_SEVIRITY_WARN = 1;
static const unsigned short MSG_DUMPER_SEVIRITY_INFO = 2;
static const unsigned short MSG_DUMPER_SEVIRITY_DEBUG = 3;
#endif
	unsigned short linux_severity;
	switch(msg_dumper_severity)
	{
	case MSG_DUMPER_SEVIRITY_DEBUG:
		linux_severity = LOG_DEBUG;
		break;
	case MSG_DUMPER_SEVIRITY_INFO:
		linux_severity = LOG_INFO;
		break;
	case MSG_DUMPER_SEVIRITY_WARN:
		linux_severity = LOG_WARNING;
		break;
	case MSG_DUMPER_SEVIRITY_ERROR:
		linux_severity = LOG_ERR;
		break;
	default:
		{
			fprintf(stderr, "%sUnknown msg dumper severity: %d\n", MSG_DUMPER_ERROR_COLOR, msg_dumper_severity);
			throw invalid_argument("Incorrect msg dumper severity");
		}
		break;
	}
	return linux_severity;
}

unsigned short MsgDumperWrapper::get_facility_index_from_string(const char* facility_name)
{
	assert(facility_name != NULL && "facility_name should NOT be NULL");
	unsigned short facility;
	bool found = false;
	for (int i = 0 ; i < FACILITY_NAME_SIZE ; i++)
	{
// #ifdef DO_DEBUG
// 		fprintf(stderr, "%s, %s, %d\n", facility_name, FACILITY_NAME[i], strcmp(facility_name, FACILITY_NAME[i]));
// #endif
		if (strcmp(facility_name, FACILITY_NAME[i]) == 0)
		{
			facility = i;
			found = true;
			break;
		}
	}
	if (!found)
	{
		char exception[64];
		snprintf(exception, 64, "Unknown facility: %s", facility_name);
		throw invalid_argument(string(exception));
	}
	return facility;
}

unsigned short MsgDumperWrapper::get_facility_from_string(const char* facility_name)
{
	return FACILITY_FLAG[get_facility_from_string(facility_name)];
}

unsigned short MsgDumperWrapper::transform_linux_severity_to_msg_dumper_severity(unsigned short linux_severity)
{
#if 0
# linux severity
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#endif
	unsigned short msg_dumper_severity;
	switch(linux_severity)
	{
	case LOG_DEBUG:
		msg_dumper_severity = MSG_DUMPER_SEVIRITY_DEBUG;
		break;
	case LOG_INFO:
		msg_dumper_severity = MSG_DUMPER_SEVIRITY_INFO;
		break;
	case LOG_WARNING:
	case LOG_NOTICE:
		msg_dumper_severity = MSG_DUMPER_SEVIRITY_WARN;
		break;
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
	case LOG_ERR:
		msg_dumper_severity = MSG_DUMPER_SEVIRITY_ERROR;
		break;
	default:
		{
			fprintf(stderr, "%sUnknown linux severity: %d\n", MSG_DUMPER_ERROR_COLOR, linux_severity);
			throw invalid_argument("Incorrect linux severity");
		}
		break;
	}
	// fprintf(stderr, "transform_linux_severity_to_msg_dumper_severity linux_severity: %d, msg_dumper_severity: %d\n", linux_severity, msg_dumper_severity);
	return msg_dumper_severity;
}

unsigned short MsgDumperWrapper::transform_msg_dumper_severity_to_linux_severity(unsigned short msg_dumper_severity)
{
#if 0
static const unsigned short MSG_DUMPER_SEVIRITY_ERROR = 0;
static const unsigned short MSG_DUMPER_SEVIRITY_WARN = 1;
static const unsigned short MSG_DUMPER_SEVIRITY_INFO = 2;
static const unsigned short MSG_DUMPER_SEVIRITY_DEBUG = 3;
#endif
	unsigned short linux_severity;
	switch(msg_dumper_severity)
	{
	case MSG_DUMPER_SEVIRITY_DEBUG:
		linux_severity = LOG_DEBUG;
		break;
	case MSG_DUMPER_SEVIRITY_INFO:
		linux_severity = LOG_INFO;
		break;
	case MSG_DUMPER_SEVIRITY_WARN:
		linux_severity = LOG_WARNING;
		break;
	case MSG_DUMPER_SEVIRITY_ERROR:
		linux_severity = LOG_ERR;
		break;
	default:
		{
			fprintf(stderr, "%sUnknown msg dumper severity: %d\n", MSG_DUMPER_ERROR_COLOR, msg_dumper_severity);
			throw invalid_argument("Incorrect msg dumper severity");
		}
		break;
	}
	return linux_severity;
}

const char* MsgDumperWrapper::get_code_pos_str(const char* file_name, unsigned long line_no)
{
	static const int CODE_POS_STR_SIZE = 256;
	static char code_pos_str[CODE_POS_STR_SIZE];
	snprintf(code_pos_str, CODE_POS_STR_SIZE,MSG_DUMPER_CODE_POS_FORMAT, file_name, line_no);
	return code_pos_str;
}

const char* MsgDumperWrapper::get_format_str_va(const char* msg_fmt, va_list ap)
{
    int n;
    va_list cp;
   	while (true) 
   	{
        va_copy(cp, ap);
        n = vsnprintf(fmt_msg_buf, fmt_msg_buf_size, msg_fmt, cp);
        va_end(cp);
/* Check error code */
       	if (n < 0)
       	{
			fprintf(stderr, "%svsnprintf() fails, due to: %s", MSG_DUMPER_ERROR_COLOR, strerror(errno));
			throw runtime_error("vsnprintf() fails");
        }
/* If that worked, return the string */
       	if (n < fmt_msg_buf_size)
            break;
/* Else try again with more space */
       	fmt_msg_buf_size <<= 1;       
/* Precisely what is needed */
    	char *fmt_msg_buf_old = fmt_msg_buf;
       	if ((fmt_msg_buf = (char*)realloc(fmt_msg_buf_old, fmt_msg_buf_size)) == NULL) 
       	{
			fprintf(stderr, "%sFails to allocate the memory: fmt_msg_buf\n", MSG_DUMPER_ERROR_COLOR);
			throw bad_alloc();
        }
    }
    return fmt_msg_buf;
}

MsgDumperWrapper* MsgDumperWrapper::get_instance()
{
	if (instance == NULL)
	{
// If the instance is NOT created...
		instance = new MsgDumperWrapper();
		if (instance == NULL)
		{
			assert(0 || "Fail to get the instance of MsgDumperWrapper");
			return NULL;
		}
// Initialize the instance
		unsigned short ret = instance->initialize();
		if(CHECK_FAILURE(ret))
		{
			assert(0 || "Fail to get the instance of MsgDumperWrapper");
			return NULL;
		}
	}
// Add the reference count
	instance->addref();
	return instance;
}

const char** MsgDumperWrapper::get_severity_name_list(int& severity_size)
{
	severity_size = SEVERITY_NAME_SIZE;
	return SEVERITY_NAME;
}

const char** MsgDumperWrapper::get_facility_name_list(int& facility_size)
{
	facility_size = FACILITY_NAME_SIZE;
	return FACILITY_NAME;
}

unsigned short MsgDumperWrapper::check_severity_name(const char* severity_name)
{
	return get_linux_severity_from_string(severity_name);
}

unsigned short MsgDumperWrapper::check_facility_name(const char* facility_name)
{
	return get_facility_from_string(facility_name);
}

MsgDumperWrapper::MsgDumperWrapper() :
	ref_count(0),
	api_handle(NULL),
	fp_msg_dumper_initialize(NULL),
	fp_msg_dumper_get_version(NULL),
	fp_msg_dumper_set_severity(NULL),
	fp_msg_dumper_set_facility(NULL),
	fp_msg_dumper_get_severity(NULL),
	fp_msg_dumper_get_facility(NULL),
	fp_msg_dumper_write_msg(NULL),
	fp_msg_dumper_deinitialize(NULL),
	fp_msg_dumper_get_error_description(NULL)
{
}

MsgDumperWrapper::~MsgDumperWrapper(){deinitialize();}

bool MsgDumperWrapper::export_api()
{
	fp_msg_dumper_get_version = (FP_msg_dumper_get_version)dlsym(api_handle, "msg_dumper_get_version");
	if (fp_msg_dumper_get_version == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_get_version() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_initialize = (FP_msg_dumper_initialize)dlsym(api_handle, "msg_dumper_initialize");
	if (fp_msg_dumper_initialize == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_initialize() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_set_severity = (FP_msg_dumper_set_severity)dlsym(api_handle, "msg_dumper_set_severity");
	if (fp_msg_dumper_set_severity == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_set_severity() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_set_facility = (FP_msg_dumper_set_facility)dlsym(api_handle, "msg_dumper_set_facility");
	if (fp_msg_dumper_set_facility == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_set_facility() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_get_severity = (FP_msg_dumper_get_severity)dlsym(api_handle, "msg_dumper_get_severity");
	if (fp_msg_dumper_get_severity == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_get_severity() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_get_facility = (FP_msg_dumper_get_facility)dlsym(api_handle, "msg_dumper_get_facility");
	if (fp_msg_dumper_get_facility == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_get_facility() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_write_msg = (FP_msg_dumper_write_msg)dlsym(api_handle, "msg_dumper_write_msg");
	if (fp_msg_dumper_write_msg == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_write_msg() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_deinitialize = (FP_msg_dumper_deinitialize)dlsym(api_handle, "msg_dumper_deinitialize");
	if (fp_msg_dumper_deinitialize == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_deinitialize() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}
	fp_msg_dumper_get_error_description = (FP_msg_dumper_get_error_description)dlsym(api_handle, "msg_dumper_get_error_descriptions");
	if (fp_msg_dumper_deinitialize == NULL)
	{
		fprintf(stderr, "%sdlsym() fails when exporting msg_dumper_get_error_description() due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return false;
	}

	return true;
}

unsigned short MsgDumperWrapper::initialize()
{
// Initialize the buffer for the format string
	fmt_msg_buf_size = MSG_DUMPER_BUF_SIZE;
	if ((fmt_msg_buf = (char*)malloc(fmt_msg_buf_size)) == NULL)
	{
		fprintf(stderr, "%sFails to allocate the memory: fmt_msg_buf\n", MSG_DUMPER_ERROR_COLOR);
		return MSG_DUMPER_FAILURE_INSUFFICIENT_MEMORY;
	}
// Load library
	unsigned short ret = MSG_DUMPER_SUCCESS;
	api_handle = dlopen("libmsg_dumper.so", RTLD_NOW);
	if (api_handle == NULL)
	{
		fprintf(stderr, "%sdlopen() fails, due to %s\n", MSG_DUMPER_ERROR_COLOR, dlerror());
		return MSG_DUMPER_FAILURE_UNKNOWN;
	}

// Export the APIs
	if (!export_api())
	{
		fprintf(stderr, "%sFail to export the APIs\n", MSG_DUMPER_ERROR_COLOR);
		return MSG_DUMPER_FAILURE_UNKNOWN;
	}

	unsigned char major_version;
	unsigned char minor_version;
	unsigned char build_version;
	fp_msg_dumper_get_version(major_version, minor_version, build_version);
#ifdef DO_DEBUG
	printf("API version: (%d.%d.%d)\n", major_version, minor_version, build_version);
#endif

// Parse the parameters from the config file
//	printf("Parse the config file\n");
	ret = parse_config();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfparse_config() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		return ret;
	}

// Initialize the library
#ifdef DO_DEBUG
	printf("Initialize the library\n");
#endif
	ret = fp_msg_dumper_initialize();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfp_msg_dumper_initialize() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		return ret;
	}
	write_msg_mut = PTHREAD_MUTEX_INITIALIZER;
	return ret;
}

void MsgDumperWrapper::deinitialize()
{
// De-initialize the library
#ifdef DO_DEBUG
	printf("Close the library\n");
#endif
	pthread_mutex_destroy(&write_msg_mut);
	fp_msg_dumper_deinitialize();

	if (fmt_msg_buf != NULL)
	{
		free(fmt_msg_buf);
		fmt_msg_buf = NULL;
	}
// Close the handle
	if (api_handle != NULL)
	{
		dlclose(api_handle);
		api_handle = NULL;
	}
	if (instance != NULL)
		instance = NULL;
}

unsigned short MsgDumperWrapper::parse_config()
{
	static const int BUF_SIZE = 256;
	char current_working_directory[BUF_SIZE];
	getcwd(current_working_directory, sizeof(current_working_directory));
	char config_filename[BUF_SIZE];
	snprintf(config_filename, BUF_SIZE, "%s/%s/%s", current_working_directory, CONF_FOLDER, CONF_FILENAME);
#ifdef DO_DEBUG
	printf("Parse the config file: %s\n", config_filename);
#endif

	FILE *fp = fopen(config_filename, "r");
	if (fp == NULL)
	{
		fprintf(stderr, "%sfopen() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, strerror(errno));
		return MSG_DUMPER_FAILURE_SYSTEM_API;
	}
	unsigned short total_facility_flag = 0x0;
	unsigned short ret = MSG_DUMPER_SUCCESS;
// Parse the config file
	char buf[BUF_SIZE];
	while (fgets(buf, BUF_SIZE, fp) != NULL)
	{
		if (buf[0] == '[')
			break;
		if (buf[0] == '\n' || buf[0] == '#')
			continue;
		int split_pos = -1;
		char* sch = strchr(buf, '=');
		if (sch == NULL)
		{
			fprintf(stderr, "%sIncorrect config format: %s\n", MSG_DUMPER_ERROR_COLOR, buf);
			return MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
		}
		split_pos = sch - buf;
		char* ech = strchr(buf, '\n');
		if (ech != NULL)
		{
			int end_pos = ech - buf;
			if (buf[end_pos - 1] == '\r')
				end_pos--;
			buf[end_pos] = '\0';
		}
		string config(buf);
//		WRITE_DEBUG_FORMAT_LOGGING(STRING_SIZE, "***Config*** content: %s, split pos: %d", config.c_str(), split_pos);
		char facility_name[16];
		snprintf(facility_name, 16, "%s", config.substr(0, split_pos).c_str());
		char severity_name[16];
		snprintf(severity_name, 16, "%s", config.substr(split_pos + 1).c_str());
#ifdef DO_DEBUG
		fprintf(stderr, "***Config*** facility: %s, severity: %s\n", facility_name, severity_name);
#endif
// Set facility and severity
		unsigned short facility_index = get_facility_index_from_string(facility_name);
		total_facility_flag |= FACILITY_FLAG[facility_index];
// Set severity
		unsigned short linux_severity = get_linux_severity_from_string(severity_name);
#ifdef DO_DEBUG
		fprintf(stderr, "Set severity of facility[%s] to %s\n", FACILITY_NAME[facility_index], SEVERITY_NAME[get_msg_dumper_severity_from_string(severity_name)]);
#endif
		ret = fp_msg_dumper_set_severity(linux_severity, FACILITY_FLAG[facility_index]);
		if (CHECK_FAILURE(ret))
		{
			fprintf(stderr, "%sfp_msg_dumper_set_severity() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
			goto OUT;
		}
	}
#ifdef DO_DEBUG
	printf("Set facility to %d\n", total_facility_flag);
#endif
	ret = fp_msg_dumper_set_facility(total_facility_flag);
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfp_msg_dumper_set_facility() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
		return ret;
	}

OUT:
	fclose(fp);
	fp = NULL;

	return ret;
}

int MsgDumperWrapper::addref()
{
	__sync_fetch_and_add(&ref_count, 1);
	return ref_count;
}

int MsgDumperWrapper::release()
{
	__sync_fetch_and_sub(&ref_count, 1);
	if (ref_count == 0)
	{
		delete this;
		return 0;
	}

	return ref_count;
}

unsigned short MsgDumperWrapper::set_severity(unsigned short linux_severity, unsigned short facility)
{
	unsigned short ret = fp_msg_dumper_set_severity(linux_severity, facility);
	if (CHECK_FAILURE(ret))
		fprintf(stderr, "%sfp_msg_dumper_set_severity() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
	return MSG_DUMPER_SUCCESS;
}

unsigned short MsgDumperWrapper::get_severity(unsigned short facility)const
{
	return fp_msg_dumper_get_severity(facility);
}

unsigned short MsgDumperWrapper::set_severity_by_name(const char* severity_name, const char* facility_name)
{
	unsigned short linux_severity = get_linux_severity_from_string(severity_name);
	unsigned short facility = get_facility_from_string(facility_name);
	return set_severity(linux_severity, facility);
}

unsigned short MsgDumperWrapper::get_severity_by_name(const char* facility_name)const
{
	unsigned short facility = get_facility_from_string(facility_name);
	return get_severity(facility);
}

unsigned short MsgDumperWrapper::set_log_severity(unsigned short linux_severity)
{
	return set_severity(linux_severity, MSG_DUMPER_FACILITY_LOG);
}

unsigned short MsgDumperWrapper::set_syslog_severity(unsigned short linux_severity)
{
	return set_severity(linux_severity, MSG_DUMPER_FACILITY_SYSLOG);
}

unsigned short MsgDumperWrapper::get_log_severity()const
{
	return get_severity(MSG_DUMPER_FACILITY_LOG);
}

unsigned short MsgDumperWrapper::get_syslog_severity()const
{
	return get_severity(MSG_DUMPER_FACILITY_SYSLOG);
}

unsigned short MsgDumperWrapper::set_log_severity_by_name(const char* severity_name)
{
	unsigned short linux_severity = get_linux_severity_from_string(severity_name);
	return set_log_severity(linux_severity);
}

unsigned short MsgDumperWrapper::set_syslog_severity_by_name(const char* severity_name)
{
	unsigned short linux_severity = get_linux_severity_from_string(severity_name);
	return set_syslog_severity(linux_severity);
}

const char* MsgDumperWrapper::get_log_severity_by_name()const
{
	unsigned short linux_severity = get_log_severity();
	unsigned short msg_dumper_severity = transform_linux_severity_to_msg_dumper_severity(linux_severity);
	return SEVERITY_NAME[msg_dumper_severity];
}

const char* MsgDumperWrapper::get_syslog_severity_by_name()const
{
	unsigned short linux_severity = get_syslog_severity();
	unsigned short msg_dumper_severity = transform_linux_severity_to_msg_dumper_severity(linux_severity);
	return SEVERITY_NAME[msg_dumper_severity];
}

unsigned short MsgDumperWrapper::set_config(const char* config_name, const char* config_value)
{
	assert(config_name != NULL && "config_name should NOT be NULL");
	assert(config_value != NULL && "config_value should NOT be NULL");
	static const int FILE_PATH_SIZE = 256;
	static const char* COMMAND_FORMAT = "sed -i 's/^%s=.*/%s=%s/g' %s";
	static const int COMMAND_SIZE = 512;
	char current_working_directory[FILE_PATH_SIZE];
	getcwd(current_working_directory, FILE_PATH_SIZE);
	char conf_filepath[FILE_PATH_SIZE];
	snprintf(conf_filepath, FILE_PATH_SIZE, "%s/%s/%s", current_working_directory, CONF_FOLDER, CONF_FILENAME);
	char command[COMMAND_SIZE];
	snprintf(command, COMMAND_SIZE, COMMAND_FORMAT, config_name, config_name, config_value, conf_filepath);
	// fprintf(stderr, "Command: %s\n", command);
	FILE* fp_set = popen(command, "w");
	if (fp_set == NULL)
	{
		fprintf(stderr, "%spopen() fails, due to: %s\n", MSG_DUMPER_ERROR_COLOR, strerror(errno));
		return MSG_DUMPER_FAILURE_SYSTEM_API;
	}
	pclose(fp_set);
	return MSG_DUMPER_SUCCESS;
}

unsigned short MsgDumperWrapper::get_config(const char* config_name, char* config_value)const
{
	assert(config_name != NULL && "config_name should NOT be NULL");
	assert(config_value != NULL && "config_value should NOT be NULL");

	static const char* COMMAND_FORMAT = "cat %s | grep '%s='";
	static const int FILE_PATH_SIZE = 256;
	static const int COMMAND_SIZE = 512;
	static const int LINE_SIZE = 64;
	char current_working_directory[FILE_PATH_SIZE];
	getcwd(current_working_directory, FILE_PATH_SIZE);
	char conf_filepath[FILE_PATH_SIZE];
	snprintf(conf_filepath, FILE_PATH_SIZE, "%s/%s/%s", current_working_directory, CONF_FOLDER, CONF_FILENAME);
	char command[COMMAND_SIZE];
	snprintf(command, COMMAND_SIZE, COMMAND_FORMAT, conf_filepath, config_name);
	FILE* fp_get = popen(command, "r");
	if (fp_get == NULL)
	{
		fprintf(stderr, "%spopen() fails, due to: %s\n", MSG_DUMPER_ERROR_COLOR, strerror(errno));
		return MSG_DUMPER_FAILURE_SYSTEM_API;
	}
	unsigned short ret = MSG_DUMPER_SUCCESS;
	char line[LINE_SIZE];
	char* buf = line;
	char *line_config_name = NULL, *line_config_value = NULL;
	if (fgets(line, LINE_SIZE, fp_get) == NULL)
	{
		fprintf(stderr, "%sfgets() fails, due to: %s\n", MSG_DUMPER_ERROR_COLOR, strerror(errno));
		ret = MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
		goto OUT;
	}
	line_config_name = strtok(buf, "=");
	line_config_value = strtok(NULL, "\t\n\r");
	if (line_config_name == NULL || line_config_value == NULL)
	{
		fprintf(stderr, "%sIncorrect config: %s\n", MSG_DUMPER_ERROR_COLOR, line);
		ret = MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
		goto OUT;
	}
	// printf("*** Parsing *** Line: %s, Name: %s, Value: %s\n", line, line_config_name, line_config_value);
	memcpy(config_value, line_config_value, strlen(line_config_value) + 1);
	// printf("*** Result *** Value: %s\n", config_value);
OUT:
	pclose(fp_get);
	return ret;
}

unsigned short MsgDumperWrapper::set_log_severity_config(unsigned short linux_severity)
{
	unsigned short msg_dumper_severity = transform_linux_severity_to_msg_dumper_severity(linux_severity);
	return set_config("Log", SEVERITY_NAME[msg_dumper_severity]);
}

unsigned short MsgDumperWrapper::set_syslog_severity_config(unsigned short linux_severity)
{
	unsigned short msg_dumper_severity = transform_linux_severity_to_msg_dumper_severity(linux_severity);
	return set_config("Syslog", SEVERITY_NAME[msg_dumper_severity]);
}

unsigned short MsgDumperWrapper::get_log_severity_config()const
{
	static const int SEVERITY_STRING_SIZE = 16;
	static char severity_name[SEVERITY_STRING_SIZE];
	unsigned short ret = get_config("Log", severity_name);
	if (CHECK_FAILURE(ret))
		return ret;
	unsigned short linux_severity = get_linux_severity_from_string(severity_name);
	return linux_severity;
}

unsigned short MsgDumperWrapper::get_syslog_severity_config()const
{
	static const int SEVERITY_STRING_SIZE = 16;
	static char severity_name[SEVERITY_STRING_SIZE];
	unsigned short ret = get_config("Syslog", severity_name);
	if (CHECK_FAILURE(ret))
		return ret;
	unsigned short linux_severity = get_linux_severity_from_string(severity_name);
	return linux_severity;
}

unsigned short MsgDumperWrapper::write(const char* file_name, unsigned long line_no, unsigned short linux_severity, const char* msg)
{
	// fprintf(stderr, "MsgDumperWrapper::write [linux_severity: %d, message: %s]\n", linux_severity, msg);
	unsigned short ret = MSG_DUMPER_SUCCESS;
	pthread_mutex_lock(&write_msg_mut);
	string msg_title(get_code_pos_str(file_name, line_no));
	string msg_body(msg);
	string msg_whole = msg_title + msg_body;
	ret = fp_msg_dumper_write_msg(linux_severity, msg_whole.c_str());
	pthread_mutex_unlock(&write_msg_mut);
	if (CHECK_FAILURE(ret))
		fprintf(stderr, "%sfp_msg_dumper_write_msg() fails, resaon: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
	return ret;
}

unsigned short MsgDumperWrapper::format_write(const char* file_name, unsigned long line_no, unsigned short linux_severity, const char* msg_fmt, ...)
{
	unsigned short ret = MSG_DUMPER_SUCCESS;
	pthread_mutex_lock(&write_msg_mut);
	string msg_title(get_code_pos_str(file_name, line_no));
	va_list ap;
	va_start(ap, msg_fmt);
	string msg_body(get_format_str_va(msg_fmt, ap));
	va_end(ap);
    // FORMAT_WRITE(linux_severity, msg_fmt);
    string msg_whole = msg_title + msg_body;
	ret = fp_msg_dumper_write_msg(linux_severity, msg_whole.c_str());
	pthread_mutex_unlock(&write_msg_mut);
	if (CHECK_FAILURE(ret))
		fprintf(stderr, "%sfp_msg_dumper_write_msg() fails, resaon: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
	return ret;
}

// #define FORMAT_WRITE_EX(priority, fmt)\
// do{\
// va_list ap;\
// va_start(ap, msg_fmt);\
// ret = format_write_va(priority, fmt, ap);\
// va_end(ap);\
// }while(0)

// unsigned short MsgDumperWrapper::format_write_ex(unsigned short linux_severity, const char* msg_fmt, ...)
// {
// 	static unsigned short ret = MSG_DUMPER_SUCCESS;
//     FORMAT_WRITE_EX(linux_severity, msg_fmt);
//     return ret;
// }

// unsigned short MsgDumperWrapper::error(const char* msg){return write(LOG_ERR, msg);}
// unsigned short MsgDumperWrapper::format_error(const char* msg_fmt, ...)
// {
// 	static unsigned short ret = MSG_DUMPER_SUCCESS;
//     FORMAT_WRITE(LOG_ERR, msg_fmt);
//     return ret;
// }

// unsigned short MsgDumperWrapper::warn(const char* msg){return write(LOG_WARNING, msg);}
// unsigned short MsgDumperWrapper::format_warn(const char* msg_fmt, ...)
// {
// 	static unsigned short ret = MSG_DUMPER_SUCCESS;
//     FORMAT_WRITE(LOG_WARNING, msg_fmt);
//     return ret;
// }

// unsigned short MsgDumperWrapper::info(const char* msg){return write(LOG_INFO, msg);}
// unsigned short MsgDumperWrapper::format_info(const char* msg_fmt, ...)
// {
// 	static unsigned short ret = MSG_DUMPER_SUCCESS;
//     FORMAT_WRITE(LOG_INFO, msg_fmt);
//     return ret;
// }

// unsigned short MsgDumperWrapper::debug(const char* msg){return write(LOG_DEBUG, msg);}
// unsigned short MsgDumperWrapper::format_debug(const char* msg_fmt, ...)
// {
// 	static unsigned short ret = MSG_DUMPER_SUCCESS;
//     FORMAT_WRITE(LOG_DEBUG, msg_fmt);
//     return ret;
// }

const char* MsgDumperWrapper::get_error_description()const
{
	return fp_msg_dumper_get_error_description();
}
