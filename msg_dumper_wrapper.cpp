#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <string>
#include "msg_dumper_wrapper.h"


using namespace std;

#define CHECK_FAILURE(x) ((x != MSG_DUMPER_SUCCESS) ? true : false)

MsgDumperWrapper* MsgDumperWrapper::instance = NULL;
const char* MsgDumperWrapper::MSG_DUMPER_ERROR_COLOR = "\x1B[31m";
const char* MsgDumperWrapper::FACILITY_NAME[] = {"Log", "Com", "Sql", "Remote", "Syslog"};
const int MsgDumperWrapper::FACILITY_NAME_SIZE = sizeof(FACILITY_NAME) / sizeof(FACILITY_NAME[0]);
const unsigned short MsgDumperWrapper::FACILITY_FLAG[] = {MSG_DUMPER_FACILITY_LOG, MSG_DUMPER_FACILITY_COM, MSG_DUMPER_FACILITY_SQL, MSG_DUMPER_FACILITY_REMOTE, MSG_DUMPER_FACILITY_SYSLOG};
const char* MsgDumperWrapper::SEVERITY_NAME[] = {"ERROR", "WARN", "INFO", "DEBUG"};
const int MsgDumperWrapper::SEVERITY_NAME_SIZE = sizeof(SEVERITY_NAME) / sizeof(SEVERITY_NAME[0]);
const char* MsgDumperWrapper::CONF_FOLDER = "conf";
const char* MsgDumperWrapper::CONF_FILENAME = "dumper_param.conf";

MsgDumperWrapper::MsgDumperWrapper() :
	ref_count(0),
	api_handle(NULL),
	fp_msg_dumper_initialize(NULL),
	fp_msg_dumper_get_version(NULL),
	fp_msg_dumper_set_severity(NULL),
	fp_msg_dumper_set_facility(NULL),
	fp_msg_dumper_write_msg(NULL),
	fp_msg_dumper_deinitialize(NULL),
	fp_msg_dumper_get_error_description(NULL)
{
}

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
	printf("API version: (%d.%d.%d)\n", major_version, minor_version, build_version);

// Parse the parameters from the config file
//	printf("Parse the config file\n");
	ret = parse_config();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfparse_config() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		return ret;
	}

// Initialize the library
	printf("Initialize the library\n");
	ret = fp_msg_dumper_initialize();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfp_msg_dumper_initialize() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		return ret;
	}

	return ret;
}

void MsgDumperWrapper::deinitialize()
{
// De-initialize the library
	printf("Close the library\n");
	fp_msg_dumper_deinitialize();

// Close the handle
	if (api_handle != NULL)
	{
		dlclose(api_handle);
		api_handle = NULL;
	}
}

unsigned short MsgDumperWrapper::parse_config()
{
	static const int BUF_SIZE = 256;
	char current_working_directory[BUF_SIZE];
	getcwd(current_working_directory, sizeof(current_working_directory));
	char config_filename[BUF_SIZE];
	snprintf(config_filename, BUF_SIZE, "%s/%s/%s", current_working_directory, CONF_FOLDER, CONF_FILENAME);
	printf("Parse the config file: %s\n", config_filename);

	FILE *fp = fopen(config_filename, "r");
	if (fp == NULL)
	{
		fprintf(stderr, "%sfopen() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, strerror(errno));
		return MSG_DUMPER_FAILURE_OPEN_FILE;
	}

	unsigned short total_facility_flag = 0x0;
	unsigned short ret = MSG_DUMPER_SUCCESS;
// Parse the config file
	const char* stop_flag = "[";
	int stop_flag_len = strlen(stop_flag);
	char buf[BUF_SIZE];

	while (fgets(buf, BUF_SIZE, fp) != NULL)
	{
		if (strncmp(buf, stop_flag, stop_flag_len) == 0)
			break;

		if (buf[0] == '\n')
			break;
		int end_pos = -1;
		int split_pos = -1;
// Check the format of config entry is correct
		for (int i = 0 ; i < BUF_SIZE ; i++)
		{
			if (buf[i] == '=')
				split_pos = i;
			else if (buf[i] == '\n')
			{
				end_pos = i;
				buf[i] = '\0';
				break;
			}
		}
		if (end_pos == -1 || split_pos == -1)
		{
			fprintf(stderr, "%sIncorrect config format, split pos: %d, end pos: %d\n", MSG_DUMPER_ERROR_COLOR, split_pos, end_pos);
			ret = MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
			break;
		}

		string config(buf);
//		WRITE_DEBUG_FORMAT_LOGGING(STRING_SIZE, "***Config*** content: %s, split pos: %d", config.c_str(), split_pos);
		char facility[16];
		snprintf(facility, 16, "%s", config.substr(0, split_pos).c_str());
		char severity[16];
		snprintf(severity, 16, "%s", config.substr(split_pos + 1).c_str());
		printf("***Config***\nfacility: %s, severity: %s\n", facility, severity);

//		unsigned short facility_flag;
		int facility_index = -1;
// Set facility
		for (int i = 0 ; i < FACILITY_NAME_SIZE ; i++)
		{
			if (strcmp(facility, FACILITY_NAME[i]) == 0)
			{
				facility_index = i;
				break;
			}
		}
		if (facility_index == -1)
		{
			fprintf(stderr, "%sUnknown facility: %s\n", MSG_DUMPER_ERROR_COLOR, facility);
			ret = MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
			goto OUT;
		}
		total_facility_flag |= FACILITY_FLAG[facility_index];
// Set severity
		for (int i = 0 ; i < SEVERITY_NAME_SIZE ; i++)
		{
			if (strcmp(severity, SEVERITY_NAME[i]) == 0)
			{
// Assign the value in the config to the member variable
				switch(i)
				{
					case MSG_DUMPER_SEVIRITY_ERROR:
					case MSG_DUMPER_SEVIRITY_WARN:
					case MSG_DUMPER_SEVIRITY_INFO:
					case MSG_DUMPER_SEVIRITY_DEBUG:
					{
						printf("Set severity of facility[%s] to %s\n", FACILITY_NAME[facility_index], SEVERITY_NAME[i]);
						ret = fp_msg_dumper_set_severity(i, FACILITY_FLAG[facility_index]);
						if (CHECK_FAILURE(ret))
						{
							fprintf(stderr, "%sfp_msg_dumper_set_severity() fails, reason: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());
							goto OUT;
						}
					}
					break;
					default:
					{
						fprintf(stderr, "%sUnknown severity: %s\n", MSG_DUMPER_ERROR_COLOR, severity);
						ret = MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
						goto OUT;
					}
					break;
				}
			}
		}
	}
	printf("Set facility to %d\n", total_facility_flag);
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


unsigned short MsgDumperWrapper::write(unsigned short syslog_priority, const char* msg)
{
#if 0
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#endif

	unsigned short msg_severity;
	switch(syslog_priority)
	{
	case LOG_DEBUG:
		msg_severity = MSG_DUMPER_SEVIRITY_DEBUG;
		break;
	case LOG_INFO:
		msg_severity = MSG_DUMPER_SEVIRITY_INFO;
		break;
	case LOG_WARNING:
	case LOG_NOTICE:
		msg_severity = MSG_DUMPER_SEVIRITY_WARN;
		break;
	default:
		msg_severity = MSG_DUMPER_SEVIRITY_ERROR;
		break;
	}

	unsigned short ret = fp_msg_dumper_write_msg(msg_severity, msg);
	if (CHECK_FAILURE(ret))
		fprintf(stderr, "%sfp_msg_dumper_write_msg() fails, resaon: %s\n", MSG_DUMPER_ERROR_COLOR, fp_msg_dumper_get_error_description());

	return ret;
}

const char* MsgDumperWrapper::get_error_description()const
{
	return fp_msg_dumper_get_error_description();
}
