#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <dlfcn.h>
#include <syslog.h>
#include "msg_dumper_wrapper.h"


MsgDumperWrapper* MsgDumperWrapper::instance = NULL;
char* MsgDumperWrapper::MSG_DUMPER_ERROR_COLOR = "\x1B[31m";
unsigned short MsgDumperWrapper::SEVERITY_ARR[] = {MSG_DUMPER_SEVIRITY_DEBUG};
unsigned short MsgDumperWrapper::FACILITY = MSG_DUMPER_FACILITY_LOG;
char* MsgDumperWrapper::FACILITY_NAME[] = {"Log", "Com", "Sql", "Remote", "Syslog"};

MsgDumperWrapper::MsgDumperWrapper() :
	ref_count(0),
//	severity(MSG_DUMPER_SEVIRITY_ERROR),
//	facility(MSG_DUMPER_FACILITY_LOG),
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
		exit(EXIT_FAILURE);
	}

// Export the APIs
	if (!export_api())
	{
		fprintf(stderr, "%sFail to export the APIs\n", MSG_DUMPER_ERROR_COLOR);
		exit(EXIT_FAILURE);
	}

	unsigned char major_version;
	unsigned char minor_version;
	fp_msg_dumper_get_version(major_version, minor_version);
	printf("API version: (%d.%d)\n", major_version, minor_version);

// Count the amount of device type
	int device_type_amount = 0;
	unsigned short flag = 0x1;
	while (MSG_DUMPER_FACILITY_ALL & flag)
	{
		device_type_amount++;
		flag <<= 1;
	}

// Set severity
	flag = 0x1;
	for (int i = 0, severity_cnt = 0 ; i < device_type_amount ; i++)
	{
		if (flag & FACILITY)
		{
			printf("Set severity of facility[%s] to %d\n", FACILITY_NAME[i], SEVERITY_ARR[severity_cnt]);
			ret = fp_msg_dumper_set_severity(SEVERITY_ARR[severity_cnt], flag);
			if (CHECK_FAILURE(ret))
			{
				fprintf(stderr, "%sfp_msg_dumper_set_severity() fails, due to %d, resaon: %s\n", MSG_DUMPER_ERROR_COLOR, ret, fp_msg_dumper_get_error_description());
				exit(EXIT_FAILURE);
			}
			severity_cnt++;
		}
		flag <<= 1;
	}
// Set facility
	printf("Set facility to :%d\n", FACILITY);
	ret = fp_msg_dumper_set_facility(FACILITY);
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfp_msg_dumper_set_facility() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		exit(EXIT_FAILURE);
	}

// Initialize the library
	printf("Initialize the library\n");
	ret = fp_msg_dumper_initialize();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "%sfp_msg_dumper_initialize() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		exit(EXIT_FAILURE);
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
	{
		fprintf(stderr, "%sfp_msg_dumper_write_msg() fails, due to %d\n", MSG_DUMPER_ERROR_COLOR, ret);
		exit(EXIT_FAILURE);
	}

	return ret;
}
