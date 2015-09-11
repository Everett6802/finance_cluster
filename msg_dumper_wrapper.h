#ifndef MSG_DUMPER_WRAPPER_H
#define MSG_DUMPER_WRAPPER_H

#include "msg_dumper.h"
#include "msg_cluster_common.h"


class MsgDumperWrapper
{
private:
	static MsgDumperWrapper* instance;
	static const char* MSG_DUMPER_ERROR_COLOR;
	static unsigned short SEVERITY_ARR[];
	static unsigned short FACILITY;
	static const char* FACILITY_NAME[];

	int ref_count;
	void* api_handle;
	FP_msg_dumper_initialize fp_msg_dumper_initialize;
	FP_msg_dumper_get_version fp_msg_dumper_get_version;
	FP_msg_dumper_set_severity fp_msg_dumper_set_severity;
	FP_msg_dumper_set_facility fp_msg_dumper_set_facility;
	FP_msg_dumper_write_msg fp_msg_dumper_write_msg;
	FP_msg_dumper_deinitialize fp_msg_dumper_deinitialize;
	FP_msg_dumper_get_error_description fp_msg_dumper_get_error_description;

	MsgDumperWrapper();

	unsigned short initialize();
	void deinitialize();
	bool export_api();

public:
	~MsgDumperWrapper(){deinitialize();}

	static MsgDumperWrapper* get_instance();
	int addref();
	int release();

	unsigned short write(unsigned short syslog_priority, const char* msg);
};

#endif
