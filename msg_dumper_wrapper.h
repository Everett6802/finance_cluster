#ifndef MSG_DUMPER_WRAPPER_H
#define MSG_DUMPER_WRAPPER_H

#include "msg_dumper.h"


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
	~MsgDumperWrapper(){deinitialize();}

	static MsgDumperWrapper* get_instance();
	int addref();
	int release();

	unsigned short write(unsigned short syslog_priority, const char* msg);
	const char* get_error_description()const;
};

#endif
