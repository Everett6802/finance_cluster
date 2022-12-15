#ifndef SYSTEM_OPERATOR_H
#define SYSTEM_OPERATOR_H

#include "common.h"


class SystemOperator : public INotify
{
	DECLARE_MSG_DUMPER()
	static unsigned int DEFAULT_SLEEP_TIME_IN_MILLISEC;

private:
	PINOTIFY observer;
	char* host_network;
	int host_netmask_digits;

// For system info
	unsigned short get_line_info(const char* line, std::string& data_info);
	unsigned short get_cpu_info(std::string& cpu_info);
	unsigned short get_memory_info(std::string& memory_info);
	unsigned short get_disk_info(std::string& disk_info);
	unsigned short get_network_info(std::string& network_info);
	unsigned short get_os_info(std::string& os_info);
// For system monitor
	unsigned short get_cpu_usage(std::string& cpu_usage, unsigned int sleep_time_in_millisec);
public:
	SystemOperator(PINOTIFY notify);
	virtual ~SystemOperator();

	unsigned short initialize(const char* network, int netmask_digits);
	unsigned short deinitialize();

	unsigned short get_system_info(std::string& system_info);
	unsigned short get_system_monitor_data(std::string& system_monitor_data);

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};

typedef SystemOperator* PSYSTEM_OPERATOR;

#endif