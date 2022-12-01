#include "system_operator.h"

using namespace std;


SystemOperator::SystemOperator(PINOTIFY notify) : 
	host_network(NULL),
	host_netmask_digits(0),
	observer(notify)
{
	IMPLEMENT_MSG_DUMPER()
}

SystemOperator::~SystemOperator()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in SystemOperator::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	RELEASE_MSG_DUMPER()
}

unsigned short SystemOperator::initialize(const char* network, int netmask_digits)
{
	assert(network != NULL && "network should NOT be NULL");
	host_network = strdup(network);
	if (host_network == NULL)
		throw bad_alloc();
	host_netmask_digits = netmask_digits;
	return RET_SUCCESS;
}

unsigned short SystemOperator::deinitialize()
{
	if (host_network != NULL)
	{
		free(host_network);
		host_network = NULL;
	}
	return RET_SUCCESS;	
}

unsigned short SystemOperator::get_line_info(const char* line, std::string& data_info)
{
	assert(line != NULL && "line should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
    char* line_new = strdup(line); 
    if (line_new == NULL)
    	throw bad_alloc();
    char* line_tmp = line_new;
    char* token; 
    char* rest = NULL;
    char* token_ptr = NULL;
    char* token_ptr_end = NULL;
    size_t data_info_pos = 0;
    size_t data_info_len = 0;
   	// string data_info;
	token = strtok_r(line_tmp, ":", &rest);
	token = strtok_r(NULL, ":", &rest);
	if (token == NULL)
	{
		WRITE_FORMAT_ERROR("Fail to parse the line: %s", line);
		ret = RET_FAILURE_RUNTIME;
		goto OUT;		
	}
// Find the start index
	token_ptr = token;
	while (isspace(*token_ptr) && *token_ptr != '\0') token_ptr++;
	data_info_pos = token_ptr - token;
// Find the string length
	token_ptr_end = token_ptr;
	while (*token_ptr_end != '\r' && *token_ptr_end != '\n' && *token_ptr_end != '\0') token_ptr_end++;
	data_info_len = token_ptr_end - token_ptr;
// Get the correct string
	data_info = string(token).substr(data_info_pos, data_info_len);
	// printf("OS: data_info: %s\n", data_info.c_str());
	// os_info += (data_info + string("\n")); 
OUT:
	if (line_new != NULL)
	{
		free(line_new);
		line_new = NULL;
	}
	return ret;
}

unsigned short SystemOperator::get_cpu_info(std::string& cpu_info)
{
	static const char* CMD_MODEL_NAME = "lscpu | grep \"Model name\"";
	static const char* CMD_CORE_NUMBER = "lscpu | grep \"CPU(s):\" | grep -v \"NUMA\"";
	static const char* CMDS[] = {CMD_MODEL_NAME, CMD_CORE_NUMBER};
	static const char* DATA_FIELDS[] = {"   Model:  ", "   Core:  "};
	static const int CMDS_SIZE = sizeof(CMDS) / sizeof(CMDS[0]);
	cpu_info = string("CPU:\n");
	unsigned short ret = RET_SUCCESS;
	for (int i = 0 ; i < CMDS_SIZE ; i++)
	{

		FILE *fp = popen(CMDS[i], "r");
		char *line = NULL;
		size_t line_len = 0;
	   	string data_info;
		if (getline(&line, &line_len, fp) == -1)
		{
			WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
			ret = RET_FAILURE_SYSTEM_API;
			goto OUT;
		}
		ret = get_line_info(line, data_info);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("get_line_info() fails, due to: %s", GetErrorDescription(ret));
			goto OUT;		
		}
		// memory_info += (data_info + string("\n"));
		cpu_info += (string(DATA_FIELDS[i]) + data_info + string("\n"));
OUT:
		if (line != NULL)
		{
			free(line);
			line = NULL;
		}
		if (fp != NULL)
		{
			pclose(fp);	
			fp = NULL;
		}
	}
	return ret;
}

unsigned short SystemOperator::get_memory_info(std::string& memory_info)
{
	static const char* CMD = "lsmem | grep \"Total online memory\"";
	memory_info = string("Memory:  ");
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(CMD, "r");
	char *line = NULL;
	size_t line_len = 0;
   	string data_info;
	if (getline(&line, &line_len, fp) == -1)
	{
		WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT;
	}
	ret = get_line_info(line, data_info);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("get_line_info() fails, due to: %s", GetErrorDescription(ret));
		goto OUT;		
	}
	memory_info += (data_info + string("\n"));
OUT:
	if (line != NULL)
	{
		free(line);
		line = NULL;
	}
	if (fp != NULL)
	{
		pclose(fp);	
		fp = NULL;
	}
	return ret;
}

unsigned short SystemOperator::get_disk_info(std::string& disk_info)
{
	static const char* CMD = "lsblk | grep sd | grep \":0\" | awk '{print $4}'";
	disk_info = string("Disk:  ");
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(CMD, "r");
	char *line = NULL;
	size_t line_len = 0;
   	string data_info;
	if (getline(&line, &line_len, fp) == -1)
	{
		WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT;
	}
	data_info = string(line);
	// printf("line: %s", line);
	disk_info += (data_info /*+ string("\n")*/);
OUT:
	if (line != NULL)
	{
		free(line);
		line = NULL;
	}
	if (fp != NULL)
	{
		pclose(fp);	
		fp = NULL;
	}
	return ret;
}

unsigned short SystemOperator::get_network_info(std::string& network_info)
{
	static const char* CMD_NETWORK = "ifconfig | grep inet | grep netmask | awk '{print $2, $4}'";
	static const char* CMD_GATEWAY = "route -n | grep -E '^0.0.0.0' | awk '{print $2}'";
	network_info = string("Network:\n");
	unsigned short ret = RET_SUCCESS;
	char *line = NULL;
	size_t line_len = 0;
    char* rest = NULL;
    char* line_tmp = NULL; 
// Find the IP and netmask
	FILE *fp_network = popen(CMD_NETWORK, "r");
	bool found = false;
	while (getline(&line, &line_len, fp_network) != -1)
	{
		line_tmp = line;
		char* ip = strtok_r(line_tmp, " ", &rest);
		char* netmask = strtok_r(NULL, " ", &rest);
		// printf ("ip: %s, netmaks: %s\n", ip, netmask);
		IPv4Addr ipv4_addr(ip);
		if (ipv4_addr.is_same_network(host_netmask_digits, host_network))
		{
			network_info += (string("   IP:  ") + string(ip) + string("\n"));
			network_info += (string("   Netmask:  ") + string(netmask)/* + string("\n")*/);
			found = true;
		}
		if (line != NULL)
		{
			free(line);
			line = NULL;
			line_len = 0;
		}
		if (found)
			break;
	}
	if (fp_network != NULL)
	{
		pclose(fp_network);
		fp_network = NULL;
	}
	if (!found)
	{
		WRITE_FORMAT_ERROR("Fails to find the network: %s, %d", host_network, host_netmask_digits);
		return RET_FAILURE_NOT_FOUND;
	}
// Find the Gateway
	FILE *fp_gateway = popen(CMD_GATEWAY, "r");
	if (getline(&line, &line_len, fp_gateway) == -1)
	{
		WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT2;		
	}
	network_info += (string("   Gateway:  ") + string(line)/* + string("\n")*/);
OUT2:
	if (line != NULL)
	{
		free(line);
		line = NULL;
		line_len = 0;
	}
	if (fp_gateway != NULL)
	{
		pclose(fp_gateway);
		fp_gateway = NULL;
	}
	return ret;
}

unsigned short SystemOperator::get_os_info(string& os_info)
{
	static const char* CMD = "lsb_release -a | grep Description";
	os_info = string("OS:  ");
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(CMD, "r");
	char *line = NULL;
	size_t line_len = 0;
    char* token; 
    char* rest = NULL;
    char* line_tmp = NULL; 
    char* token_ptr = NULL;
    char* token_ptr_end = NULL;
    size_t data_info_pos = 0;
    size_t data_info_len = 0;
   	string data_info;
	if (getline(&line, &line_len, fp) == -1)
	{
		WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT;
	}
	line_tmp = line;
	token = strtok_r(line_tmp, ":", &rest);
	token = strtok_r(NULL, ":", &rest);
	if (token == NULL)
	{
		WRITE_FORMAT_ERROR("Fail to parse the line: %s", line);
		ret = RET_FAILURE_RUNTIME;
		goto OUT;		
	}
// Find the start index of the linux platform
	token_ptr = token;
	while (isspace(*token_ptr) && *token_ptr != '\0') token_ptr++;
	data_info_pos = token_ptr - token;
// Find the string length of the linux platform
	token_ptr_end = token_ptr;
	while (*token_ptr_end != '\r' && *token_ptr_end != '\n' && *token_ptr_end != '\0') token_ptr_end++;
	data_info_len = token_ptr_end - token_ptr;
// Get the correct string of linux platform
	data_info = string(token).substr(data_info_pos, data_info_len);
	// printf("OS: data_info: %s\n", data_info.c_str());
	os_info += (data_info + string("\n")); 
OUT:
	if (line != NULL)
	{
		free(line);
		line = NULL;
	}
	pclose(fp);
	return ret;
}

unsigned short SystemOperator::get_system_info(string& system_info)
{
	unsigned short ret = RET_SUCCESS;
	// char system_info_buf[SYSTEM_INFO_BUF_SIZE];
// Get CPU info
	string cpu_info;
	ret = get_cpu_info(cpu_info);
	if (CHECK_FAILURE(ret))
		return ret;
	system_info += cpu_info;
// Get Memroy info
	string memory_info;
	ret = get_memory_info(memory_info);
	if (CHECK_FAILURE(ret))
		return ret;
	system_info += memory_info;
	// printf ("system_info: %s\n", system_info.c_str());
// Get Disk info
	string disk_info;
	ret = get_disk_info(disk_info);
	if (CHECK_FAILURE(ret))
		return ret;
	system_info += disk_info;
// Get Network info
	string network_info;
	ret = get_network_info(network_info);
	if (CHECK_FAILURE(ret))
		return ret;
	system_info += network_info;
// Get OS info
	string os_info;
	ret = get_os_info(os_info);
	if (CHECK_FAILURE(ret))
		return ret;
	system_info += os_info;
	// printf ("system_info: %s\n", system_info.c_str());
	// snprintf(system_info_buf, SYSTEM_INFO_BUF_SIZE, "%s: %s\n", OS_INFO, os_info.c_str());
	// system_info += string(system_info_buf);
	return RET_SUCCESS;
}

unsigned short SystemOperator::get_system_monitor_data(std::string& system_monitor_data)
{
	unsigned short ret = RET_SUCCESS;
	system_monitor_data = string("This is only a test\n");
	return ret;
}

unsigned short SystemOperator::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short SystemOperator::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}
