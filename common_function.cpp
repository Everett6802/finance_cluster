#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "common.h"


using namespace std;

unsigned short get_local_interface_ip(map<string, string>& interface_ip_map)
{
	struct ifaddrs* ifAddrStruct = NULL;
	void* tmpAddrPtr = NULL;

	getifaddrs(&ifAddrStruct);
// Traverse the ethernet card on local PC
	STATIC_WRITE_DEBUG("Traverse the all IPs bounded to local network interface...");
	// bool found = false;
	for (struct ifaddrs* ifa = ifAddrStruct ; ifa != NULL ; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) // check it is IP4
		{
			tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			string local_interface(ifa->ifa_name);
			string local_ip(addressBuffer);
			// STATIC_WRITE_FORMAT_DEBUG("%s IPv4 Address %s", local_interface.c_str(), local_ip.c_str());
			interface_ip_map[local_interface] = local_ip;
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6) // check it is IP6
		{
			// tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
			// char addressBuffer[INET6_ADDRSTRLEN];
			// inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			// STATIC_WRITE_FORMAT_DEBUG("%s IPv6 Address %s", ifa->ifa_name, addressBuffer);
		}
	}

// Release the resource
	if (ifAddrStruct!=NULL)
		freeifaddrs(ifAddrStruct);

	return RET_SUCCESS;
}

bool check_file_exist(const char* filepath)
{
	assert(filepath != NULL && "filepath should NOT be NULL");
	struct stat dummy;
	return (stat(filepath, &dummy) == 0);
}

bool check_config_file_exist(const char* config_filename)
{
	CREATE_PROJECT_FILEPATH(file_path, CONFIG_FOLDER_NAME, config_filename)
	return check_file_exist(file_path);
}

unsigned short get_file_line_count(unsigned int &line_count, const char* filepath)
{
	if (!check_file_exist(filepath))
	{
		STATIC_WRITE_FORMAT_ERROR("The file[%s] does NOT exist", filepath);
		return RET_FAILURE_NOT_FOUND;
	}
	FILE* fp = fopen(filepath, "r");
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to open the file[%s], due to: %s", filepath, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	static const int BUF_SIZE = 512;
	static char line_buf[BUF_SIZE];
	line_count = 0;
	while (fgets(line_buf, BUF_SIZE, fp) != NULL) line_count++;
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return RET_SUCCESS;	
}

unsigned short read_file_lines_ex(std::list<std::string>& line_list, const char* filepath, const char* file_read_attribute, char data_seperate_character)
{
	if (!check_file_exist(filepath))
	{
		STATIC_WRITE_FORMAT_ERROR("The file[%s] does NOT exist", filepath);
		return RET_FAILURE_NOT_FOUND;		
	}
	FILE* fp = fopen(filepath, file_read_attribute);
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to open the file[%s], due to: %s", filepath, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	static const int BUF_SIZE = 512;
	static char line_buf[BUF_SIZE];
	int last_character_in_string_index = 0;
	while (fgets(line_buf, BUF_SIZE, fp) != NULL) 
	{
		if (line_buf[0] == '\n' || line_buf[0] == '#')
			continue;
		last_character_in_string_index = strlen(line_buf) - 1;
		if (line_buf[last_character_in_string_index] == '\n')
			line_buf[last_character_in_string_index] = '\0';
		string line_str(line_buf);
		line_list.push_back(line_str);
	}
// OUT:
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return RET_SUCCESS;
}

unsigned short read_config_file_lines_ex(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_file_read_attribute, const char* config_folderpath)
{
	CREATE_PROJECT_FILEPATH(filepath, CONFIG_FOLDER_NAME, config_filename);
	return read_file_lines_ex(conf_line_list, filepath, config_file_read_attribute);
}

unsigned short read_config_file_lines(std::list<std::string>& conf_line_list, const char* config_filename, const char* config_folderpath)
{
	return read_config_file_lines_ex(conf_line_list, config_filename, "r", config_folderpath);
}
