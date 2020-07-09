#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pwd.h>
#include <time.h>
#include <stdexcept>
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
	if (stat(filepath, &dummy) != 0)
	{
		if (errno == ENOENT)
			return false;
		else
		{
			static const int ERR_BUF_SIZE = 256;
			char err_buf[ERR_BUF_SIZE];
			memset(err_buf, 0x0, sizeof(char) * ERR_BUF_SIZE);
			snprintf(err_buf, ERR_BUF_SIZE, "stat() fails, due to: %s", strerror(errno));
			throw runtime_error(err_buf);			
		}
	}

	return true;
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

unsigned short get_linux_platform(string& linux_platform)
{
	static const char* cmd = "lsb_release -a | grep Description";
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(cmd, "r");
	char *line = NULL;
	size_t line_len = 0;
    char* token; 
    char* rest = NULL;
    char* line_tmp = NULL; 
    char* token_ptr = NULL;
    char* token_ptr_end = NULL;
    size_t linux_platform_pos = 0;
    size_t linux_platform_len = 0;
	if (getline(&line, &line_len, fp) == -1)
	{
		STATIC_WRITE_FORMAT_ERROR("popen() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT;
	}
	line_tmp = line;
	token = strtok_r(line_tmp, ":", &rest);
	token = strtok_r(NULL, ":", &rest);
	if (token == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to parse the line: %s", line);
		ret = RET_FAILURE_RUNTIME;
		goto OUT;		
	}
// Find the start index of the linux platform
	token_ptr = token;
	while (isspace(*token_ptr) && *token_ptr != '\0') token_ptr++;
	linux_platform_pos = token_ptr - token;
// Find the string length of the linux platform
	token_ptr_end = token_ptr;
	while (*token_ptr_end != '\r' && *token_ptr_end != '\n' && *token_ptr_end != '\0') token_ptr_end++;
	linux_platform_len = token_ptr_end - token_ptr;
// Get the correct string of linux platform
	linux_platform = string(token).substr(linux_platform_pos, linux_platform_len);
	// printf("get_linux_platform: %s\n", linux_platform.c_str());
OUT:
	if (line != NULL)
	{
		free(line);
		line = NULL;
	}
	pclose(fp);
	return ret;
}

unsigned short get_system_info(string& system_info)
{
	static const char* LINUX_PLATFORM = "Linux Platform";
	static const int SYSTEM_INFO_BUF_SIZE = 256;
	unsigned short ret = RET_SUCCESS;
	char system_info_buf[SYSTEM_INFO_BUF_SIZE];
// Get Linux platform
	string linux_platform;
	ret = get_linux_platform(linux_platform);
	if (CHECK_FAILURE(ret))
		return ret;
	snprintf(system_info_buf, SYSTEM_INFO_BUF_SIZE, "%s: %s\n", LINUX_PLATFORM, linux_platform.c_str());
	system_info += string(system_info_buf);
	return RET_SUCCESS;
}

bool check_string_is_number(const char* input)
{
	assert(input != NULL && "input should NOT be NULL");
    char *next;
// Get value with failure detection.
	/*long val = */strtol(input, &next, 10);
// Check for empty string and characters left after conversion.
	return ((next == input) || (*next != '\0')) ? false : true;
}

const char *get_username()
{
  	uid_t uid = geteuid();
  	struct passwd *pw = getpwuid(uid);
  	if (pw != NULL)
    	return pw->pw_name;
  	return NULL;
}

bool is_root_user()
{
	return ((strcmp(get_username(), "root") == 0) ? true : false);
}

void print_curtime(const char* title)
{
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  printf("%s: %d-%02d-%02d %02d:%02d:%02d\n", (title == NULL ? "Time" : title), tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}