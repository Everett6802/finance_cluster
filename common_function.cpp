#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pwd.h>
#include <time.h>
#include <dirent.h>
#include <stdexcept>
#include "common.h"


using namespace std;

const char *GetErrorDescription(unsigned short ret)
{
	static const char *ret_failure_description[] =
	{
		"Success",
		"Failure Unknown",
		"Failure Runtime",
		"Failure Invalid Argument",
		"Failure Invalid Pointer",
		"Failure Insufficient Memory",
		"Failure Incorrect Operation",
		"Failure Open File",
		"Failure Not Found",
		"Failure Incorrect Config",
		"Failure Incorrect Path",
		"Failure IO Operation",
		"Failure Handle Thread",
		"Failure System API",
		"Failure Internal Error",
		"Failure Incorrect Value",
		"Failure Resource Busy"
	};
	static const char *connection_ret_failure_description[] =
	{
		// "ConnectionFailure Base",
		"ConnectionFailure Error",
		"ConnectionFailure Try Timeout",
		"ConnectionFailure Try Fail",
		"ConnectionFailure Close",
		"ConnectionFailure Keepalive Timeout",
		"ConnectionFailure No Server",
		"ConnectionFailure Already in Use",
		"ConnectionFailure Message Incomplete",
		"ConnectionFailure Message Timeout"
	};
	static const char *ret_warn_description[] =
	{
		// "Warn Base",
		"Warn Interactive Command",
		"Warn Interactive Configuration Command",
		"Warn Simulator Not Installed",
		"Warn Simulator Package Not Found",
		"Warn File Transfer in Process",
		"Warn Cluster Not Single",
		"Warn Remote File Transfer Failure",
	};
	static int ret_failure_description_len = sizeof(ret_failure_description) / sizeof(ret_failure_description[0]);
	static int connection_ret_failure_description_len = sizeof(connection_ret_failure_description) / sizeof(connection_ret_failure_description[0]);
	static int ret_warn_description_len = sizeof(ret_warn_description) / sizeof(ret_warn_description[0]);

	unsigned short orig_ret = ret;
	if (ret >= RET_WARN_BASE)
	{
		ret -= RET_WARN_BASE;
		if (ret >= 0 && ret < ret_warn_description_len)
			return ret_warn_description[ret];
	}
	else if (ret >= RET_FAILURE_CONNECTION_BASE)
	{
		ret -= RET_FAILURE_CONNECTION_BASE;
		if (ret >= 0 && ret < connection_ret_failure_description_len)
			return connection_ret_failure_description[ret];
	}
	else if (ret >= RET_FAILURE_BASE)
	{
		if (ret >= 0 && ret < ret_failure_description_len)
			return ret_failure_description[ret];
	}
	else if (ret == RET_SUCCESS)
		return ret_failure_description[ret];

	char buf[STRING_SIZE + 1];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, STRING_SIZE, "Unsupported Error Description: %d", orig_ret);
	throw runtime_error(buf);
}

static char* EVENT_TYPE_DESCRIPTION[] = {
	"Operate Node",
	"Telnet Console",
	"Sync Data",
	"Remote Sync Data",
	"Update Config"
};
static int EVENT_TYPE_DESCRIPTION_SIZE = sizeof(EVENT_TYPE_DESCRIPTION) / sizeof(EVENT_TYPE_DESCRIPTION[0]);

const char* GetEventTypeDescription(EventType event_type)
{
	assert(event_type >= 0 && event_type < EVENT_TYPE_SIZE && "event type is out of range");
	assert(EVENT_TYPE_DESCRIPTION_SIZE == EVENT_TYPE_SIZE && "EVENT_TYPE_DESCRIPTION_SIZE != EVENT_TYPE_SIZE");
	return EVENT_TYPE_DESCRIPTION[event_type];
}

EventType GetEventTypeFromDescription(const char* event_type_description)
{
	assert(event_type_description != NULL && "event_type_description should NOT be NULL");
	assert(EVENT_TYPE_DESCRIPTION_SIZE == EVENT_TYPE_SIZE && "EVENT_TYPE_DESCRIPTION_SIZE != EVENT_TYPE_SIZE");
	for (int i = 0 ; i < EVENT_TYPE_SIZE ; i++)
	{
		if (strcmp(event_type_description, EVENT_TYPE_DESCRIPTION[i]) == 0)
			return (EventType)i;
	}
    static const int BUF_SIZE = 256;
    char buf[BUF_SIZE];
    snprintf(buf, BUF_SIZE, "Unknown event type description: %s", event_type_description);
    // fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
	throw invalid_argument(buf);
}

static char* EVENT_SEVERITY_DESCRIPTION[] = {
	"Critical",
	"Warning",
	"Informational"
};
static int EVENT_SEVERITY_DESCRIPTION_SIZE = sizeof(EVENT_SEVERITY_DESCRIPTION) / sizeof(EVENT_SEVERITY_DESCRIPTION[0]);

const char* GetEventSeverityDescription(EventSeverity event_severity)
{
	assert(event_severity >= 0 && event_severity < EVENT_SEVERITY_SIZE && "event severity is out of range");
	assert(EVENT_SEVERITY_DESCRIPTION_SIZE == EVENT_SEVERITY_SIZE && "EVENT_SEVERITY_DESCRIPTION_SIZE != EVENT_SEVERITY_SIZE");
	return EVENT_SEVERITY_DESCRIPTION[event_severity];
}

EventSeverity GetEventSeverityFromDescription(const char* event_severity_description)
{
	assert(event_severity_description != NULL && "event_severity_description should NOT be NULL");
	assert(EVENT_SEVERITY_DESCRIPTION_SIZE == EVENT_SEVERITY_SIZE && "EVENT_SEVERITY_DESCRIPTION_SIZE != EVENT_SEVERITY_SIZE");
	for (int i = 0 ; i < EVENT_SEVERITY_SIZE ; i++)
	{
		if (strcmp(event_severity_description, EVENT_SEVERITY_DESCRIPTION[i]) == 0)
			return (EventSeverity)i;
	}
    static const int BUF_SIZE = 256;
    char buf[BUF_SIZE];
    snprintf(buf, BUF_SIZE, "Unknown event severity description: %s", event_severity_description);
    // fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
	throw invalid_argument(buf);
}

static char* EVENT_CATEGORY_DESCRIPTION[] = {
	"Cluter",
	"Console"
};
static int event_category_description_size = sizeof(EVENT_CATEGORY_DESCRIPTION) / sizeof(EVENT_CATEGORY_DESCRIPTION[0]);

const char* GetEventCategoryDescription(EventCategory event_category)
{
	// printf("Event Category: %d\n", (int)event_category);
	assert(event_category >= 0 && event_category < EVENT_CATEGORY_SIZE && "event category is out of range");
	assert(event_category_description_size == EVENT_CATEGORY_SIZE && "event_category_description_size != EVENT_CATEGORY_SIZE");
	return EVENT_CATEGORY_DESCRIPTION[event_category];
}

EventCategory GetEventCategoryFromDescription(const char* event_category_description)
{
	// printf("Event Category: %d\n", (int)event_category);
	assert(event_category_description != NULL && "event_category_description should NOT be NULL");
	assert(event_category_description_size == EVENT_CATEGORY_SIZE && "event_category_description_size != EVENT_CATEGORY_SIZE");
	for (int i = 0 ; i < EVENT_CATEGORY_SIZE ; i++)
	{
		if (strcmp(event_category_description, EVENT_CATEGORY_DESCRIPTION[i]) == 0)
			return (EventCategory)i;
	}
    static const int BUF_SIZE = 256;
    char buf[BUF_SIZE];
    snprintf(buf, BUF_SIZE, "Unknown event category description: %s", event_category_description);
    // fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
	throw invalid_argument(buf);
}

const char* GetEventDeviceDescription(EventDevice event_device)
{
	static char* event_device_description[] = {
		"File",
		"Shared Memory",
		"Database"
	};
	static int event_device_description_size = sizeof(event_device_description) / sizeof(event_device_description[0]);
	assert(event_device >= 0 && event_device < EVENT_DEVICE_SIZE && "event device is out of range");
	assert(event_device_description_size == EVENT_DEVICE_SIZE && "event_device_description_size != EVENT_DEVICE_SIZE");
	return event_device_description[event_device];
}

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
			// fprintf(stderr, "%s IPv4 Address %s\n",  local_interface.c_str(), local_ip.c_str());
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

unsigned short read_file_lines_ex(std::list<std::string>& line_list, const char* filepath, const char* file_read_attribute/*, char data_seperate_character*/, bool ignore_comment)
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
/*
	gets 不推荐使用，gets(s) 等价于 fgets(s, INT_MAX, stdin)，因为没有对缓冲区溢出做处理，不安全；
	getline 碰到EOF返回-1，fgets返回NULL；
	传入getline的buffer指针如果为NULL，函数会分配缓冲区用于存储行字符串，并由调用者释放。如果传入buffer空间不足以存放一行，那么函数会自动扩增缓冲区空间，同时更新其指针及缓冲区大小。
	传入fgets的buffer空间如果不足以存放一行，fgets提前返回，并在末尾添加null byte（'\0'）。
*/
	while (fgets(line_buf, BUF_SIZE, fp) != NULL) 
	{
		if (line_buf[0] == '\n' || line_buf[0] == '#')
		{
			if (ignore_comment)
				continue;
		}
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

unsigned short write_file_lines_ex(const std::list<std::string>& line_list, const char* filepath, const char* file_write_attribute, const char* newline_character)
{
	FILE* fp = fopen(filepath, file_write_attribute);
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to open the file[%s], due to: %s", filepath, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	list<string>::const_iterator iter = line_list.cbegin();
	while (iter != line_list.cend())
	{
		const char* line = ((string)*iter).c_str();
		fputs(line, fp);
		if (newline_character != NULL)
			fputs(newline_character, fp);
		iter++;
	}
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return RET_SUCCESS;
}

unsigned short get_process_id_list(const char* process_name, list<int>& process_id_list)
{
	assert(process_name != NULL && "process_name should NOT be NULL");
	static const char* cmd_format = "ps aux | grep %s | grep -v grep | awk '{print $2}'";
	static const int CMD_BUFSIZE = 256;
	char cmd[CMD_BUFSIZE];
	snprintf(cmd, CMD_BUFSIZE, cmd_format, process_name);
	// fprintf(stderr, "(get_process_id_list) cmd: %s\n", cmd);
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(cmd, "r");
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("popen() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	char *line = NULL;
	size_t line_len = 0;
    char* token; 
    char* rest = NULL;
    char* line_tmp = NULL; 
    char* pid_str = NULL;
/*
	gets 不推荐使用，gets(s) 等价于 fgets(s, INT_MAX, stdin)，因为没有对缓冲区溢出做处理，不安全；
	getline 碰到EOF返回-1，fgets返回NULL；
	传入getline的buffer指针如果为NULL，函数会分配缓冲区用于存储行字符串，并由调用者释放。如果传入buffer空间不足以存放一行，那么函数会自动扩增缓冲区空间，同时更新其指针及缓冲区大小。
	传入fgets的buffer空间如果不足以存放一行，fgets提前返回，并在末尾添加null byte（'\0'）。
*/
	while (getline(&line, &line_len, fp) != -1)
	{
		// fprintf(stderr, "(get_process_id_list) line: %s\n", line);
		line_tmp = line;
		pid_str = strtok_r(line_tmp, "\r\n", &rest);
		int pid = atoi(pid_str);
		// fprintf(stderr, "(get_process_id_list) pid: %d\n", pid);
		process_id_list.push_back(pid);
		if (line != NULL)
		{
			free(line);
			line = NULL;
		}
	}
	pclose(fp);
	return ret;
}

unsigned short get_process_count(const char* process_name, int& process_count)
{
	assert(process_name != NULL && "process_name should NOT be NULL");
	static const char* cmd_format = "ps aux | grep %s | grep -v grep | wc -l";
	static const int CMD_BUFSIZE = 256;
	char cmd[CMD_BUFSIZE];
	snprintf(cmd, CMD_BUFSIZE, cmd_format, process_name);
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(cmd, "r");
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("popen() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	char *line = NULL;
	size_t line_len = 0;
    char* token; 
    char* rest = NULL;
    char* line_tmp = NULL; 
    char* count_str = NULL;
	if (getline(&line, &line_len, fp) == -1)
	{
		STATIC_WRITE_FORMAT_ERROR("getline() fails, due to: %s", strerror(errno));
		ret = RET_FAILURE_SYSTEM_API;
		goto OUT;
	}
	line_tmp = line;
	count_str = strtok_r(line_tmp, "\r\n", &rest);
	if (count_str == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to parse the line: %s", line);
		ret = RET_FAILURE_RUNTIME;
		goto OUT;		
	}
// Find the start index of the linux platform
	process_count = atoi(count_str);
OUT:
	if (line != NULL)
	{
		free(line);
		line = NULL;
	}
	pclose(fp);
	return ret;
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

void get_curtime_str(string& curtime)
{
  	time_t t = time(NULL);
  	struct tm tm = *localtime(&t);
  	char curtime_str[DEF_SHORT_STRING_SIZE];
  	snprintf(curtime_str, DEF_SHORT_STRING_SIZE, "%d/%02d/%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  	curtime = curtime_str;
}

// void print_curtime(const char* title)
// {
//   	time_t t = time(NULL);
//   	struct tm tm = *localtime(&t);
//   	printf("%s: %d/%02d/%02d %02d:%02d:%02d\n", (title == NULL ? "Time" : title), tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
// }

const char* pthread_cond_timedwait_err(int ret)
{
    // fprintf(stderr, "Conditional timed wait, failed.\n");
    switch (ret)
    {
        case ETIMEDOUT:
            return "wait timeout";
        case EINVAL:
            return "cond or mutex is invalid";
        case EPERM:
            return "mutex was not owned by the current thread at the time of the call";
        default:
            break;
    }
    return NULL;
}

unsigned short create_folder_recursive(const char* full_folderpath)
{
	assert(full_folderpath != NULL && "input should NOT be NULL");
	char* full_folderpath_tmp = strdup(full_folderpath);
	char* full_folderpath_tmp_ptr = full_folderpath_tmp;
	char* rest_full_folderpath_tmp_ptr = NULL;
	char* foldername;
	string upper_folderpath;
	unsigned short ret = RET_SUCCESS;
	while ((foldername = strtok_r(full_folderpath_tmp_ptr, "/", &rest_full_folderpath_tmp_ptr)) != NULL)
	{
		upper_folderpath += (string("/") + string(foldername));
		// printf("Folderpath: %s\n", upper_folderpath.c_str());
		if (access(upper_folderpath.c_str(), F_OK) != 0)
		{
			// printf("Create the folder: %s\n", upper_folderpath.c_str());
			// // STATIC_WRITE_FORMAT_DEBUG("Create the folder: %s", upper_folderpath.c_str());
			if(mkdir(upper_folderpath.c_str(), S_IRWXU) != 0)
			{
				STATIC_WRITE_FORMAT_ERROR("mkdir() fails, due to: %s", strerror(errno));
				ret = RET_FAILURE_SYSTEM_API;
				goto OUT;
			}
		}
		if (full_folderpath_tmp_ptr != NULL)
			full_folderpath_tmp_ptr = NULL;
	}
OUT:
	if (full_folderpath_tmp != NULL)
	{
		free(full_folderpath_tmp);
		full_folderpath_tmp = NULL;
	}
	return ret;
}

unsigned short get_filepath_in_folder_recursive(std::list<std::string>& full_filepath_in_folder_list, const std::string& parent_full_folderpath)
{
    DIR *dp = opendir(parent_full_folderpath.c_str());
    if (dp == nullptr)
    {
		if (errno == ENOENT) 
		{
			STATIC_WRITE_FORMAT_ERROR("The folder[%s] being synchronized does NOT exist", parent_full_folderpath.c_str());
			return RET_FAILURE_NOT_FOUND;
		} 
		else  /* opendir() failed for some other reason. */
		{
			STATIC_WRITE_FORMAT_ERROR("opendir() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
    } 

    unsigned short ret = RET_SUCCESS;
    struct dirent *entry = nullptr;
    struct stat states;
    while ((entry = readdir(dp)))
    {
// You can't (usefully) compare strings using != or ==, you need to use strcmp
// The reason for this is because != and == will only compare the base addresses of those strings. 
// Not the contents of the strings themselves.
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        	continue;
        // printf("%s/%s\n", parent_full_folderpath.c_str(), entry->d_name);
		string child_full_path = parent_full_folderpath + string("/") + string(entry->d_name);
       	stat(child_full_path.c_str(), &states);
        if(S_ISDIR(states.st_mode))
        {
        	// printf("* Folder: %s\n", child_full_path.c_str());
			ret = get_filepath_in_folder_recursive(full_filepath_in_folder_list, child_full_path);
			if (CHECK_FAILURE(ret))
				break;
        }
        else
        {
        	// printf("  => File: %s\n", child_full_path.c_str());
        	full_filepath_in_folder_list.push_back(child_full_path);
        }
    }
    closedir(dp);
    return ret;
}

string join(const string string_list[], int string_list_len, const string& delimiter)
{
	string new_string = string_list[0];
	for (int i = 1 ; i < string_list_len ; i++)
		new_string += (delimiter + string_list[i]);
	return new_string;
}

string join(const char *string_list[], int string_list_len, const char* delimiter)
{
	string new_string_list[string_list_len];
	for (int i = 0 ; i < string_list_len ; i++)
		new_string_list[i] = string(string_list[i]);
	string new_delimiter = string(delimiter);
	return join(new_string_list, string_list_len, new_delimiter);
}