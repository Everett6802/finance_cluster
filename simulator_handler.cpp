#include <assert.h>
#include <stdexcept>
#include <dirent.h>
#include "simulator_handler.h"


using namespace std;

const char* SimulatorHandler::SIMULATOR_PACKAGE_FOLDER_PATH = "/dev/shm/simulator";
const char* SimulatorHandler::SIMULATOR_ROOT_FOLDER_PATH = "/simulator/BUILD";
const char* SimulatorHandler::SIMULATOR_SCRIPTS_FOLDER_NAME = "scripts";
const char* SimulatorHandler::SIMULATOR_CONF_FOLDER_NAME = "conf";
const char* SimulatorHandler::SIMULATOR_VERSION_FILENAME = "VERSION";
const char* SimulatorHandler::SIMULATOR_BUILD_FILENAME = "BUILD";
const char* SimulatorHandler::SIMULATOR_UTIL_FILENAME = "simulator_util";
const char* SimulatorHandler::SIMULATOR_FAKE_ACSPT_SIM_CFG_FILENAME = "fake_acspt_sim.cfg";
const char* SimulatorHandler::SIMULATOR_FAKE_USREPT_CFG_FILENAME = "fake_usrept.conf";
const char* SimulatorHandler::SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG = "START_PKT_PROFILES";
const char* SimulatorHandler::SIMULATOR_INSTALL_SCRIPT_NAME = "simulator_install.sh";
const char* SimulatorHandler::FAKE_ACSPT_CONTROL_SCRIPT_NAME = "fake_acspt_control.sh";
const char* SimulatorHandler::FAKE_USREPT_CONTROL_SCRIPT_NAME = "fake_usrept_control.sh";
const char* SimulatorHandler::SCRIPT_FILENAME_ARRAY[] = {SIMULATOR_INSTALL_SCRIPT_NAME, FAKE_ACSPT_CONTROL_SCRIPT_NAME, FAKE_USREPT_CONTROL_SCRIPT_NAME};


SimulatorHandler::SimulatorHandler(PINOTIFY notify) : 
	// fake_acspt_control_script_filepath(NULL),
	// fake_usrept_control_script_filepath(NULL),
	script_filepath_array(NULL),
	observer(notify)
{
	IMPLEMENT_MSG_DUMPER()
	script_filepath_array = new char*[SCRIPT_FILE_TYPE_SIZE];
	if (script_filepath_array == NULL)
		throw bad_alloc();
	for (int i = 0 ; i < SCRIPT_FILE_TYPE_SIZE ; i++)
		script_filepath_array[i] = NULL;
}

SimulatorHandler::~SimulatorHandler()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in SimulatorHandler::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (script_filepath_array != NULL)
	{
		for (int i = 0 ; i < SCRIPT_FILE_TYPE_SIZE ; i++)
		{
			if (script_filepath_array[i] != NULL)
			{
				delete[] script_filepath_array[i];
				script_filepath_array[i] = NULL;
			}
		}
		delete[] script_filepath_array;
		script_filepath_array = NULL;
	}
	// if (fake_acspt_control_script_filepath != NULL)
	// {
	// 	delete[] fake_acspt_control_script_filepath;
	// 	fake_acspt_control_script_filepath = NULL;
	// }
	// if (fake_usrept_control_script_filepath != NULL)
	// {
	// 	delete[] fake_usrept_control_script_filepath;
	// 	fake_usrept_control_script_filepath = NULL;
	// }
	RELEASE_MSG_DUMPER()
}

bool SimulatorHandler::check_simulator_installed()
{
	// bool file_exist = check_file_exist(SIMULATOR_PACKAGE_FOLDER_PATH);
	// printf("Check folder[%s] exist: %s\n", SIMULATOR_PACKAGE_FOLDER_PATH, (file_exist ? "True" : "False"));
	return check_file_exist(SIMULATOR_PACKAGE_FOLDER_PATH);
}

void SimulatorHandler::assemble_script_filepath(char** filepath, const char* filename)
{
	assert(filepath != NULL && "filepath should NOT be NULL");
	assert(filename != NULL && "filename should NOT be NULL");
	static const int BUF_SIZE = 256;
	char cwd[BUF_SIZE];
	memset(cwd, 0x0, sizeof(cwd) / sizeof(cwd[0]));
	getcwd(cwd, BUF_SIZE - 1);
	char* filepath_tmp = new char[BUF_SIZE];
	if (filepath_tmp == NULL)
		throw runtime_error("fails to allocate memory: filepath_tmp");
	memset(filepath_tmp, 0x0, sizeof(char) * BUF_SIZE);
	snprintf(filepath_tmp, BUF_SIZE, "%s/%s", cwd, filename);
	// printf("cwd: %s, filepath: %s\n", cwd, filepath);
	*filepath = filepath_tmp;
}

void SimulatorHandler::assemble_simulator_sub_folder_path(char** sub_folder_path, const char* sub_folder_name)
{
	assert(sub_folder_path != NULL && "sub_folder_path should NOT be NULL");
	assert(sub_folder_name != NULL && "sub_folder_name should NOT be NULL");	
	static const int BUF_SIZE = 256;
	char* sub_folder_path_tmp = new char[BUF_SIZE];
	if (sub_folder_path_tmp == NULL)
		throw runtime_error("fails to allocate memory: filepath_tmp");
	memset(sub_folder_path_tmp, 0x0, sizeof(char) * BUF_SIZE);
	snprintf(sub_folder_path_tmp, BUF_SIZE, "%s/%s", SIMULATOR_ROOT_FOLDER_PATH, sub_folder_name);
	// printf("cwd: %s, filepath: %s\n", cwd, filepath);
	*sub_folder_path = sub_folder_path_tmp;
}

const char* SimulatorHandler::get_script_filepath(SCRIPT_FILE_TYPE script_file_type)
{
	assert(script_filepath_array != NULL && "script_filepath_array should NOT be NULL");
	if (script_filepath_array[script_file_type] == NULL)
		assemble_script_filepath(&script_filepath_array[script_file_type], SCRIPT_FILENAME_ARRAY[script_file_type]);
	return script_filepath_array[script_file_type];
}

unsigned short SimulatorHandler::run_script(SCRIPT_FILE_TYPE script_file_type, const char* param_string)
{
	static const int BUF_SIZE = 256;
	char cmd[BUF_SIZE + 1];
	memset(cmd, 0x0, sizeof(cmd)/sizeof(cmd[0]));

	// system("fake_acspt.sh clean");
	if (param_string == NULL)
		snprintf(cmd, BUF_SIZE, "%s", get_script_filepath(script_file_type));
	else
		snprintf(cmd, BUF_SIZE, "%s %s", get_script_filepath(script_file_type), param_string);
	system(cmd);
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::initialize()
{
	// if (!check_simulator_installed())
	// 	return RET_FAILURE_INCORRECT_OPERATION;
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::deinitialize()
{
	return  RET_SUCCESS;
}

unsigned short SimulatorHandler::install_simulator(const char* simulator_filepath)
{
	run_script(SIMULATOR_INSTALL, simulator_filepath);
	return RET_SUCCESS;
}

bool SimulatorHandler::is_simulator_installed()const
{
	return check_simulator_installed();	
}

unsigned short SimulatorHandler::get_simulator_version(char* simulator_version, int simulator_version_size)const
{
	assert(simulator_version != NULL && "simulator_version should NOT be NULL");
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
	static const int FILEPATH_SIZE = 256;
	char filepath[FILEPATH_SIZE + 1];
	unsigned short ret = RET_SUCCESS;
	// chdir(SIMULATOR_ROOT_FOLDER_PATH);
// Get Version
	memset(filepath, 0x0, sizeof(filepath) / sizeof(filepath[0]));
	snprintf(filepath, FILEPATH_SIZE, "%s/%s", SIMULATOR_ROOT_FOLDER_PATH, SIMULATOR_VERSION_FILENAME);
	list<string> line_list1;
	ret = read_file_lines_ex(line_list1, filepath);
	if (CHECK_FAILURE(ret))
		return ret;
	if (line_list1.size() != 1)
		return RET_FAILURE_INCORRECT_CONFIG;
	list<string>::iterator iter1 = line_list1.begin();
	string version_string = (string)*iter1;
// Get Build
	memset(filepath, 0x0, sizeof(filepath) / sizeof(filepath[0]));
	snprintf(filepath, FILEPATH_SIZE, "%s/%s", SIMULATOR_ROOT_FOLDER_PATH, SIMULATOR_BUILD_FILENAME);
	list<string> line_list2;
	ret = read_file_lines_ex(line_list2, filepath);
	if (CHECK_FAILURE(ret))
		return ret;
	if (line_list2.size() != 1)
		return RET_FAILURE_INCORRECT_CONFIG;
	list<string>::iterator iter2 = line_list2.begin();
	string build_string = (string)*iter2;
// Assemble the simulator version
	snprintf(simulator_version, simulator_version_size, "%s.%s", version_string.c_str(), build_string.c_str());
	return ret;
}

unsigned short SimulatorHandler::start_fake_acspt(bool need_reset)
{
	if (need_reset)
		run_script(FAKE_ACSPT_CONTROL, "stop");
	run_script(FAKE_ACSPT_CONTROL, "start");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::stop_fake_acspt()
{
	run_script(FAKE_ACSPT_CONTROL, "stop");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::start_fake_usrept(bool need_reset)
{
	if (need_reset)
		run_script(FAKE_USREPT_CONTROL, "stop");
	run_script(FAKE_USREPT_CONTROL, "start");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::stop_fake_usrept()
{
	run_script(FAKE_USREPT_CONTROL, "stop");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::get_fake_acspt_state(char* fake_acspt_state, int fake_acspt_state_size)const
{
	assert(fake_acspt_state != NULL && "fake_acspt_state should NOT be NULL");
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
	static const int CMD_SIZE = 256;
	char cmd[CMD_SIZE + 1];
	// unsigned short ret = RET_SUCCESS;
	// chdir(SIMULATOR_ROOT_FOLDER_PATH);
// Get file path of the simulator_util executable
	char *simulator_scripts_folder_path = NULL;
	assemble_simulator_sub_folder_path(&simulator_scripts_folder_path, SIMULATOR_SCRIPTS_FOLDER_NAME);
	memset(cmd, 0x0, sizeof(cmd) / sizeof(cmd[0]));
	snprintf(cmd, CMD_SIZE, "%s/%s -v", simulator_scripts_folder_path, SIMULATOR_UTIL_FILENAME);
	if (simulator_scripts_folder_path != NULL)
	{
		delete[] simulator_scripts_folder_path;
		simulator_scripts_folder_path = NULL;
	}
	// printf("cmd: %s\n", cmd);
// Parse the data from the executable
	unsigned short ret = RET_SUCCESS;
	FILE *fp = popen(cmd, "r");
	static const char* SUMMARY_STR = "SUMMARY";
	char *line = NULL;
	size_t line_len = 0;
    char* token; 
    char* rest = NULL;
    char* line_tmp = NULL; 
    bool can_parse = false;
    char* line_seg_array[16];
    int line_seg_count = 0;
    while (getline(&line, &line_len, fp) != -1)
    {
    	if (can_parse)
    	{
    		line_tmp = line;
// strip the newline character
    		char* line_tmp_new = strtok_r(line_tmp, "\n", &rest);
    		token = strtok_r(line_tmp_new, " ", &rest);
    		while (token != NULL)
    		{
    			token = strtok_r(NULL, " ", &rest);
    			// printf("%d ==> token: %s, rest: %s\n", line_seg_count, token, rest);
    			line_seg_array[line_seg_count++] = token;
    		}
    		break;
    	}
    	else
    	{
    		if(strstr(line, SUMMARY_STR) != NULL) 
    			can_parse = true;
    	}
    	// printf("%d: %s\n", line_cnt++, line);
    }
    line_seg_count--;
    string fake_acspt_state_str = string("");
    for (int i = 0; i < line_seg_count ; i++)
    {
    	fake_acspt_state_str += string(line_seg_array[i]);
    	if (i != line_seg_count - 1)
    		fake_acspt_state_str += string("  ");
    	// printf("%d %s\n", i, line_seg_array[i]);
    }
    strncpy(fake_acspt_state, fake_acspt_state_str.c_str(), fake_acspt_state_size - 1);
	pclose(fp);
	return ret;
}

unsigned short SimulatorHandler::get_fake_acspt_detail(std::string& fake_acspt_detail)const
{
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;

// wsgclient_param
    static const char *WSGCLIENT_FOLDER = "wsgclientsim";
    static const char *WSGCLIENT_PARAM[] = {"ssn", "dev-ip", "dev-mac", "model", "fw-ver"};
    static const int WSGCLIENT_PARAM_LEN = sizeof(WSGCLIENT_PARAM) / sizeof(WSGCLIENT_PARAM[0]);
    dp = opendir(SHM_FOLDERPATH);
    if (dp == nullptr) 
    {
		WRITE_FORMAT_ERROR("opendir() fails(%s), due to: %s", SHM_FOLDERPATH, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
    }

    fake_acspt_detail = string("");
    while ((entry = readdir(dp)))
    {
// You can't (usefully) compare strings using != or ==, you need to use strcmp
// The reason for this is because != and == will only compare the base addresses of those strings. 
// Not the contents of the strings themselves.
        if (strcmp(entry->d_name, "apgroup") == 0 || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        	continue;
        // printf ("%s\n", entry->d_name);
// /dev/shm/sim/00:01:88:01:35:64/rpm/wsgclientsim
        char rpm_data_filepath[DEF_LONG_STRING_SIZE];
        for (int i = 0 ; i < WSGCLIENT_PARAM_LEN ; i++)
        {
        	snprintf(rpm_data_filepath, DEF_LONG_STRING_SIZE, RPM_DATA_FILEPATH_FORMAT, entry->d_name, WSGCLIENT_FOLDER, WSGCLIENT_PARAM[i]);
		 	FILE* fp = fopen(rpm_data_filepath, "r");
			if (fp == NULL)
			{
				fprintf(stderr, "fopen() fails: %s, due to: %s\n", rpm_data_filepath, strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
			static const int BUF_SIZE = 512;
			static char line_buf[BUF_SIZE];
			int last_character_in_string_index = 0;
			static char fake_acspt_detail_line[BUF_SIZE];
			while (fgets(line_buf, BUF_SIZE, fp) != NULL) 
			{
				last_character_in_string_index = strlen(line_buf) - 1;
				if (line_buf[last_character_in_string_index] == '\n')
					line_buf[last_character_in_string_index] = '\0';
				snprintf(fake_acspt_detail_line, BUF_SIZE, "%s   ", line_buf);
				fake_acspt_detail += fake_acspt_detail_line;
				// printf("line: %s\n", line_buf);
			}
	// OUT:
			if (fp != NULL)
			{
				fclose(fp);
				fp = NULL;
			}
        }
		fake_acspt_detail += string("\n");        
    }
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::apply_new_fake_acspt_config(const list<string>& new_config_line_list)
{
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
	static const int BUF_SIZE = 256;
	unsigned short ret = RET_SUCCESS;
	char fake_acspt_cfg_filepath[BUF_SIZE + 1];
	char *simulator_scripts_folder_path = NULL;
	assemble_simulator_sub_folder_path(&simulator_scripts_folder_path, SIMULATOR_SCRIPTS_FOLDER_NAME);
	memset(fake_acspt_cfg_filepath, 0x0, sizeof(fake_acspt_cfg_filepath) / sizeof(fake_acspt_cfg_filepath[0]));
	snprintf(fake_acspt_cfg_filepath, BUF_SIZE, "%s/%s", simulator_scripts_folder_path, SIMULATOR_FAKE_ACSPT_SIM_CFG_FILENAME);
	if (simulator_scripts_folder_path != NULL)
	{
		delete[] simulator_scripts_folder_path;
		simulator_scripts_folder_path = NULL;
	}
// Read the config in simulator
	list<string> simulator_config_line_list;
	ret = read_file_lines_ex(simulator_config_line_list, fake_acspt_cfg_filepath, "r", ',', false);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the simulator config file[%s], due to: %s", fake_acspt_cfg_filepath, GetErrorDescription(ret));
		return ret;
	}
// // Read the new config
// 	list<string> new_config_line_list;
// 	ret = read_file_lines_ex(new_config_line_list, new_fake_acspt_config_filepath);
// 	if (CHECK_FAILURE(ret))
// 	{
// 		WRITE_FORMAT_ERROR("Fail to read the new config file[%s], due to: %s", new_fake_acspt_config_filepath, GetErrorDescription(ret));
// 		return ret;
// 	}
// Update the config in simulator
	list<string>::const_iterator iter_new = new_config_line_list.begin();
	while (iter_new != new_config_line_list.end())
	{
		std::size_t found;
		string line_new = (string)*iter_new;
		found = line_new.find('=');
		if (found == std::string::npos)
		{
			WRITE_FORMAT_ERROR("Incorrect new configuration format in line: %s", line_new.c_str());
			ret = RET_FAILURE_INCORRECT_CONFIG;
			break;
		}
		list<string>::iterator iter_simulator = simulator_config_line_list.begin();
		bool update = false;
		while (iter_simulator != simulator_config_line_list.end())
		{
			string line_simulator = (string)*iter_simulator;
			if (line_simulator.compare(0, found, line_new.substr(0, found)) == 0)
			{
				// str.replace(str.find(str2), str2.length(),"preposition");
				simulator_config_line_list.insert(iter_simulator, line_new);
				simulator_config_line_list.erase(iter_simulator);
				update = true;
				break;
			}
			iter_simulator++;
		}
		if (!update)
		{
			WRITE_FORMAT_ERROR("Undefined config in line: %s", line_new.c_str());
			ret = RET_FAILURE_INCORRECT_CONFIG;
			break;
		}
		iter_new++;
	}
	FILE* fp = fopen(fake_acspt_cfg_filepath, "w");
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to open the file[%s], due to: %s", fake_acspt_cfg_filepath, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	// int line_cnt = 0;
	list<string>::iterator iter_simulator_tmp = simulator_config_line_list.begin();
	while (iter_simulator_tmp != simulator_config_line_list.end())
	{
		// printf("%d, %s\n", ++line_cnt, ((string)*iter_simulator_tmp).c_str());
		fputs(((string)*iter_simulator_tmp).c_str(), fp);
		fputs("\n", fp);
		iter_simulator_tmp++;
	}
	// printf("fake_acspt_cfg_filepath: %s\n", fake_acspt_cfg_filepath);
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

unsigned short SimulatorHandler::get_fake_acspt_config_value(const std::list<std::string>& config_list, std::list<std::string>& config_line_list)const
{
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
	static const int BUF_SIZE = 256;
	unsigned short ret = RET_SUCCESS;
	char fake_acspt_cfg_filepath[BUF_SIZE + 1];
	char *simulator_scripts_folder_path = NULL;
	assemble_simulator_sub_folder_path(&simulator_scripts_folder_path, SIMULATOR_SCRIPTS_FOLDER_NAME);
	memset(fake_acspt_cfg_filepath, 0x0, sizeof(fake_acspt_cfg_filepath) / sizeof(fake_acspt_cfg_filepath[0]));
	snprintf(fake_acspt_cfg_filepath, BUF_SIZE, "%s/%s", simulator_scripts_folder_path, SIMULATOR_FAKE_ACSPT_SIM_CFG_FILENAME);
	if (simulator_scripts_folder_path != NULL)
	{
		delete[] simulator_scripts_folder_path;
		simulator_scripts_folder_path = NULL;
	}
// Read the config in simulator
	list<string> simulator_config_line_list;
	ret = read_file_lines_ex(simulator_config_line_list, fake_acspt_cfg_filepath, "r", ',', false);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the simulator config file[%s], due to: %s", fake_acspt_cfg_filepath, GetErrorDescription(ret));
		return ret;
	}
// Update the config in simulator
	list<string>::const_iterator iter_config= config_list.begin();
	while (iter_config != config_list.end())
	{
		string line_config = (string)*iter_config;
		std::size_t line_config_size = line_config.size();
		list<string>::iterator iter_simulator = simulator_config_line_list.begin();
		bool update = false;
		while (iter_simulator != simulator_config_line_list.end())
		{
			string line_simulator = (string)*iter_simulator;
			if (line_simulator.compare(0, line_config_size, line_config.substr(0, line_config_size)) == 0)
			{
				config_line_list.push_back(line_simulator);
				update = true;
				break;
			}
			iter_simulator++;
		}
		if (!update)
		{
			WRITE_FORMAT_ERROR("Undefined config in line: %s", line_config.c_str());
			ret = RET_FAILURE_INCORRECT_CONFIG;
			break;
		}
		iter_config++;
	}
	return ret;
}

unsigned short SimulatorHandler::apply_new_fake_usrept_config(const list<string>& new_config_line_list, const list<string>& new_pkt_profile_config_line_list, const list<string>& new_wlan_profile_config_line_list)
{
	if (!is_simulator_installed())
		return RET_FAILURE_INCORRECT_OPERATION;
	static const int BUF_SIZE = 256;
	unsigned short ret = RET_SUCCESS;
	char fake_usrept_cfg_filepath[BUF_SIZE + 1];
	char fake_usrept_cfg_bak_filepath[BUF_SIZE + 1];
	char *simulator_conf_folder_path = NULL;
	assemble_simulator_sub_folder_path(&simulator_conf_folder_path, SIMULATOR_CONF_FOLDER_NAME);
	memset(fake_usrept_cfg_filepath, 0x0, sizeof(fake_usrept_cfg_filepath) / sizeof(fake_usrept_cfg_filepath[0]));
	snprintf(fake_usrept_cfg_filepath, BUF_SIZE, "%s/%s", simulator_conf_folder_path, SIMULATOR_FAKE_USREPT_CFG_FILENAME);
// Need to manually backup the fake_usrept.conf.bak file in the source codes of the simulaltor
	snprintf(fake_usrept_cfg_bak_filepath, BUF_SIZE, "%s.bak", fake_usrept_cfg_filepath);
	if (simulator_conf_folder_path != NULL)
	{
		delete[] simulator_conf_folder_path;
		simulator_conf_folder_path = NULL;
	}
// Read the config in simulator
	list<string> simulator_config_line_list;
	ret = read_file_lines_ex(simulator_config_line_list, fake_usrept_cfg_bak_filepath, "r", ',', false);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the simulator config file[%s], due to: %s", fake_usrept_cfg_filepath, GetErrorDescription(ret));
		return ret;
	}
// Filter the config lines which are related to UE traffic features and WLAN PROFILES
	static size_t SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG_LEN = strlen(SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG);
	list<string>::iterator iter = simulator_config_line_list.begin();
	bool found = false;
	list<string> simulator_config_line_sublist;
	while(iter != simulator_config_line_list.end())
	{
		string simulator_config_line = (string)*iter;
		if (simulator_config_line.compare(0, SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG_LEN, SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG) == 0)
		{
			simulator_config_line_sublist.assign(simulator_config_line_list.begin(), iter);
			found = true;
			break;
		}
		iter++;
	}
	if (!found)
	{
		WRITE_FORMAT_ERROR("The tag[%s] is NOT found in the config file: %s", SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG, SIMULATOR_FAKE_USREPT_CFG_FILENAME);
		ret = RET_FAILURE_INCORRECT_CONFIG;
	}
// Update the config in simulator
	list<string>::const_iterator iter_new = new_config_line_list.begin();
	while (iter_new != new_config_line_list.end())
	{
		std::size_t found;
		string line_new = (string)*iter_new;
		found = line_new.find('=');
		if (found == std::string::npos)
		{
			WRITE_FORMAT_ERROR("Incorrect new configuration format in line: %s", line_new.c_str());
			ret = RET_FAILURE_INCORRECT_CONFIG;
			break;
		}
		list<string>::iterator iter_simulator = simulator_config_line_sublist.begin();
		bool update = false;
		while (iter_simulator != simulator_config_line_sublist.end())
		{
			string line_simulator = (string)*iter_simulator;
			if (line_simulator.compare(0, found, line_new.substr(0, found)) == 0)
			{
				// str.replace(str.find(str2), str2.length(),"preposition");
				simulator_config_line_sublist.insert(iter_simulator, line_new);
				simulator_config_line_sublist.erase(iter_simulator);
				update = true;
				break;
			}
			iter_simulator++;
		}
		if (!update)
		{
			WRITE_FORMAT_ERROR("Undefined config in line: %s", line_new.c_str());
			ret = RET_FAILURE_INCORRECT_CONFIG;
			break;
		}
		iter_new++;
	}
/*
r 只读方式打开文件，该文件必须存在。
r+ 以可读写方式打开文件，该文件必须存在。
rb+ 读写打开一个二进制文件，只允许读写数据。
w 打开只写文件，若文件存在则文件长度清为0，即该文件内容会消失。若文件不存在则建立该文件。
w+ 打开可读写文件，若文件存在则文件长度清为零，即该文件内容会消失。若文件不存在则建立该文件。
a 以附加的方式打开只写文件。若文件不存在，则会建立该文件，如果文件存在，写入的数据会被加到文件尾，即文件原先的内容会被保留。（EOF符保留）
a+ 以附加方式打开可读写的文件。若文件不存在，则会建立该文件，如果文件存在，写入的数据会被加到文件尾后，即文件原先的内容会被保留。 （原来的EOF符不保留） 
*/

	FILE* fp = fopen(fake_usrept_cfg_filepath, "w");
	if (fp == NULL)
	{
		STATIC_WRITE_FORMAT_ERROR("Fail to open the file[%s], due to: %s", fake_usrept_cfg_filepath, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	// int line_cnt = 0;
	list<string>::iterator iter_simulator_tmp = simulator_config_line_sublist.begin();
	while (iter_simulator_tmp != simulator_config_line_sublist.end())
	{
		// printf("%d, %s\n", ++line_cnt, ((string)*iter_simulator_tmp).c_str());
		fputs(((string)*iter_simulator_tmp).c_str(), fp);
		fputs("\n", fp);
		iter_simulator_tmp++;
	}
	list<string>::const_iterator iter_new_pkt_profile_tmp = new_pkt_profile_config_line_list.begin();
	while (iter_new_pkt_profile_tmp != new_pkt_profile_config_line_list.end())
	{
		// printf("%d, %s\n", ++line_cnt, ((string)*iter_new_pkt_profile_tmp).c_str());
		fputs(((string)*iter_new_pkt_profile_tmp).c_str(), fp);
		fputs("\n", fp);
		iter_new_pkt_profile_tmp++;
	}
	list<string>::const_iterator iter_new_wlan_profile_tmp = new_wlan_profile_config_line_list.begin();
	while (iter_new_wlan_profile_tmp != new_wlan_profile_config_line_list.end())
	{
		// printf("%d, %s\n", ++line_cnt, ((string)*iter_new_wlan_profile_tmp).c_str());
		fputs(((string)*iter_new_wlan_profile_tmp).c_str(), fp);
		fputs("\n", fp);
		iter_new_wlan_profile_tmp++;
	}

	// printf("fake_usrept_cfg_filepath: %s\n", fake_usrept_cfg_filepath);
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}

// // Write the config in simulator
// 	ret = write_file_lines_ex(simulator_config_line_sublist, fake_usrept_cfg_filepath);
// 	if (CHECK_FAILURE(ret))
// 	{
// 		WRITE_FORMAT_ERROR("Fail to write the simulator config file[%s], due to: %s", fake_usrept_cfg_filepath, GetErrorDescription(ret));
// 		return ret;
// 	}
// // Write the pkt profile config in simulator
// 	ret = write_file_lines_ex(new_pkt_profile_config_line_list, fake_usrept_cfg_filepath, "a");
// 	if (CHECK_FAILURE(ret))
// 	{
// 		WRITE_FORMAT_ERROR("Fail to write the simulator PKT profile config file[%s], due to: %s", fake_usrept_cfg_filepath, GetErrorDescription(ret));
// 		return ret;
// 	}
// // Write the wlan profile config in simulator
// 	ret = write_file_lines_ex(new_wlan_profile_config_line_list, fake_usrept_cfg_filepath, "a");
// 	if (CHECK_FAILURE(ret))
// 	{
// 		WRITE_FORMAT_ERROR("Fail to write the simulator WLAN profile config file[%s], due to: %s", fake_usrept_cfg_filepath, GetErrorDescription(ret));
// 		return ret;
// 	}
	return ret;
}

unsigned short SimulatorHandler::notify(NotifyType notify_type, void* notify_param)
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
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short SimulatorHandler::async_handle(NotifyCfg* notify_cfg)
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
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}
