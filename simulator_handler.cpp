#include <assert.h>
#include <stdexcept>
#include "simulator_handler.h"


using namespace std;

const char* SimulatorHandler::SIMULATOR_ROOT_FOLDER_PATH = "/simulator/BUILD";
const char* SimulatorHandler::SIMULATOR_PACKAGE_FOLDER_PATH = "/dev/shm/simulator";
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
		throw runtime_error(string(errmsg));
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

// const char* SimulatorHandler::get_fake_acspt_control_script_filepath()
// {
// 	if (fake_acspt_control_script_filepath == NULL)
// 		assemble_script_filepath(&fake_acspt_control_script_filepath, FAKE_ACSPT_CONTROL_SCRIPT_NAME);
// 	return fake_acspt_control_script_filepath;
// }

// const char* SimulatorHandler::get_fake_usrept_control_script_filepath()
// {
// 	if (fake_usrept_control_script_filepath == NULL)
// 		assemble_script_filepath(&fake_usrept_control_script_filepath, FAKE_USREPT_CONTROL_SCRIPT_NAME);
// 	return fake_usrept_control_script_filepath;
// }

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

unsigned short SimulatorHandler::start_fake_acspt(bool need_reset)
{
	// static const int BUF_SIZE = 256;
	// char cmd[BUF_SIZE + 1];
	// memset(cmd, 0x0, sizeof(cmd)/sizeof(cmd[0]));

	// // system("fake_acspt.sh clean");
	// if (need_reset)
	// {
	// 	snprintf(cmd, BUF_SIZE, "%s stop", get_script_filepath(FAKE_ACSPT_CONTROL));
	// 	system(cmd);
	// 	sleep(3);	
	// }

	// // system("fake_acspt.sh up");
	// snprintf(cmd, BUF_SIZE, "%s start", get_script_filepath(FAKE_ACSPT_CONTROL));
	// system(cmd);
	if (need_reset)
		run_script(FAKE_ACSPT_CONTROL, "stop");
	run_script(FAKE_ACSPT_CONTROL, "start");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::stop_fake_acspt()
{
	// static const int BUF_SIZE = 256;
	// char cmd[BUF_SIZE + 1];
	// memset(cmd, 0x0, sizeof(cmd)/sizeof(cmd[0]));

	// // system("fake_acspt.sh clean");
	// snprintf(cmd, BUF_SIZE, "%s stop", get_script_filepath(FAKE_ACSPT_CONTROL));
	// system(cmd);
	run_script(FAKE_ACSPT_CONTROL, "stop");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::start_fake_usrept(bool need_reset)
{
	// static const int BUF_SIZE = 256;
	// char cmd[BUF_SIZE + 1];
	// memset(cmd, 0x0, sizeof(cmd)/sizeof(cmd[0]));

	// // system("fake_acspt.sh clean");
	// if (need_reset)
	// {
	// 	snprintf(cmd, BUF_SIZE, "%s stop", get_script_filepath(FAKE_USREPT_CONTROL));
	// 	printf("cmd: %s\n", cmd);
	// 	system(cmd);
	// 	sleep(3);	
	// }

	// snprintf(cmd, BUF_SIZE, "%s start", get_script_filepath(FAKE_USREPT_CONTROL));
	// printf("cmd: %s\n", cmd);
	// system(cmd);
	if (need_reset)
		run_script(FAKE_USREPT_CONTROL, "stop");
	run_script(FAKE_USREPT_CONTROL, "start");
	return RET_SUCCESS;
}

unsigned short SimulatorHandler::stop_fake_usrept()
{
	// static const int BUF_SIZE = 256;
	// char cmd[BUF_SIZE + 1];
	// memset(cmd, 0x0, sizeof(cmd)/sizeof(cmd[0]));

	// snprintf(cmd, BUF_SIZE, "%s stop", get_script_filepath(FAKE_USREPT_CONTROL));
	// system(cmd);
	run_script(FAKE_USREPT_CONTROL, "stop");
	return RET_SUCCESS;
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
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}
