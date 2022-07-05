#ifndef SIMULATOR_HANDLER_H
#define SIMULATOR_HANDLER_H

#include <string>
#include "common.h"


class SimulatorHandler : public INotify
{
	DECLARE_MSG_DUMPER()

	enum SCRIPT_FILE_TYPE {SIMULATOR_INSTALL, FAKE_ACSPT_CONTROL, FAKE_USREPT_CONTROL, SCRIPT_FILE_TYPE_SIZE};

	static const char* SIMULATOR_PACKAGE_FOLDER_PATH;
	static const char* SIMULATOR_ROOT_FOLDER_PATH;
	static const char* SIMULATOR_SCRIPTS_FOLDER_NAME;
	static const char* SIMULATOR_CONF_FOLDER_NAME;
	static const char* SIMULATOR_VERSION_FILENAME;
	static const char* SIMULATOR_BUILD_FILENAME;
	static const char* SIMULATOR_UTIL_FILENAME;
	static const char* SIMULATOR_FAKE_ACSPT_SIM_CFG_FILENAME;
	static const char* SIMULATOR_FAKE_USREPT_CFG_FILENAME;
	static const char* SIMULATOR_FAKE_USREPT_CFG_IGNORE_TAG;
	static const char* SIMULATOR_INSTALL_SCRIPT_NAME;
	static const char* FAKE_ACSPT_CONTROL_SCRIPT_NAME;
	static const char* FAKE_USREPT_CONTROL_SCRIPT_NAME;
	static const char* SCRIPT_FILENAME_ARRAY[];

private:
	static bool check_simulator_installed();
	static void assemble_script_filepath(char** filepath, const char* filename);
	static void assemble_simulator_sub_folder_path(char** sub_folder_path, const char* sub_folder_name);

	// char* fake_acspt_control_script_filepath;
	// char* fake_usrept_control_script_filepath;
	char** script_filepath_array;
	PINOTIFY observer;

	// const char* get_fake_acspt_control_script_filepath();
	// const char* get_fake_usrept_control_script_filepath();
	const char* get_script_filepath(SCRIPT_FILE_TYPE script_file_type);
	unsigned short run_script(SCRIPT_FILE_TYPE script_file_type, const char* param_string=NULL);

public:
	SimulatorHandler(PINOTIFY notify);
	virtual ~SimulatorHandler();

	unsigned short initialize();
	unsigned short deinitialize();

	unsigned short install_simulator(const char* simulator_filepath);
	bool is_simulator_installed()const;
	unsigned short get_simulator_version(char* simulator_version, int simulator_version_size)const;

	unsigned short start_fake_acspt(bool need_reset=true);
	unsigned short stop_fake_acspt();

	unsigned short start_fake_usrept(bool need_reset=true);
	unsigned short stop_fake_usrept();

	unsigned short get_fake_acspt_state(char* fake_acspt_state, int fake_acspt_state_size)const;
	unsigned short get_fake_acspt_detail(std::string& fake_acspt_detail)const;

	unsigned short apply_new_fake_acspt_config(const std::list<std::string>& new_config_line_list);
	unsigned short get_fake_acspt_config_value(const std::list<std::string>& config_list, std::list<std::string>& config_line_list)const;

	unsigned short apply_new_fake_usrept_config(const std::list<std::string>& new_config_line_list, const std::list<std::string>& new_pkt_profile_config_line_list, const std::list<std::string>& new_wlan_profile_config_line_list);

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef SimulatorHandler* PSIMULATOR_HANDLER;

#endif
