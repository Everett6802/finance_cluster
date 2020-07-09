#ifndef SIMULATOR_HANDLER_H
#define SIMULATOR_HANDLER_H

#include <string>
#include "common.h"


class SimulatorHandler : public INotify
{
	DECLARE_MSG_DUMPER()

	enum SCRIPT_FILE_TYPE {SIMULATOR_INSTALL, FAKE_ACSPT_CONTROL, FAKE_USREPT_CONTROL, SCRIPT_FILE_TYPE_SIZE};

	static const char* SIMULATOR_ROOT_FOLDER_PATH;
	static const char* SIMULATOR_PACKAGE_FOLDER_PATH;
	static const char* SIMULATOR_INSTALL_SCRIPT_NAME;
	static const char* FAKE_ACSPT_CONTROL_SCRIPT_NAME;
	static const char* FAKE_USREPT_CONTROL_SCRIPT_NAME;
	static const char* SCRIPT_FILENAME_ARRAY[];

private:
	static bool check_simulator_installed();
	static void assemble_script_filepath(char** filepath, const char* filename);

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

	unsigned short start_fake_acspt(bool need_reset=true);
	unsigned short stop_fake_acspt();

	unsigned short start_fake_usrept(bool need_reset=true);
	unsigned short stop_fake_usrept();

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef SimulatorHandler* PSIMULATOR_HANDLER;

#endif
