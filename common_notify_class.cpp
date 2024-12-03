#include "common.h"

using namespace std;

NotifyCfg::NotifyCfg(NotifyType type, const void* param, size_t param_size) :
	ref_count(0),
	notify_type(type),
	notify_param(NULL)
{
	// printf("NotifyCfg()\n");
	addref(__FILE__, __LINE__);
	if (param != NULL)
	{
		// printf("NotifyCfg()::malloc\n");
		assert(param_size != 0 && "param_size should NOT be 0");
		notify_param = malloc(param_size);
		if (notify_param == NULL)
			throw bad_alloc();
		memcpy(notify_param, param, param_size);
		// printf("param: %d, notify_param: %d\n", *(FakeAcsptControlType*)param, *(FakeAcsptControlType*)notify_param);
	}
}

NotifyCfg::~NotifyCfg()
{
	// printf("~NotifyCfg()\n");
	// assert(notify_param != NULL && "notify_param should be NULL");
	if (notify_param != NULL)
	{
		// printf("~NotifyCfg():free\n");
/*
When allocating memory, the runtime library keeps track of 
the size of each allocation. When you call free(), 
it looks up the address, and if it finds an allocation for that 
address, the correct amount of memory is freed 
*/
		free(notify_param);
		notify_param = NULL;
	}
}

int NotifyCfg::addref(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_add(&ref_count, 1);
	// printf("addref() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	return ref_count;
}

int NotifyCfg::release(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_sub(&ref_count, 1);
	// printf("release() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	assert(ref_count >= 0 && "ref_count should NOT be smaller than 0");
	if (ref_count == 0)
	{
		delete this;
		return 0;
	}

	return ref_count;
}

int NotifyCfg::getref()const
{
	return ref_count;
}

NotifyType NotifyCfg::get_notify_type()const{return notify_type;}

const void* NotifyCfg::get_notify_param()const{return notify_param;}

void NotifyCfg::dump_notify_info()const{}

///////////////////////////

NotifyCfgEx::NotifyCfgEx(NotifyType type, const void* param, size_t param_size) :
	NotifyCfg(type, param, param_size)
{
}

NotifyCfgEx::~NotifyCfgEx()
{
}

int NotifyCfgEx::get_session_id()const
{
	return session_id;
}

int NotifyCfgEx::get_cluster_id()const
{
	return cluster_id;
}

///////////////////////////

NotifyNodeDieCfg::NotifyNodeDieCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_NODE_DIE, param, param_size)
{
	// printf("NotifyNodeDieCfg()\n");
	// fprintf(stderr, "NotifyNodeDieCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	remote_token = (char*)notify_param;
}

NotifyNodeDieCfg::~NotifyNodeDieCfg()
{
	remote_token = NULL;
	// printf("~NotifyNodeDieCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_node_die_param = (char*)notify_param;
	// 	free(notify_node_die_param);
	// 	notify_param = NULL;
	// }
}

const char* NotifyNodeDieCfg::get_remote_token()const
{
	return remote_token;
}

///////////////////////////

NotifySessionExitCfg::NotifySessionExitCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_SESSION_EXIT, param, param_size)
{
	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	// session_id = atoi((char*)notify_param); 
	// session_id = *(int*)notify_param;
	memcpy(&session_id, notify_param, sizeof(int));
}

NotifySessionExitCfg::~NotifySessionExitCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	int* notify_session_exit_param = (int*)notify_param;
	// 	free(notify_session_exit_param);
	// 	notify_param = NULL;
	// }
}

int NotifySessionExitCfg::get_session_id()const
{
	return session_id;
}

///////////////////////////

NotifySystemInfoCfg::NotifySystemInfoCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_GET_SYSTEM_INFO, param, param_size)
{
// // session ID[2 digits]|system info
// 	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
// 	assert(param != NULL && "param should NOT be NULL");
// 	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
// // De-Serialize: convert the type of session id from string to integer  
// 	char session_id_buf[SESSION_ID_BUF_SIZE];
// 	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
// 	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
// 	session_id = atoi(session_id_buf);

// 	const char* param_char = (const char*)notify_param;
// 	system_info = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS);
// 	if (strlen(system_info) == 0)
// 		system_info = NULL;
// 	// fprintf(stderr, "NotifySystemInfoCfg, session id: %d, system_info: %s\n", session_id, system_info);
// session ID[2 digits]|cluster ID[2 digits]|system info
	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char + PAYLOAD_SESSION_ID_DIGITS, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);

	system_info = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS);
	if (strlen(system_info) == 0)
		system_info = NULL;
	// fprintf(stderr, "NotifySystemInfoCfg, session id: %d, system_info: %s\n", session_id, system_info);
}

NotifySystemInfoCfg::~NotifySystemInfoCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

// int NotifySystemInfoCfg::get_session_id()const
// {
// 	return session_id;
// }

// int NotifySystemInfoCfg::get_cluster_id()const
// {
// 	return cluster_id;
// }

const char* NotifySystemInfoCfg::get_system_info()const
{
	return system_info;
}

void NotifySystemInfoCfg::dump_notify_info()const
{
	(system_info == NULL ? printf("No Data") : printf("%s\n", system_info));
}


///////////////////////////

NotifySystemMonitorCfg::NotifySystemMonitorCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_GET_SYSTEM_MONITOR, param, param_size)
{
// session ID[2 digits]|cluster ID[2 digits]|system monitor data
	// fprintf(stderr, "NotifySystemMonitorCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char + PAYLOAD_SESSION_ID_DIGITS, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);

	system_monitor_data = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS);
	if (strlen(system_monitor_data) == 0)
		system_monitor_data = NULL;
	// fprintf(stderr, "NotifySystemMonitorCfg, session id: %d, system_monitor_data: %s\n", session_id, system_monitor_data);
}

NotifySystemMonitorCfg::~NotifySystemMonitorCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

const char* NotifySystemMonitorCfg::get_system_monitor_data()const
{
	return system_monitor_data;
}

///////////////////////////

NotifySimulatorVersionCfg::NotifySimulatorVersionCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_GET_SIMULATOR_VERSION, param, param_size)
{
// session ID[2 digits]|cluster ID[2 digits]|system info
	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char + PAYLOAD_SESSION_ID_DIGITS, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);

	simulator_version = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS);
	if (strlen(simulator_version) == 0)
		simulator_version = NULL;
	// fprintf(stderr, "NotifySimulatorVersionCfg, session id: %d, system_info: %s\n", session_id, system_info);
}

NotifySimulatorVersionCfg::~NotifySimulatorVersionCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

// int NotifySimulatorVersionCfg::get_session_id()const
// {
// 	return session_id;
// }

// int NotifySimulatorVersionCfg::get_cluster_id()const
// {
// 	return cluster_id;
// }

const char* NotifySimulatorVersionCfg::get_simulator_version()const
{
	return simulator_version;
}

///////////////////////////

NotifySimulatorInstallCfg::NotifySimulatorInstallCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_INSTALL_SIMULATOR, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize:
	simulator_package_filepath = (char*)notify_param;
}

NotifySimulatorInstallCfg::~NotifySimulatorInstallCfg()
{
}

const char* NotifySimulatorInstallCfg::get_simulator_package_filepath()const
{
	return simulator_package_filepath;
}

///////////////////////////

NotifyFakeAcsptConfigApplyCfg::NotifyFakeAcsptConfigApplyCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_APPLY_FAKE_ACSPT_CONFIG, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize:
	fake_acspt_config_line_list_str = (char*)notify_param;
}

NotifyFakeAcsptConfigApplyCfg::~NotifyFakeAcsptConfigApplyCfg()
{
}

const char* NotifyFakeAcsptConfigApplyCfg::get_fake_acspt_config_line_list_str()const
{
	return fake_acspt_config_line_list_str;
}

///////////////////////////

NotifyFakeUsreptConfigApplyCfg::NotifyFakeUsreptConfigApplyCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_APPLY_FAKE_USREPT_CONFIG, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize:
	fake_usrept_config_line_list_str = (char*)notify_param;
}

NotifyFakeUsreptConfigApplyCfg::~NotifyFakeUsreptConfigApplyCfg()
{
}

const char* NotifyFakeUsreptConfigApplyCfg::get_fake_usrept_config_line_list_str()const
{
	return fake_usrept_config_line_list_str;
}

///////////////////////////

NotifyFakeAcsptControlCfg::NotifyFakeAcsptControlCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_CONTROL_FAKE_ACSPT, param, param_size)
{
	// printf("NotifyFakeAcsptControlCfg()\n");
	// fprintf(stderr, "NotifyFakeAcsptControlCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize: convert the type of session id from string to integer  
	// fake_acspt_control_type = *(FakeAcsptControlType*)notify_param;   // Check if better: fake_acspt_control_type = (FakeAcsptControlType)atoi((char*)notify_param);
	memcpy(&fake_acspt_control_type, param, param_size);
	// printf("NotifyFakeAcsptControlCfg::fake_acspt_control_type: %d\n", fake_acspt_control_type);
}

NotifyFakeAcsptControlCfg::~NotifyFakeAcsptControlCfg()
{
	// printf("~NotifyFakeAcsptControlCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_fake_acspt_control_param = (char*)notify_param;
	// 	free(notify_fake_acspt_control_param);
	// 	notify_param = NULL;
	// }
}

FakeAcsptControlType NotifyFakeAcsptControlCfg::get_fake_acspt_control_type()const
{
	return fake_acspt_control_type;
}

///////////////////////////

NotifyFakeUsreptControlCfg::NotifyFakeUsreptControlCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_CONTROL_FAKE_USREPT, param, param_size)
{
	// printf("NotifyFakeAcsptControlCfg()\n");
	// fprintf(stderr, "NotifyFakeAcsptControlCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize: convert the type of session id from string to integer  
	// fake_usrept_control_type = *(FakeUsreptControlType*)notify_param;   // Check if better: fake_acspt_control_type = (FakeAcsptControlType)atoi((char*)notify_param);
	memcpy(&fake_usrept_control_type, param, param_size);
	// printf("NotifyFakeAcsptControlCfg::fake_acspt_control_type: %d\n", fake_acspt_control_type);
}

NotifyFakeUsreptControlCfg::~NotifyFakeUsreptControlCfg()
{
	// printf("~NotifyFakeAcsptControlCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_fake_acspt_control_param = (char*)notify_param;
	// 	free(notify_fake_acspt_control_param);
	// 	notify_param = NULL;
	// }
}

FakeUsreptControlType NotifyFakeUsreptControlCfg::get_fake_usrept_control_type()const
{
	return fake_usrept_control_type;
}


///////////////////////////

NotifyFakeAcsptStateCfg::NotifyFakeAcsptStateCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_GET_FAKE_ACSPT_STATE, param, param_size)
{
// session ID[2 digits]|cluster ID[2 digits]|fake acspt state
	// fprintf(stderr, "NotifyFakeAcsptStateCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char + PAYLOAD_SESSION_ID_DIGITS, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);

	fake_acspt_state = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS);
	if (strlen(fake_acspt_state) == 0)
		fake_acspt_state = NULL;
	// fprintf(stderr, "NotifyFakeAcsptStateCfg, session id: %d, system_info: %s\n", session_id, system_info);
}

NotifyFakeAcsptStateCfg::~NotifyFakeAcsptStateCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

// int NotifyFakeAcsptStateCfg::get_session_id()const
// {
// 	return session_id;
// }

// int NotifyFakeAcsptStateCfg::get_cluster_id()const
// {
// 	return cluster_id;
// }

const char* NotifyFakeAcsptStateCfg::get_fake_acspt_state()const
{
	return fake_acspt_state;
}


///////////////////////////

NotifyFakeAcsptDetailCfg::NotifyFakeAcsptDetailCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_GET_FAKE_ACSPT_STATE, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char + PAYLOAD_SESSION_ID_DIGITS, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);

	fake_acspt_detail = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS);
	if (strlen(fake_acspt_detail) == 0)
		fake_acspt_detail = NULL;
	// fprintf(stderr, "NotifySystemInfoCfg, session id: %d, system_info: %s\n", session_id, system_info);
}

NotifyFakeAcsptDetailCfg::~NotifyFakeAcsptDetailCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

// int NotifyFakeAcsptDetailCfg::get_session_id()const
// {
// 	return session_id;
// }

// int NotifyFakeAcsptDetailCfg::get_cluster_id()const
// {
// 	return cluster_id;
// }

const char* NotifyFakeAcsptDetailCfg::get_fake_acspt_detail()const
{
	return fake_acspt_detail;
}


///////////////////////////

NotifyFileTransferConnectCfg::NotifyFileTransferConnectCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_CONNECT_FILE_TRANSFER, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
	sender_token = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS);
	int sender_token_len = strlen(sender_token);
	if (sender_token_len == 0)
		sender_token = NULL;
	filepath = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS + sender_token_len + 1);
	if (strlen(filepath) == 0)
		filepath = NULL;
}

NotifyFileTransferConnectCfg::~NotifyFileTransferConnectCfg()
{
	filepath = NULL;
	sender_token = NULL;
}

const char* NotifyFileTransferConnectCfg::get_sender_token()const
{
	return sender_token;
}

const char* NotifyFileTransferConnectCfg::get_filepath()const
{
	return filepath;
}

///////////////////////////

NotifyFileTransferAbortCfg::NotifyFileTransferAbortCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_ABORT_FILE_TRANSFER, param, param_size)
{
	// printf("NotifyFileTransferAbortCfg()\n");
	// fprintf(stderr, "NotifyFileTransferAbortCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	remote_token = (char*)notify_param;
}

NotifyFileTransferAbortCfg::~NotifyFileTransferAbortCfg()
{
	remote_token = NULL;
}

const char* NotifyFileTransferAbortCfg::get_remote_token()const
{
	return remote_token;
}

///////////////////////////

NotifyFileTransferCompleteCfg::NotifyFileTransferCompleteCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_COMPLETE_FILE_TRANSFER, param, param_size)
{
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
	static const int RETURN_CODE_BUF_SIZE = sizeof(unsigned short) + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
// De-Serialize: convert the type of cluster id from string to integer  
	param_char += PAYLOAD_SESSION_ID_DIGITS;
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(char) * CLUSTER_ID_BUF_SIZE);
	memcpy(cluster_id_buf, param_char, sizeof(char) * PAYLOAD_CLUSTER_ID_DIGITS);
	cluster_id = atoi(cluster_id_buf);
// De-Serialize: convert the type of ret code from string to integer  
	param_char += PAYLOAD_CLUSTER_ID_DIGITS;
	char return_code_buf[RETURN_CODE_BUF_SIZE];
	memset(return_code_buf, 0x0, sizeof(char) * RETURN_CODE_BUF_SIZE);
	memcpy(return_code_buf, param_char, sizeof(unsigned short));
	return_code = atoi(return_code_buf);
// De-Serialize: remote token
	param_char += sizeof(unsigned short);
	remote_token = param_char;
}

NotifyFileTransferCompleteCfg::~NotifyFileTransferCompleteCfg()
{
	remote_token = NULL;
}

const char* NotifyFileTransferCompleteCfg::get_remote_token()const
{
	return remote_token;
}

// int NotifyFileTransferCompleteCfg::get_session_id()const
// {
// 	return session_id;
// }

// int NotifyFileTransferCompleteCfg::get_cluster_id()const
// {
// 	return cluster_id;
// }

unsigned short NotifyFileTransferCompleteCfg::get_return_code()const
{
	return return_code;
}


//////////////////////////////////////////////////////////

unsigned short NotifySendFileDoneCfg::generate_obj(NotifySendFileDoneCfg **obj, int session_id_param, const char* remote_token_param)
{
	assert(obj != NULL && "obj should NOT be NULL");
	assert(remote_token_param != NULL && "remote_token_param should NOT be NULL");
	int buf_size = PAYLOAD_SESSION_ID_DIGITS + strlen(remote_token_param) + 1;
	char* buf = new char[buf_size];
	if (buf == NULL) throw bad_alloc();
	memset(buf, 0x0, sizeof(char) * buf_size);
	char* buf_ptr = buf;
	memcpy(buf_ptr, &session_id_param, PAYLOAD_SESSION_ID_DIGITS);
	buf_ptr += PAYLOAD_SESSION_ID_DIGITS;
	memcpy(buf_ptr, remote_token_param, strlen(remote_token_param));
	NotifySendFileDoneCfg *obj_tmp = new NotifySendFileDoneCfg(buf, buf_size);
	if (obj_tmp == NULL) throw bad_alloc();
	*obj = obj_tmp;
	delete[] buf;
	// fprintf(stderr, "[generate_obj], session_id: %d, remote_token: %s, remote_token len: %d\n", session_id_param, remote_token_param, strlen(remote_token_param));
	// fprintf(stderr, "[NotifySendFileDoneCfg::generate_obj]  session_id: %d, remote_token: %s, remote_token len: %d\n", obj_tmp->get_session_id(), obj_tmp->get_remote_token(), strlen(remote_token_param));
}

NotifySendFileDoneCfg::NotifySendFileDoneCfg(const void* param, size_t param_size) :
	NotifyCfgEx(NOTIFY_SEND_FILE_DONE, param, param_size)
{
	// printf("NotifySendFileDoneCfg()\n");
	// fprintf(stderr, "NotifySendFileDoneCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	// // remote_token = (char*)notify_param;

	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	// static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
	remote_token = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS);
	if (strlen(remote_token) == 0)
		remote_token = NULL;
}

NotifySendFileDoneCfg::~NotifySendFileDoneCfg()
{
	remote_token = NULL;
}

const char* NotifySendFileDoneCfg::get_remote_token()const
{
	return remote_token;
}


// //////////////////////////////////////////////////////////

// unsigned short NotifyRecvFileDoneCfg::generate_obj(NotifyRecvFileDoneCfg **obj, int session_id_param, const char* node_token_param)
// {
// 	assert(obj != NULL && "obj should NOT be NULL");
// 	assert(node_token_param != NULL && "node_token_param should NOT be NULL");
// 	int buf_size = PAYLOAD_SESSION_ID_DIGITS + strlen(node_token_param) + 1;
// 	char* buf = new char[buf_size];
// 	if (buf == NULL) throw bad_alloc();
// 	memset(buf, 0x0, sizeof(char) * buf_size);
// 	char* buf_ptr = buf;
// 	memcpy(buf_ptr, &session_id_param, PAYLOAD_SESSION_ID_DIGITS);
// 	buf_ptr += PAYLOAD_SESSION_ID_DIGITS;
// 	memcpy(buf_ptr, node_token_param, strlen(node_token_param));
// 	NotifyRecvFileDoneCfg *obj_tmp = new NotifyRecvFileDoneCfg(buf, buf_size);
// 	if (obj_tmp == NULL) throw bad_alloc();
// 	*obj = obj_tmp;
// 	delete[] buf;
// 	// fprintf(stderr, "[generate_obj], session_id: %d, remote_token: %s, remote_token len: %d\n", session_id_param, remote_token_param, strlen(remote_token_param));
// 	// fprintf(stderr, "[generate_obj] obj, session_id: %d, remote_token: %s\n", obj_tmp->get_session_id(), obj_tmp->get_remote_token());
// }

// NotifyRecvFileDoneCfg::NotifyRecvFileDoneCfg(const void* param, size_t param_size) :
// 	NotifyCfgEx(NOTIFY_RECEIVE_FILE_DONE, param, param_size)
// {
// 	// printf("NotifySendFileDoneCfg()\n");
// 	// fprintf(stderr, "NotifySendFileDoneCfg: param:%s, param_size: %d\n", (char*)param, param_size);
// 	// // remote_token = (char*)notify_param;

// 	assert(param != NULL && "param should NOT be NULL");
// 	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
// 	// static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
// // De-Serialize: convert the type of session id from string to integer  
// 	char session_id_buf[SESSION_ID_BUF_SIZE];
// 	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
// 	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
// 	session_id = atoi(session_id_buf);

// 	const char* param_char = (const char*)notify_param;
// 	remote_token = (char*)(param_char + PAYLOAD_SESSION_ID_DIGITS);
// 	if (strlen(remote_token) == 0)
// 		remote_token = NULL;
// }

// NotifyRecvFileDoneCfg::~NotifyRecvFileDoneCfg()
// {
// 	node_token = NULL;
// }

// const char* NotifyRecvFileDoneCfg::get_node_token()const
// {
// 	return node_token;
// }

//////////////////////////////////////////////////////////

NotifySwitchLeaderCfg::NotifySwitchLeaderCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_SWITCH_LEADER, param, param_size)
{
// Caution: don't implement as below. The types of char and int are different. Can't be transformed directly
	// node_id = *(int*)notify_param;
	// node_id = atoi((char*)notify_param);
	memcpy(&node_id, notify_param, param_size);
	// fprintf(stderr, "[NotifySwitchLeaderCfg::NotifySwitchLeaderCfg] param:%s, param_size: %d, node_id: %d\n", (char*)param, param_size, node_id);
}

NotifySwitchLeaderCfg::~NotifySwitchLeaderCfg(){}

int NotifySwitchLeaderCfg::get_node_id()const
{
	return node_id;
}

//////////////////////////////////////////////////////////

NotifyRemoveFollowerCfg::NotifyRemoveFollowerCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_REMOVE_FOLLOWER, param, param_size)
{
// Caution: don't implement as below. The types of char and int are different. Can't be transformed directly
	// node_id = *(int*)notify_param;
	// node_id = atoi((char*)notify_param);
	memcpy(&node_id, notify_param, param_size);
	// fprintf(stderr, "[NotifyRemoveFollowerCfg::NotifyRemoveFollowerCfg] param:%s, param_size: %d, node_id: %d\n", (char*)param, param_size, node_id);
}

NotifyRemoveFollowerCfg::~NotifyRemoveFollowerCfg(){}

int NotifyRemoveFollowerCfg::get_node_id()const
{
	return node_id;
}

///////////////////////////

NotifyEventCfg::NotifyEventCfg(EventCfg* param) :
	NotifyCfg(NOTIFY_ADD_EVENT)
{
	event_param = (EventCfg*)param;
}

NotifyEventCfg::~NotifyEventCfg()
{
// Only a wrapper, don't handle the memory release of EvnetCfg
	event_param = NULL;
}

EventCfg* NotifyEventCfg::get_event_cfg()
{
	return event_param;
}
