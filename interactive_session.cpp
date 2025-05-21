#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <dirent.h>
#include <map>
// #include <string>
#include "interactive_session.h"


using namespace std;

// Command type definition
enum InteractiveSessionCommandType
{
	InteractiveSessionCommand_Help,
	InteractiveSessionCommand_SwitchConfigMode,
	InteractiveSessionCommand_GetRole,
	InteractiveSessionCommand_GetClusterDetail,
	InteractiveSessionCommand_GetSystemInfo,
	InteractiveSessionCommand_SearchEvent,
	InteractiveSessionCommand_ListSearchRule,
	// InteractiveSessionCommand_GetNodeSystemInfo,
	InteractiveSessionCommand_GetConfigurationSetupInfo,
	InteractiveSessionCommand_GetRunningSetupInfo,
	InteractiveSessionCommand_StartSystemMonitor,
	InteractiveSessionCommand_StopSystemMonitor,
	InteractiveSessionCommand_SyncFolder,
	InteractiveSessionCommand_SyncFile,
	InteractiveSessionCommand_RemoteSyncFolder,
	InteractiveSessionCommand_RemoteSyncFile,
	InteractiveSessionCommand_GetSimulatorVersion,
	InteractiveSessionCommand_TransferSimulatorPackage,
	InteractiveSessionCommand_InstallSimulator,
	InteractiveSessionCommand_ApplyFakeAcsptConfig,
	InteractiveSessionCommand_GetFakeAcsptConfigValue,
	InteractiveSessionCommand_ApplyFakeUsreptConfig,
	InteractiveSessionCommand_StartFakeAcspt,
	InteractiveSessionCommand_StopFakeAcspt,
	InteractiveSessionCommand_StartFakeUsrept,
	InteractiveSessionCommand_StopFakeUsrept,
	InteractiveSessionCommand_GetFakeAcsptState,
	InteractiveSessionCommand_GetFakeAcsptDetail,
	InteractiveSessionCommand_RunMultiClis,
	InteractiveSessionCommand_SwitchLeader,
	InteractiveSessionCommand_RemoveFollower,
	InteractiveSessionCommand_Exit,
	InteractiveSessionCommandSize
};

// Configuration Command type definition
enum InteractiveSessionConfigCommandType
{
	InteractiveSessionConfigCommand_Help,
	InteractiveSessionConfigCommand_SearchEvent,
	InteractiveSessionConfigCommand_SetupCluster,
	InteractiveSessionConfigCommand_MonitorSystem,
	InteractiveSessionConfigCommand_SyncCluster,
	InteractiveSessionConfigCommand_Exit,
	InteractiveSessionConfigCommandSize
};

struct CommandAttribute
{
	string command;
	unsigned char authority;
	string description;
};
typedef CommandAttribute* PCOMMAND_ATTRIBUTE;
typedef CommandAttribute ConfigCommandAttribute;
typedef ConfigCommandAttribute* PCONFIG_COMMAND_ATTRIBUTE;

static const unsigned char AUTHORITY_ALL = 0x0;
static const unsigned char AUTHORITY_LEADER = 0x1;
static const unsigned char AUTHORITY_ROOT = 0x1 << 1; 

#define CHECK_LDADER(x) ((x & AUTHORITY_LEADER) ? true : false)
#define CHECK_ROOT(x) ((x & AUTHORITY_ROOT) ? true : false)
#define GET_COMMAND(x) interactive_session_command_attr[x].command
#define GET_AUTHORITY(x) interactive_session_command_attr[x].authority
#define GET_DESCRIPTION(x) interactive_session_command_attr[x].description
#define CHECK_AUTHORITY(x, y) (y >= GET_AUTHORITY(x) ? true : false)
#define GET_CONFIG_COMMAND(x) interactive_session_config_command_attr[x].command
#define GET_CONFIG_AUTHORITY(x) interactive_session_config_command_attr[x].authority
#define GET_CONFIG_DESCRIPTION(x) interactive_session_config_command_attr[x].description
#define CHECK_CONFIG_AUTHORITY(x, y) (y >= GET_CONFIG_AUTHORITY(x) ? true : false)

static const CommandAttribute interactive_session_command_attr[InteractiveSessionCommandSize] = 
{
	{.command="help", .authority=AUTHORITY_ALL, .description="The usage"},
	{.command="config", .authority=AUTHORITY_ALL, .description="Switch to configuration mode"},
	{.command="get_role", .authority=AUTHORITY_ALL, .description="Get the role in the cluster"},
	{.command="get_cluster_detail", .authority=AUTHORITY_ALL, .description="Get the cluster detail info"},
	{.command="get_system_info", .authority=AUTHORITY_ALL, .description="Get the system info\n Caution: Leader get the entire cluster system info. Follower only get the node system info"},
	{.command="search_event", .authority=AUTHORITY_ALL, .description="Search for events"},
	{.command="list_search_rule", .authority=AUTHORITY_ALL, .description="List the search rules"},
	{.command="get_configuration_setup", .authority=AUTHORITY_LEADER, .description="Get the configuration setup of the cluster"},
	{.command="get_running_setup", .authority=AUTHORITY_LEADER, .description="Get the running setup of the cluster"},
	{.command="start_system_monitor", .authority=AUTHORITY_LEADER, .description="Start system monitor"},
	{.command="stop_system_monitor", .authority=AUTHORITY_LEADER, .description="Stop system monitor"},
	{.command="sync_folder", .authority=AUTHORITY_ALL, .description="Synchronize all the files in the folder to the Receiver  Param: folderpath (ex. /home/super/test) or No param: exploit the sync folder in the config file\n Caution: Leader synchorinize folders to the entire cluster. Follower only synchorinize to Leader\n Caution: It's required to use absolute folderpath in Follower"},
	{.command="sync_file", .authority=AUTHORITY_ALL, .description="Synchronize a specific file of the folder to the Receiver\n  Param: filename (ex. text.txt, exploit the sync folder in the config file) or filepath (ex. /home/super/text.txt)\n Caution: Leader synchorinize a specific file to the entire cluster. Follower only synchorinize to Leader\n Caution: It's required to use absolute filepath in Follower"},
	{.command="remote_sync_folder", .authority=AUTHORITY_LEADER, .description="Request remote node to synchronize all the files in the folder to the Receiver\n  Param: Node ID\n  Param: folderpath (ex. /home/super/text)\n Caution: Only Leader can request Follower to synchorinize a specific file to Leader\n Caution: It's required to use absolute folderpath in Follower"},
	{.command="remote_sync_file", .authority=AUTHORITY_LEADER, .description="Request remote node to synchronize a specific file of the folder to the Receiver\n  Param: Node ID\n  Param: filepath (ex. /home/super/text.txt)\n Caution: Only Leader can request Follower to synchorinize a specific file to Leader\n Caution: It's required to use absolute filepath"},
	{.command="get_simulator_version", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Get simulator version"},
	{.command="transfer_simulator_package", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Leader transfers the simulator package to each follower\n  Param: Simulator package filepath (ex. /home/super/simulator.tar.xz)"},
	{.command="install_simulator", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Install simulator\n  Param: Simulator package filepath (ex. /home/super/simulator.tar.xz)"},
	{.command="apply_fake_acspt_config", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Apply new config to all fake acepts\n  Param: Fake acspt config filepath (ex. /home/super/new_fake_acspt_sim.cfg)"},
	{.command="get_fake_acspt_config_value", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Get the config value from fake acspts config file\n  Param: Acspt config list string (ex. CONFIG1,CONFIG2,CONFIG3)"},
	{.command="apply_fake_usrept_config", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Apply new config to all fake usrepts\n  Param: Fake usrept config filepath (ex. /home/super/new_fake_usrept.cfg)"},
	{.command="start_fake_acspt", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Start fake acepts"},
	{.command="stop_fake_acspt", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Stop fake acepts"},
	{.command="start_fake_usrept", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Start fake usrepts"},
	{.command="stop_fake_usrept", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Stop fake usrepts"},
	{.command="get_fake_acspt_state", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Get the states of all fake acepts"},
	{.command="get_fake_acspt_detail", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Get the details of all fake acepts"},
	{.command="run_multi_clis", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Run multiple CLI commands at a time\n  Param: The filepath of defining CLI commands (ex. /home/super/cli_commands)"},
	{.command="switch_leader", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Switch leader to specific follower\n  Param: Node ID"},
	{.command="remove_follower", .authority=AUTHORITY_LEADER|AUTHORITY_ROOT, .description="Leader remove specific follower\n  Param: Node ID"},
	{.command="exit", .authority=AUTHORITY_ALL, .description="Exit the session"}
};

static const char* interactive_session_unset_search_event_config_command = "unset";
static const char* interactive_session_search_event_type_config_command[] = 
{
	"operate_node",
	"telnet_console",
	"sync_data"
};
static const int SEARCH_EVENT_TYPE_CONFIG_COMMAND_SIZE = sizeof(interactive_session_search_event_type_config_command) / sizeof(interactive_session_search_event_type_config_command[0]);

static const char* interactive_session_search_event_severity_config_command[] = 
{
	"critical",
	"warning",
	"informational"
};
static const int SEARCH_EVENT_SEVERITY_CONFIG_COMMAND_SIZE = sizeof(interactive_session_search_event_severity_config_command) / sizeof(interactive_session_search_event_severity_config_command[0]);

static const char* interactive_session_search_event_category_config_command[] = 
{
	"cluster",
	"console"
};
static const int SEARCH_EVENT_CATEGORY_CONFIG_COMMAND_SIZE = sizeof(interactive_session_search_event_category_config_command) / sizeof(interactive_session_search_event_category_config_command[0]);

// static const char* ConfigCommandSearchEventDescritpion = "Set criterion for searching event\n"
// " * time_option\n  1) Last 24 hours  2) Last 7 days  3) Last 30 days\n"
// " * time\n  Time format: YYYY/mm/dd_HH:MM_YYYY/mm/dd_HH:MM"
// " * type\n"
// " * severity\n"
// " * category\n";
static const string ConfigCommandSearchEventDescritpion = string("Set rules for searching event\n")
													    + string(" * time_option\n  1) Last 24 hours  2) Last 7 days  3) Last 30 days\n")
													    + string(" * time\n  Time format: YYYY/mm/dd_HH:MM-YYYY/mm/dd_HH:MM\n")
													    + string(" * type\n  ") + join(interactive_session_search_event_type_config_command, SEARCH_EVENT_TYPE_CONFIG_COMMAND_SIZE) + string("\n")
													    + string(" * severity\n  ") + join(interactive_session_search_event_severity_config_command, SEARCH_EVENT_SEVERITY_CONFIG_COMMAND_SIZE) + string("\n")
													    + string(" * category\n  ") + join(interactive_session_search_event_category_config_command, SEARCH_EVENT_CATEGORY_CONFIG_COMMAND_SIZE) + string("\n")
														+ string(" * description\n  sub-string in the description\n")
														+ string(" Dismiss the setting: unset");

static const string ConfigCommandSetupClusterDescritpion = string("Set configurations for cluster setup\n")
                                                          + string(" * network\n  network  Ex: 10.206.24.0\n")
                                                          + string(" * netmask_digits\n  netmask digit  Ex: 23\n")
														  + string(" Caution: can only be set while cluster is single (no other Followers)");

static const string ConfigCommandMonitorSystemDescritpion = string("Set configurations for monitoring system\n")
                                                          + string(" * period\n  monitor period in seconds");
														  
static const string ConfigCommandSyncClusterDescritpion = string("Set configurations for synchronizing data in the cluster\n")
                                                        + string(" * folderpath\n  folder path");

static const ConfigCommandAttribute interactive_session_config_command_attr[InteractiveSessionConfigCommandSize] = 
{
	{.command="help", .authority=AUTHORITY_ALL, .description="The usage in configuration mode"},
	{.command="search_event", .authority=AUTHORITY_ALL, .description=ConfigCommandSearchEventDescritpion.c_str()},
	{.command="setup_cluster", .authority=AUTHORITY_LEADER, .description=ConfigCommandSetupClusterDescritpion.c_str()},
	{.command="monitor_system", .authority=AUTHORITY_LEADER, .description=ConfigCommandMonitorSystemDescritpion.c_str()},
	{.command="sync_cluster", .authority=AUTHORITY_LEADER, .description=ConfigCommandSyncClusterDescritpion.c_str()},
	{.command="exit", .authority=AUTHORITY_ALL, .description="Exit the configuration mode"}
};

// static const char *interactive_session_command[InteractiveSessionCommandSize] = 
// {
// 	"help",
// 	"exit",
// 	"get_cluster_detail",
// 	"get_system_info",
// 	// "get_node_system_info",
// 	"start_system_monitor",
// 	"stop_system_monitor",
// 	"get_simulator_version",
// 	"transfer_simulator_package",
// 	"install_simulator",
// 	"apply_fake_acspt_config",
// 	"get_fake_acspt_config_value",
// 	"apply_fake_usrept_config",
// 	"start_fake_acspt",
// 	"stop_fake_acspt",
// 	"start_fake_usrept",
// 	"stop_fake_usrept",
// 	"get_fake_acspt_state",
// 	"get_fake_acspt_detail",
// 	"run_multi_clis"
// };

typedef map<string, InteractiveSessionCommandType> COMMAND_MAP;
typedef COMMAND_MAP::iterator COMMAND_MAP_ITER;
typedef map<string, InteractiveSessionConfigCommandType> CONFIG_COMMAND_MAP;
typedef CONFIG_COMMAND_MAP::iterator CONFIG_COMMAND_MAP_ITER;

static const char* INTERACTIVE_PROMPT = "FC> ";
static const char* INTERACTIVE_CONFIG_PROMPT = "FC(config)> ";
// static const char* INCORRECT_COMMAND_ARGUMENT_FORMAT = "Incorrect command[%s] argument: %s";

static string welcome_phrases = "\n************** Welcome to Finance Cluster CLI **************\n\n";
static string incomplete_command_phrases = "\nIncomplete Command\n\n";
static string incorrect_command_phrases = "\nIncorrect Command\n\n";

static COMMAND_MAP command_map;
static CONFIG_COMMAND_MAP config_command_map;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

const int InteractiveSession::REQ_BUF_SIZE = 1024;
const int InteractiveSession::RSP_BUF_VERY_SHORT_SIZE = 32;
const int InteractiveSession::RSP_BUF_SHORT_SIZE = 64;
const int InteractiveSession::RSP_BUF_SIZE = 256;
const int InteractiveSession::RSP_BUF_LONG_SIZE = 1024;
const int InteractiveSession::RSP_BUF_VERY_LONG_SIZE = 4096;
const int InteractiveSession::MAX_ARGC = 20;

// const char* InteractiveSession::session_thread_tag = "Listen Thread";
const int InteractiveSession::WAIT_SESSION_TIMEOUT = 60; // 5 seconds

static const int SECONDS_IN_A_DAY = 86400;
static const int TIME_INTERVAL_LIST[] = {SECONDS_IN_A_DAY, 7 * SECONDS_IN_A_DAY, 30 * SECONDS_IN_A_DAY};
static const int TIME_INTERVAL_LIST_SIZE = sizeof(TIME_INTERVAL_LIST) / sizeof(TIME_INTERVAL_LIST[0]); 
static const int DEFAULT_TIME_OPTION = 1;

void InteractiveSession::init_command_map()
{
	static bool init_map = false;
	if (!init_map)
	{
		pthread_mutex_lock(&mtx);
		if (!init_map)
		{
			for (int i = 0 ; i < InteractiveSessionCommandSize ; i++)
			{
				// command_map.insert(make_pair(string(interactive_session_command[i]), (InteractiveSessionCommandType)i));
				// printf("Insert command: %s\n", interactive_session_command_attr[i].command);
				command_map.insert(make_pair(interactive_session_command_attr[i].command, (InteractiveSessionCommandType)i));
			}
			// for(COMMAND_MAP_ITER iter = command_map.begin() ; iter != command_map.end() ; iter++)
			// {
			// 	string command_description = (string)iter->first;
			// 	int command_type = (int)iter->second;
			// 	STATIC_WRITE_FORMAT_DEBUG("Command %d: %s", command_type, command_description.c_str());
			// }
			init_map = true;
		}
		pthread_mutex_unlock(&mtx);
	}
}

void InteractiveSession::init_config_command_map()
{
	static bool init_config_map = false;
	if (!init_config_map)
	{
		pthread_mutex_lock(&mtx);
		if (!init_config_map)
		{
			for (int i = 0 ; i < InteractiveSessionConfigCommandSize ; i++)
			{
				// printf("Insert config command: %s\n", interactive_session_config_command_attr[i].command);
				config_command_map.insert(make_pair(interactive_session_config_command_attr[i].command, (InteractiveSessionConfigCommandType)i));
			}
			init_config_map = true;
		}
		pthread_mutex_unlock(&mtx);
	}
}

InteractiveSession::InteractiveSession(PINOTIFY notify, PIMANAGER mgr, int client_fd, const sockaddr_in& client_sockaddr, int interactive_session_id) :
	observer(notify),
	manager(mgr),
	session_exit(0),
	session_tid(0),
	session_thread_ret(RET_SUCCESS),
	multi_clis_tid(0),
	multi_clis_thread_ret(RET_SUCCESS),
	multi_clis_filepath(NULL),
	sock_fd(client_fd),
	session_id(interactive_session_id),
	is_root(false),
	is_leader(false),
	node_token(NULL),
	authority_mask(0x0),
	system_monitor(false),
	monitor_system_timer_thread(NULL),
	// system_monitor_period(0),
	is_config_mode(false),
	cluster_config_updated(false)
{
	IMPLEMENT_MSG_DUMPER()
	IMPLEMENT_EVT_RECORDER()
	event_search_rule = {.need_search_event_time=false, .need_search_event_type=false, .need_search_event_severity=false, .need_search_event_category=false};
	event_search_rule.need_search_event_time = true;
	event_search_rule.search_event_time_end = time(0);
	event_search_rule.search_event_time_begin = event_search_rule.search_event_time_end - TIME_INTERVAL_LIST[DEFAULT_TIME_OPTION];
	init_command_map();
	init_config_command_map();
	memcpy(&sock_addr, &client_sockaddr, sizeof(sockaddr_in));
	memset(session_tag, 0x0, sizeof(char) * 64);
	snprintf(session_tag, 64, "%d (%s:%d)", session_id, inet_ntoa(sock_addr.sin_addr), htons(sock_addr.sin_port));
	// printf("is_root: %s\n", (is_root ? "True" : "False"));
}
	
InteractiveSession::~InteractiveSession()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "%s Error occurs in InteractiveSession::~InteractiveSession(), due to :%s", session_tag, GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (node_token != NULL)
	{
		free(node_token);
		node_token = NULL;
	}
	if (observer != NULL)
		observer = NULL;
	if (manager != NULL)
		manager = NULL;

	RELEASE_EVT_RECORDER()
	RELEASE_MSG_DUMPER()
}

unsigned short InteractiveSession::initialize(/*int system_monitor_period_value*/)
{
	assert(manager != NULL && "manager should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	// system_monitor_period = system_monitor_period_value;
	NodeType node_type = NONE;
    ret = manager->get(PARAM_NODE_TYPE, (void*)&node_type);
 	if (CHECK_FAILURE(ret))
		return ret;	
    ret = manager->get(PARAM_NODE_TOKEN, (void*)&node_token);
 	if (CHECK_FAILURE(ret))
		return ret;	
	is_leader = (node_type == LEADER ? true : false);
	is_root = is_root_user();

	authority_mask = 0x0;
	if (is_leader)
		authority_mask |= AUTHORITY_LEADER;
	if (is_root)
		authority_mask |= AUTHORITY_ROOT;
	WRITE_FORMAT_DEBUG("is_root: %s, is_leader: %s, authority_mask: %d", (is_root ? "true" : "false"), (is_leader ? "true" : "false"), authority_mask);

	if (pthread_create(&session_tid, NULL, session_thread_handler, this) != 0)
	{
		WRITE_FORMAT_ERROR("Fail to create a handler thread of interactive session[%s], due to: %s", session_tag, strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}
	WRITE_EVT_RECORDER(TelnetConsoleEventCfg, inet_ntoa(sock_addr.sin_addr), session_id, 0);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	if (monitor_system_timer_thread != NULL)
	{
		ret = monitor_system_timer_thread->deinitialize();
		delete monitor_system_timer_thread;
		monitor_system_timer_thread = NULL;		
	}

// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&session_exit, 1);
	// sleep(1);
	usleep(10000);
// Check interactive session thread alive
	// bool session_thread_alive = false;
	if (session_tid != 0)
	{
		int kill_ret = pthread_kill(session_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_FORMAT_WARN("The worker thread of interactive session[%s] did NOT exist......", session_tag);
			ret = RET_SUCCESS;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_FORMAT_ERROR("The worker thread of interactive session[%s] is invalid", session_tag);
			ret = RET_FAILURE_HANDLE_THREAD;
		}
		else
		{
			WRITE_FORMAT_DEBUG("The worker thread of interactive session[%s] is STILL alive", session_tag);
// Kill the thread
		    if (pthread_cancel(session_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of interactive session[%s], due to: %s", session_tag, strerror(errno));
			// sleep(1);
			usleep(100000);
		}
		WRITE_FORMAT_DEBUG("Wait for the worker thread of interactive session[%s]'s death...", session_tag);
		pthread_join(session_tid, NULL);
		WRITE_EVT_RECORDER(TelnetConsoleEventCfg, inet_ntoa(sock_addr.sin_addr), session_id, 1);
		session_tid = 0;

// Wait for interactive session thread's death
		// printf("Session Exit\n");
		if (CHECK_SUCCESS(session_thread_ret))
			WRITE_FORMAT_DEBUG("Wait for the worker thread of interactive session[%s]'s death Successfully !!!", session_tag);
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of interactive session[%s]'s death, due to: %s", session_tag, GetErrorDescription(session_thread_ret));
			ret = session_thread_ret;
		}
	}
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'status' variable accesses the illegal address
	// pthread_join(session_tid, &status);
	// if (status == NULL)
	// 	sWRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	// else
	// {
	// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
	// 	return session_thread_ret;
	// }
// Notify each session to exit and Delete all the sessions
// Implemented in listen cleanup thread handler 
	// INTERACTIVE_SESSION_ITER iter = interactive_session_deque.begin();
	// while(iter != interactive_session_deque.end())
	// {
	// 	PINTERACTIVE_SESSION interactive_session = (PINTERACTIVE_SESSION)(*iter);
	// 	iter++;
	// 	if (interactive_session != NULL)
	// 	{
	// 		interactive_session->notify_exit();
	// 		delete interactive_session;
	// 		interactive_session = NULL;
	// 	}
	// }
	// interactive_session_deque.clear();
	if (sock_fd != -1)
	{
		close(sock_fd);
		sock_fd = -1;
	}

	return ret;
}

const char* InteractiveSession::get_session_tag()const
{
	return session_tag;
}

unsigned short InteractiveSession::print_console(const std::string& console_string)const
{
	print_to_console(console_string);
	return RET_SUCCESS;
}

bool InteractiveSession::check_command_authority(int command_type)
{
	// static InteractiveSessionCommandType PRIVILEGE_USER_COMMAND_LIST[] = 
	// {
	// 	InteractiveSessionCommand_GetSimulatorVersion,
	// 	InteractiveSessionCommand_TransferSimulatorPackage,
	// 	InteractiveSessionCommand_InstallSimulator,
	// 	InteractiveSessionCommand_ApplyFakeAcsptConfig,
	// 	InteractiveSessionCommand_GetFakeAcsptConfigValue,
	// 	InteractiveSessionCommand_ApplyFakeUsreptConfig,
	// 	InteractiveSessionCommand_StartFakeAcspt,
	// 	InteractiveSessionCommand_StopFakeAcspt,
	// 	InteractiveSessionCommand_StartFakeUsrept,
	// 	InteractiveSessionCommand_StopFakeUsrept,
	// 	InteractiveSessionCommand_GetFakeAcsptState,
	// 	InteractiveSessionCommand_GetFakeAcsptDetail,
	// 	InteractiveSessionCommand_RunMultiClis
	// };
	// static int PRIVILEGE_USER_COMMAND_LIST_LEN = sizeof(PRIVILEGE_USER_COMMAND_LIST) / sizeof(PRIVILEGE_USER_COMMAND_LIST[0]);
	// for (int i = 0 ; i < PRIVILEGE_USER_COMMAND_LIST_LEN ; i++)
	// {
	// 	if (command_type == PRIVILEGE_USER_COMMAND_LIST[i])
	// 		return true;
	// }
	// return false;
	return CHECK_AUTHORITY(command_type, authority_mask);
}

bool InteractiveSession::check_config_command_authority(int command_type)
{
	return CHECK_CONFIG_AUTHORITY(command_type, authority_mask);
}

unsigned short InteractiveSession::get_complete_sync_folderpath(string& sync_folderpath)const
{
	unsigned short ret = RET_SUCCESS;
	// char folderpath[DEF_LONG_STRING_SIZE]; 
	// if (strchr(sync_folderpath.c_str(), '~') != NULL)
	// {
	// 	const char* sync_folderpath_start_ptr = &(sync_folderpath.c_str()[2]);
	// 	if (strcmp(get_username(), "root") == 0)
	// 		snprintf(folderpath, DEF_LONG_STRING_SIZE, "/root/%s", sync_folderpath_start_ptr);
	// 	else
	// 		snprintf(folderpath, DEF_LONG_STRING_SIZE, "/home/%s/%s", get_username(), sync_folderpath_start_ptr);
	// }
	// else
	// 	strcpy(folderpath, sync_folderpath.c_str());
	if (sync_folderpath.c_str()[0] != '~')
		return RET_FAILURE_INVALID_ARGUMENT;
	string sync_folderpath_tmp = sync_folderpath;
	if (strcmp(get_username(), "root") == 0)
		sync_folderpath = string("/root/");
	else
		sync_folderpath = string("/home/") + string(get_username()) + string("/");
	const char* sync_folderpath_tmp_start_ptr = &(sync_folderpath_tmp.c_str()[2]);
	sync_folderpath += string(sync_folderpath_tmp_start_ptr);
	return ret;
}

bool InteractiveSession::check_cluster_is_single()const
{
	bool is_single;
	manager->get(PARAM_CLUSTER_IS_SINGLE, (void*)&is_single);
	return is_single;
}

void* InteractiveSession::session_thread_handler(void* pvoid)
{
	InteractiveSession* pthis = (InteractiveSession*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->session_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->session_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->session_thread_ret))
	{
		// pthread_cleanup_push(session_thread_cleanup_handler, pthis);
		pthis->session_thread_ret = pthis->session_thread_handler_internal();
		// pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->session_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->session_thread_ret)));
	pthread_exit(NULL);
}

unsigned short InteractiveSession::session_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of interactive session is running", session_tag);
	unsigned short ret = RET_SUCCESS;

	struct pollfd pollfds[1];
	char req_buf[REQ_BUF_SIZE];
	FILE* sock_fp = NULL;
	if ((sock_fp = fdopen(sock_fd, "a+")) == 0) 
	{
		WRITE_FORMAT_ERROR("[%s] Fail to transform FD to FP, due to: %s", session_tag, strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
// Print the welcome phrases
	print_to_console(welcome_phrases);
// Print the prompt
	print_prompt_to_console();
// Parse the command from user
	while(session_exit == 0)
	{
// Wait for the input event from user
      	memset(pollfds, 0, sizeof(pollfds));
      	pollfds[0].fd = sock_fd;
      	pollfds[0].events = POLLIN;
      	int res = poll(pollfds, 1, WAIT_SESSION_TIMEOUT);
      	if (res == -1) 
		{
			WRITE_FORMAT_ERROR("[%s] poll() fails, due to: %s", session_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			usleep(100000);
			continue;
		}
      	if ((pollfds[0].revents & POLLIN) != POLLIN)
		{
			usleep(100000);
			continue;
		}
// Read the command and parse it
    	if (fgets(req_buf, REQ_BUF_SIZE, sock_fp) == NULL)
    		break;
     	// WRITE_FORMAT_DEBUG("Command Line: %s", req_buf);
// Parse the command
		char *command_line_outer = req_buf;
		char *rest_command_line_outer =  NULL;
		char *argv_outer[MAX_ARGC];
		int cur_argc_outer = 0;
		while ((argv_outer[cur_argc_outer] = strtok_r(command_line_outer, ";\t\n\r", &rest_command_line_outer)) != NULL)
		{
			// WRITE_FORMAT_DEBUG("Command Argument[Outer]: %s, rest: %s", argv_outer[cur_argc_outer], rest_command_line_outer);
			char *command_line_inner =  argv_outer[cur_argc_outer];
			char *rest_command_line_inner =  NULL;
			char *argv_inner[MAX_ARGC];
			int cur_argc_inner = 0;
			bool can_execute = true;
			while ((argv_inner[cur_argc_inner] = strtok_r(command_line_inner, " ", &rest_command_line_inner)) != NULL)
			{
				// WRITE_FORMAT_DEBUG("Command Argument[Inner]: %s, rest: %s", argv_inner[cur_argc_inner], rest_command_line_inner);
				if (command_line_inner != NULL)
				{
					string cur_command = string(argv_inner[cur_argc_inner]);
					// printf("cur command: %s\n", cur_command.c_str());
					if (is_config_mode)
					{
// Check if the config command exist
						CONFIG_COMMAND_MAP::iterator iter = config_command_map.find(cur_command/*string(argv_inner[cur_argc_inner])*/);
						if (iter == config_command_map.end())
						{
							WRITE_FORMAT_ERROR("Error!! Unknown config command: %s", argv_inner[0]);
							char unknown_config_command_error[64];
							snprintf(unknown_config_command_error, 64, "Unknown config command: %s\n", argv_inner[0]);
							print_to_console(string(unknown_config_command_error));
							can_execute = false;
							break;
						}
						else
						{
// Some commmands require privilege user
							int command_type = (int)iter->second;
							if (!check_command_authority(command_type))
							{
								WRITE_FORMAT_WARN("The User[mask: %d] doesn't have the authority[%d] to execute the %s config command", authority_mask, GET_CONFIG_AUTHORITY(command_type), argv_inner[0]);
								static string no_role_string("No Authority to Execute\n");
								print_to_console(no_role_string);
								can_execute = false;
							}						
						}						
					}
					else
					{
// Check if the command exist
						if (system_monitor && (strcmp(cur_command.c_str(), "quit") == 0))
						{
							argv_inner[0] = "stop_system_monitor";
							cur_command = string(argv_inner[0]);
						}

						COMMAND_MAP::iterator iter = command_map.find(cur_command/*string(argv_inner[cur_argc_inner])*/);
						if (iter == command_map.end())
						{
							WRITE_FORMAT_ERROR("Error!! Unknown command: %s", argv_inner[0]);
							char unknown_command_error[64];
							snprintf(unknown_command_error, 64, "Unknown command: %s\n", argv_inner[0]);
							print_to_console(string(unknown_command_error));
							can_execute = false;
							break;
						}
						else
						{
// Stop system monitor before executing other commands if the system monitor is enabled
							if (system_monitor && (strcmp(argv_inner[0], "stop_system_monitor") != 0))
							{
								WRITE_WARN("Warning!! System Monitor Enabled");
								static string system_monitor_string("System Montior Enabled\n");
								print_to_console(system_monitor_string);
								goto OUT;
							}
// Some commmands require privilege user
							int command_type = (int)iter->second;
							if (!check_command_authority(command_type))
							{
								// if (!is_root)
								// {
								// 	can_execute = false;
								// 	WRITE_FORMAT_WARN("The %s command requires privilege user", argv_inner[0]);
								// }
								WRITE_FORMAT_WARN("The User[mask: %d] doesn't have the authority[%d] to execute the %s command", authority_mask, GET_AUTHORITY(command_type), argv_inner[0]);
								static string no_role_string("No Authority to Execute\n");
								print_to_console(no_role_string);
								can_execute = false;
							}						
						}
					}
					command_line_inner = NULL;
				}
				cur_argc_inner++;
			}
// Handle command
			if (can_execute)
			{
				if (is_config_mode)
				{
					WRITE_FORMAT_DEBUG("Try to execute the %s config command......", argv_inner[0]);
					ret = handle_config_command(cur_argc_inner, argv_inner);
					if (CHECK_SUCCESS(ret))
						WRITE_FORMAT_DEBUG("Execute the %s config command...... DONE", argv_inner[0]);
					else if (CHECK_WARN(ret))
					{
						char rsp_buf[RSP_BUF_SIZE + 1];
						memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
						snprintf(rsp_buf, RSP_BUF_SIZE, "Warning occurs while executing the %s config command in the session: %s, due to: %s\n", argv_inner[0], session_tag, GetErrorDescription(ret));
// Show warning if warn occurs while executing the command
						WRITE_WARN(rsp_buf);
						snprintf(rsp_buf, RSP_BUF_SIZE, "WARNING  %s: %s\n", argv_inner[0], GetErrorDescription(ret));
						print_to_console(string(rsp_buf));
					}
					else
					{
						static const int BUF_SIZE = 256;
						char buf[BUF_SIZE];
						snprintf(buf, BUF_SIZE, "Unexpected return while executing the config command[%s]: %s", argv_inner[0], GetErrorDescription(ret));
						fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
						throw runtime_error(buf);
					}
				}
				else
				{
					WRITE_FORMAT_DEBUG("Try to execute the %s command......", argv_inner[0]);
					ret = handle_command(cur_argc_inner, argv_inner);
					if (CHECK_SUCCESS(ret))
						WRITE_FORMAT_DEBUG("Execute the %s command...... DONE", argv_inner[0]);
					else if (CHECK_FAILURE(ret))
					{
						char rsp_buf[RSP_BUF_SIZE + 1];
						memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
						snprintf(rsp_buf, RSP_BUF_SIZE, "Error occurs while executing the %s command in the session: %s, due to: %s\n", argv_inner[0], session_tag, GetErrorDescription(ret));
// Show warning if error occurs while executing the command and then exit
						WRITE_ERROR(rsp_buf);
						snprintf(rsp_buf, RSP_BUF_SIZE, "ERROR  %s: %s\n", argv_inner[0], GetErrorDescription(ret));
						print_to_console(string(rsp_buf));
						// return ret;				
					}
					else if (CHECK_WARN(ret))
					{
						char rsp_buf[RSP_BUF_SIZE + 1];
						memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
						snprintf(rsp_buf, RSP_BUF_SIZE, "Warning occurs while executing the %s command in the session: %s, due to: %s\n", argv_inner[0], session_tag, GetErrorDescription(ret));
// Show warning if warn occurs while executing the command
						WRITE_WARN(rsp_buf);
						snprintf(rsp_buf, RSP_BUF_SIZE, "WARNING  %s: %s\n", argv_inner[0], GetErrorDescription(ret));
						print_to_console(string(rsp_buf));
						// goto OUT;
						// return ret;	
					}
					else
					{
						static const int BUF_SIZE = 256;
						char buf[BUF_SIZE];
						snprintf(buf, BUF_SIZE, "Unexpected return while executing the command[%s]: %s", argv_inner[0], GetErrorDescription(ret));
						fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
						throw runtime_error(buf);
					}
				}
			}
			if (command_line_outer != NULL)
				command_line_outer = NULL;
			cur_argc_outer++;
		}
OUT:
		if (session_exit == 0)
		{
// Print the prompt again
			print_prompt_to_console();
		}
	}
// OUT:
	if (sock_fp != NULL)
	{
		fclose(sock_fp);
		sock_fp = NULL;
	}

	if (CHECK_FAILURE(ret))
	{
// Notify the parent to close the session
		size_t notify_param_size = sizeof(int);
		PNOTIFY_CFG notify_cfg = new NotifySessionExitCfg((void*)&session_id, notify_param_size);
		if (notify_cfg == NULL)
			throw bad_alloc();
		WRITE_FORMAT_WARN("[%s] The session is closed due to error: %s", session_tag, GetErrorDescription(ret));
// Asynchronous event
		observer->notify(NOTIFY_SESSION_EXIT, notify_cfg);
		SAFE_RELEASE(notify_cfg)
	}
	return ret;
}

void* InteractiveSession::multi_clis_thread_handler(void* pvoid)
{
	InteractiveSession* pthis = (InteractiveSession*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->multi_clis_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->multi_clis_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->multi_clis_thread_ret))
	{
		pthread_cleanup_push(multi_clis_thread_cleanup_handler, pthis);
		pthis->multi_clis_thread_ret = pthis->multi_clis_thread_handler_internal();
		pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->session_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->session_thread_ret)));
	pthread_exit(NULL);
}

unsigned short InteractiveSession::multi_clis_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of multiple CLIs is running", session_tag);
	unsigned short ret = RET_SUCCESS;
// Read the new config
	list<string> multi_clis_line_list;
	ret = read_file_lines_ex(multi_clis_line_list, multi_clis_filepath);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the multiple CLIs file[%s], due to: %s", multi_clis_filepath, GetErrorDescription(ret));
		return ret;
	}

	string line_list_str;
	list<string>::iterator iter = multi_clis_line_list.begin();
	int multi_clis_line_index = 0;
	while (iter != multi_clis_line_list.end())
	{
// Get one command line
		string multi_clis_line = (string)*iter;
		char* cli_line = strdup(multi_clis_line.c_str());
		if (cli_line == NULL)
		{
			WRITE_FORMAT_ERROR("Fail to allocate memroy: %s", multi_clis_line.c_str());
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}
// Parse the command line
		char *cli_line_tmp = cli_line; 
		char *rest_cli_line =  NULL;
		char *cli_argv[MAX_ARGC];
		int cli_argc = 0;
		while ((cli_argv[cli_argc] = strtok_r(cli_line_tmp, " ", &rest_cli_line)) != NULL)
		{
			// WRITE_FORMAT_DEBUG("Command Argument: %s, rest: %s", cli_argv[cli_argc], rest_cli_line);
			if (cli_line_tmp != NULL)
				cli_line_tmp = NULL;
			cli_argc++;
		}
		// printf("CLI: %s  ", cli_line);
		// for (int i = 0 ; i < cli_argc ; i++)
		// 	printf("[%d]: %s ", i + 1, cli_argv[i]);
		// printf("\n");
		if (strcasecmp(cli_argv[0], "sleep") == 0) 
		{
			int sleep_time_in_sec = atoi(cli_argv[1]);
			WRITE_FORMAT_DEBUG("CLI: Sleep %d seconds...... ", sleep_time_in_sec);
			sleep(sleep_time_in_sec);
		}
		else
		{
// Execute the command
			WRITE_FORMAT_DEBUG("CLI[%d]: Try to execute the %s command...... ", multi_clis_line_index, cli_argv[0]);
			ret = handle_command(cli_argc, cli_argv);
			if (CHECK_SUCCESS(ret))
				WRITE_FORMAT_DEBUG("CLI[%d]: Execute the %s command...... DONE", multi_clis_line_index, cli_argv[0]);
			else if (CHECK_FAILURE(ret))
			{
				char rsp_buf[RSP_BUF_SIZE + 1];
				memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
				snprintf(rsp_buf, RSP_BUF_SIZE, "CLI[%d]: Error occurs while executing the %s command in the session: %s, due to: %s\n", multi_clis_line_index, cli_argv[0], session_tag, GetErrorDescription(ret));
// Show warning if error occurs while executing the command and then exit
				WRITE_ERROR(rsp_buf);
				snprintf(rsp_buf, RSP_BUF_SIZE, "ERROR[%d]  %s: %s\n", multi_clis_line_index, cli_argv[0], GetErrorDescription(ret));
				print_to_console(string(rsp_buf));
			}
			else if (CHECK_WARN(ret))
			{
				char rsp_buf[RSP_BUF_SIZE + 1];
				memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
				snprintf(rsp_buf, RSP_BUF_SIZE, "CLI[%d]: Warning occurs while executing the %s command in the session: %s, due to: %s\n", multi_clis_line_index, cli_argv[0], session_tag, GetErrorDescription(ret));
// Show warning if warn occurs while executing the command
				WRITE_WARN(rsp_buf);
				snprintf(rsp_buf, RSP_BUF_SIZE, "WARNING[%d]  %s: %s\n", multi_clis_line_index, cli_argv[0], GetErrorDescription(ret));
				print_to_console(string(rsp_buf));
			}
		}
		multi_clis_line_index++;

		free(cli_line);
		iter++;
	}
	return ret;
}

void InteractiveSession::multi_clis_thread_cleanup_handler(void* pvoid)
{
	InteractiveSession* pthis = (InteractiveSession*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->multi_clis_thread_cleanup_handler_internal();
}

void InteractiveSession::multi_clis_thread_cleanup_handler_internal()
{
	WRITE_INFO("Cleanup the resource in the multi clis thread......");
	if (multi_clis_filepath != NULL)
	{
		free(multi_clis_filepath);
		multi_clis_filepath = NULL;
	}
}

unsigned short InteractiveSession::print_to_console(const string& response)const
{
	const char* response_ptr = response.c_str();
	int response_size = response.size();
	int n;
	while (response_size > 0)
	{
		n = write(sock_fd, response_ptr, response_size);
		if (n < 0)
		{
			WRITE_FORMAT_ERROR("write() fails, due to: %s", strerror(errno));		
			return RET_FAILURE_SYSTEM_API;
		}
		else if(n < response_size)
		{
			response_ptr += n;
			response_size -= n;
		}
		else
			break;
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::print_prompt_to_console()const
{
	static string prompt(INTERACTIVE_PROMPT);
	static string config_prompt(INTERACTIVE_CONFIG_PROMPT);
	return print_to_console((is_config_mode ? config_prompt : prompt));
}

unsigned short InteractiveSession::print_search_rule_to_console()const
{
	print_to_console(string("\n# Search Rule #\n"));
	char buf[DEF_STRING_SIZE];
	if (event_search_rule.need_search_event_time)
	{
		tm search_event_time_begin = *localtime(&event_search_rule.search_event_time_begin);
		tm search_event_time_end = *localtime(&event_search_rule.search_event_time_end);
		// char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Time Range  %d/%02d/%02d_%02d:%02d:%02d -> %d/%02d/%02d_%02d:%02d:%02d\n", 
			search_event_time_begin.tm_year + 1900, 
			search_event_time_begin.tm_mon + 1, 
			search_event_time_begin.tm_mday, 
			search_event_time_begin.tm_hour, 
			search_event_time_begin.tm_min, 
			search_event_time_begin.tm_sec,
			search_event_time_end.tm_year + 1900, 
			search_event_time_end.tm_mon + 1, 
			search_event_time_end.tm_mday, 
			search_event_time_end.tm_hour, 
			search_event_time_end.tm_min, 
			search_event_time_end.tm_sec
		);
		print_to_console(string(buf));
	}
	if (event_search_rule.need_search_event_type)
	{
		// char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Type  %s\n", GetEventTypeDescription(event_search_rule.search_event_type));
		print_to_console(string(buf) + string("\n"));
	}
	if (event_search_rule.need_search_event_severity)
	{
		// char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Severity  %s\n", GetEventSeverityDescription(event_search_rule.search_event_severity));
		print_to_console(string(buf) + string("\n"));
	}
	if (event_search_rule.need_search_event_category)
	{
		// char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Category  %s\n", GetEventCategoryDescription(event_search_rule.search_event_category));
		print_to_console(string(buf) + string("\n"));
	}
	if (event_search_rule.need_search_event_description)
	{
		// char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Description  %s\n", event_search_rule.search_event_description.c_str());
		print_to_console(string(buf) + string("\n"));
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_command(int argc, char **argv)
{
	typedef unsigned short (InteractiveSession::*handle_command_func_ptr)(int argc, char**argv);
	static handle_command_func_ptr handle_command_func_array[] =
	{
		&InteractiveSession::handle_help_command,
		&InteractiveSession::handle_switch_config_mode_command,
		&InteractiveSession::handle_get_role_command,
		&InteractiveSession::handle_get_cluster_detail_command,
		&InteractiveSession::handle_get_system_info_command,
		&InteractiveSession::handle_search_event_command,
		&InteractiveSession::handle_list_search_rule_command,
		// &InteractiveSession::handle_get_node_system_info_command,
		&InteractiveSession::handle_get_configuration_setup_command,
		&InteractiveSession::handle_get_running_setup_command,
		&InteractiveSession::handle_start_system_monitor_command,
		&InteractiveSession::handle_stop_system_monitor_command,
		&InteractiveSession::handle_sync_folder_command,
		&InteractiveSession::handle_sync_file_command,
		&InteractiveSession::handle_remote_sync_folder_command,
		&InteractiveSession::handle_remote_sync_file_command,
		&InteractiveSession::handle_get_simulator_version_command,
		&InteractiveSession::handle_trasnfer_simulator_package_command,
		&InteractiveSession::handle_install_simulator_command,
		&InteractiveSession::handle_apply_fake_acspt_config_command,
		&InteractiveSession::handle_get_fake_acspt_config_value_command,
		&InteractiveSession::handle_apply_fake_usrept_config_command,
		&InteractiveSession::handle_start_fake_acspt_command,
		&InteractiveSession::handle_stop_fake_acspt_command,
		&InteractiveSession::handle_start_fake_usrept_command,
		&InteractiveSession::handle_stop_fake_usrept_command,
		&InteractiveSession::handle_get_fake_acspt_state_command,
		&InteractiveSession::handle_get_fake_acspt_detail_command,
		&InteractiveSession::handle_run_multi_clis_command,
		&InteractiveSession::handle_switch_leader_command,
		&InteractiveSession::handle_remove_follower_command,
		&InteractiveSession::handle_exit_command
	};
	// assert (iter != command_map.end() && "Unknown command");
	COMMAND_MAP::iterator iter = command_map.find(string(argv[0]));
	int command_type = (int)iter->second;
	return (this->*(handle_command_func_array[command_type]))(argc, argv);
}

unsigned short InteractiveSession::handle_help_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	string usage_string;
	usage_string += string("====================== Usage ======================\n");
	for (int i = 0; i < InteractiveSessionCommandSize; i++)
	{
		if (CHECK_AUTHORITY(i, authority_mask))
			usage_string += string("* ") + GET_COMMAND(i) + string("\n Description: ") + GET_DESCRIPTION(i) + string("\n");	
	}
	// usage_string += string("* help\n Description: The usage\n");
	// usage_string += string("* exit\n Description: Exit the session\n");
	// usage_string += string("* get_cluster_detail\n Description: Get the cluster detail info\n");
	// usage_string += string("* get_system_info\n Description: Get the system info\n Caution: Leader get the entire cluster system info. Follower only get the node system info\n");
	// if (is_leader)
	// {
	// 	// usage_string += string("* get_node_system_info\n Description: Get the system info of certain a node\n");
	// 	usage_string += string("  Param: Node ID/IP\n");
	// 	usage_string += string("    Format 1: Node ID: (ex. 1)\n");
	// 	usage_string += string("    Format 2: Node IP: (ex. 10.206.24.219)\n");
	// 	usage_string += string("* start_system_monitor\n Description: Start system monitor\n");
	// 	usage_string += string("* stop_system_monitor\n Description: Stop system monitor\n");
	// 	if (is_root)
	// 	{
	// 		usage_string += string("* get_simulator_version\n Description: Get simulator version\n");
	// 		usage_string += string("* transfer_simulator_package\n Description: Leader transfers the simulator package to each follower\n");
	// 		usage_string += string("  Param: Simulator package filepath (ex. /home/super/simulator.tar.xz)\n");
	// 		usage_string += string("* install_simulator\n Description: Install simulator\n");
	// 		usage_string += string("  Param: Simulator package filepath (ex. /home/super/simulator.tar.xz)\n");
	// 		usage_string += string("* apply_fake_acspt_config\n Description: Apply new config to all fake acepts\n");
	// 		usage_string += string("  Param: Fake acspt config filepath (ex. /home/super/new_fake_acspt_sim.cfg)\n");
	// 		usage_string += string("* get_fake_acspt_config_value\n Description: Get the config value from fake acspts config file\n");
	// 		usage_string += string("  Param: Acspt config list string (ex. CONFIG1,CONFIG2,CONFIG3)\n");
	// 		usage_string += string("* apply_fake_usrept_config\n Description: Apply new config to all fake usrepts\n");
	// 		usage_string += string("  Param: Fake usrept config filepath (ex. /home/super/new_fake_usrept.cfg)\n");
	// 		usage_string += string("* start_fake_acspt\n Description: Start fake acepts\n");
	// 		usage_string += string("* stop_fake_acspt\n Description: Stop fake acepts\n");
	// 		usage_string += string("* start_fake_usrept\n Description: Start fake usrepts\n");
	// 		usage_string += string("* stop_fake_usrept\n Description: Stop fake usrepts\n");
	// 		usage_string += string("* get_fake_acspt_state\n Description: Get the states of all fake acepts\n");
	// 		usage_string += string("* get_fake_acspt_detail\n Description: Get the details of all fake acepts\n");
	// 		usage_string += string("* run_multi_clis\n Description: Run multiple CLI commands at a time\n");
	// 		usage_string += string("  Param: The filepath of defining CLI commands (ex. /home/super/cli_commands)\n");
	// 	}
	// }
	usage_string += string("===================================================\n\n");

	ret = print_to_console(usage_string);
	return ret;
}

unsigned short InteractiveSession::handle_switch_config_mode_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	is_config_mode = true;
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_get_role_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	string role_string;
	if (is_leader)
	{
		role_string = "Leader";
		if (is_root)
			role_string += string("(Root)");
	}
	else
		role_string = "Follower";

	role_string += string("\n\n");
	print_to_console(role_string);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_get_cluster_detail_command(int argc, char **argv)
{
	static const char* CLUSTER_DETAIL_TITLE = "\n====================== Cluster Info ======================\n";
	static const char* NODE_TYPE_LIST[] = {"Leader","Follower"};
	assert(manager != NULL && "manager should NOT be NULL");

	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	// int node_id;
// Get the data
	ClusterDetailParam cluster_detail_param;
    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
	if (CHECK_FAILURE(ret))
		return ret;
	// ClusterMap cluster_map;
	// ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
	// if (CHECK_FAILURE(ret))
	// 	return ret;
// Print data in cosole
	string cluster_detail_string(CLUSTER_DETAIL_TITLE);
	ClusterMap::const_iterator iter = cluster_detail_param.cluster_map.begin();
	char cluster_node_token[RSP_BUF_VERY_SHORT_SIZE];
	while(iter != cluster_detail_param.cluster_map.end())
	{
		const ClusterNode& cluster_node = *iter;
		// snprintf(cluster_node_token, RSP_BUF_VERY_SHORT_SIZE, "%s", cluster_node.node_token.c_str());
		strcpy(cluster_node_token, cluster_node.node_token.c_str());
		// strcpy(cluster_node_token, "10.206.24.219");
		int node_type_index = (strcmp(cluster_node_token, cluster_detail_param.cluster_token) == 0 ? LEADER : FOLLOWER);
		bool is_local_node = (cluster_detail_param.node_id == cluster_node.node_id ? true : false);
		char buf[RSP_BUF_SIZE];
		snprintf(buf, RSP_BUF_SIZE, (is_local_node ? "%d %s %s *\n":  "%d %s %s\n"), cluster_node.node_id, cluster_node_token, NODE_TYPE_LIST[node_type_index]);
		++iter;
		cluster_detail_string += string(buf);
	}

	ret = print_to_console(cluster_detail_string);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_get_system_info_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	NodeType node_type = NONE;
    ret = manager->get(PARAM_NODE_TYPE, (void*)&node_type);
 	if (CHECK_FAILURE(ret))
		return ret;	
// Get the data
	switch (node_type)
	{
		case LEADER:
		{
			ClusterSystemInfoParam cluster_system_info_param; // = new SimulatorVersionParam(DEF_VERY_SHORT_STRING_SIZE);
			// if (simulator_version_param  == NULL)
			// 	throw bad_alloc();
		    ret = manager->get(PARAM_SYSTEM_INFO, (void*)&cluster_system_info_param);
		 	if (CHECK_FAILURE(ret))
				return ret;
		    // SAFE_RELEASE(notify_cfg)
			// ClusterDetailParam cluster_detail_param;
		 //    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
			// if (CHECK_FAILURE(ret))
			// 	return ret;
			// ClusterMap& cluster_map = cluster_detail_param.cluster_map;
			ClusterMap cluster_map;
		    ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
			if (CHECK_FAILURE(ret))
				return ret;

			map<int, string>& cluster_data_map = cluster_system_info_param.cluster_data_map;
	// Print data in cosole
			string system_info_string("*** System Info ***\n");
			map<int, string>::iterator iter = cluster_data_map.begin();
			while (iter != cluster_data_map.end())
			{
				// simulator_version_string += string(simulator_version_param->simulator_version);
				// simulator_version_string += string("\n");
				int node_id = (int)iter->first;
				string node_token;
				ret = cluster_map.get_node_token(node_id, node_token);
				if (CHECK_FAILURE(ret))
					return ret;
				char buf[DEF_STRING_SIZE];
				snprintf(buf, DEF_STRING_SIZE, "%s\n", node_token.c_str());
				system_info_string += string(buf);
				system_info_string += ((string)iter->second);
				system_info_string += string("\n**********\n");
				++iter;
			}
			system_info_string += string("\n");
			ret = print_to_console(system_info_string);
		}
		break;
		case FOLLOWER:
		{
			SystemInfoParam system_info_param;
		    ret = manager->get(PARAM_SYSTEM_INFO, (void*)&system_info_param);
		 	if (CHECK_FAILURE(ret))
				return ret;
			string system_info_string("*** System Info (Local) ***\n");
			system_info_string += system_info_param.system_info;
			system_info_string += string("\n**********\n");
			ret = print_to_console(system_info_string);
		}
		break;
		default:
		{
			WRITE_FORMAT_ERROR("Unknow node type: %d", node_type);
			return RET_FAILURE_INCORRECT_VALUE;
		}
		break;
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_search_event_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	list<EventEntry*> event_list;
	list<string> event_line_list;
	// event_search_rule.need_search_event_time = true;
	// event_search_rule.search_event_time_end = time(0);
	// event_search_rule.search_event_time_begin = event_search_rule.search_event_time_end - 86400;
	// printf("Begin: %d, End: %d\n", event_search_rule.search_event_time_begin, event_search_rule.search_event_time_end);
	// event_search_rule.need_search_event_type = true;
	// event_search_rule.search_event_type = EVENT_TELENT_CONSOLE;
	// event_search_rule.need_search_event_severity = true;
	// event_search_rule.search_event_severity = EVENT_SEVERITY_CRITICAL;
	// event_search_rule.need_search_event_category = true;
	// event_search_rule.search_event_category = EVENT_CATEGORY_CONSOLE;
	bool enable_search_rule = ENABLE_SEARCH_RULE(event_search_rule);
	if (enable_search_rule)
		print_search_rule_to_console();
	ret = event_recorder->read(&event_list, &event_line_list, (enable_search_rule ? &event_search_rule : NULL));
	if (CHECK_SUCCESS(ret))
	{
		// list<EventEntry*>::iterator iter_event = event_list.begin();
		// int event_line_size = event_line_list.size();
		print_to_console(string("\n"));
		list<string>::iterator iter_event_line = event_line_list.begin();
		int event_count = 0;
		while (iter_event_line != event_line_list.end())
		{
			// EventEntry* event_entry = (PEVENT_ENTRY)*iter_event;
			string event_line = (string)*iter_event_line + string("\n");
			print_to_console(event_line);
			// iter_event++;
			iter_event_line++;
			event_count++;
		}
		char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "\n ***  %d event(s) found  ***\n", event_count);
		print_to_console(string(buf) + string("\n"));
	}
	list<EventEntry*>::iterator iter_clean = event_list.begin();
	while (iter_clean != event_list.end())
	{
		PEVENT_ENTRY event_entry = (PEVENT_ENTRY)*iter_clean;
		if (event_entry != NULL)
		{
			delete event_entry;
			event_entry = NULL;
		}
		iter_clean++;
	}
	event_list.clear();
	return ret;
}

unsigned short InteractiveSession::handle_list_search_rule_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	bool enable_search_rule = ENABLE_SEARCH_RULE(event_search_rule);
	if (enable_search_rule)
		print_search_rule_to_console();
	else
		print_to_console(string("\n*** No search rule ***\n\n"));
	return ret;
}
// unsigned short InteractiveSession::handle_get_node_system_info_command(int argc, char **argv)
// {
// 	static const char* NODE_SYSTEM_INFO_TITLE = "\n====================== Node System Info ======================\n";
// 	assert(manager != NULL && "manager should NOT be NULL");

// 	if (argc != 2)
// 	{
// 		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
// 		print_to_console(incorrect_command_phrases);
// 		return RET_WARN_INTERACTIVE_COMMAND;
// 	}

// 	unsigned short ret = RET_SUCCESS;
// 	// int node_id;
// // Get the data
// 	SystemInfoParam system_info_param;
// 	system_info_param.session_id = session_id;
// 	snprintf(system_info_param.node_token_buf, VERY_SHORT_STRING_SIZE, "%s", argv[1]);
//     ret = manager->get(PARAM_SYSTEM_INFO, (void*)&system_info_param);
// 	if (CHECK_FAILURE(ret))
// 		return ret;
// // Print data in cosole
// 	string node_system_info_string(NODE_SYSTEM_INFO_TITLE);
// 	char cluster_node[RSP_BUF_VERY_SHORT_SIZE];
// 	snprintf(cluster_node,  RSP_BUF_VERY_SHORT_SIZE, "Node %s\n", system_info_param.node_token_buf);
// 	node_system_info_string += string(cluster_node);
// 	node_system_info_string += system_info_param.system_info;
// 	node_system_info_string += string("\n");
// 	ret = print_to_console(node_system_info_string);
// 	return RET_SUCCESS;
// }

unsigned short InteractiveSession::handle_get_configuration_setup_command(int argc, char **argv)
{
	unsigned short ret = RET_SUCCESS;
	string configuration_setup_string;
	ret = manager->get(PARAM_CONFIGURATION_SETUP, (void*)&configuration_setup_string);
	if (CHECK_FAILURE(ret))
		return ret;
	print_to_console(configuration_setup_string);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_get_running_setup_command(int argc, char **argv)
{
	unsigned short ret = RET_SUCCESS;
	string running_setup_string;
	ret = manager->get(PARAM_RUNNING_SETUP, (void*)&running_setup_string);
	if (CHECK_FAILURE(ret))
		return ret;
	print_to_console(running_setup_string);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_start_system_monitor_command(int argc, char **argv)
{
	static string system_monitor_string("*** System Monitor ***\n While Monitoring the system, the CLI commands will NOT take effect\n It's required to stop system monitor first\n Type: quit to stop\n**********************\n\n");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	if (system_monitor)
	{
		WRITE_ERROR("System monitor is enabled");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	assert(monitor_system_timer_thread == NULL && "monitor_system_timer_thread should be NULL");
	unsigned short ret = RET_SUCCESS;
	monitor_system_timer_thread = new MonitorSystemTimerThread(this, manager);
	if (monitor_system_timer_thread == NULL)
		throw bad_alloc();
	int system_monitor_period;
    ret = manager->get(PARAM_SYSTEM_MONITOR_PERIOD, (void*)&system_monitor_period);
 	if (CHECK_FAILURE(ret))
		return ret;	
	if (system_monitor_period != 0)
		monitor_system_timer_thread->set_period(system_monitor_period);
	ret = monitor_system_timer_thread->initialize();
	if (CHECK_FAILURE(ret))
	{
		delete monitor_system_timer_thread;
		monitor_system_timer_thread = NULL;
		return ret;
	}
	system_monitor = true;
	print_to_console(system_monitor_string);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_stop_system_monitor_command(int argc, char **argv)
{
	static string system_monitor_string("*** System Monitor ***\n STOP\n**********************\n\n");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	if (!system_monitor)
	{
		WRITE_ERROR("System monitor is disabled");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	assert(monitor_system_timer_thread != NULL && "monitor_system_timer_thread should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	ret = monitor_system_timer_thread->deinitialize();
	delete monitor_system_timer_thread;
	monitor_system_timer_thread = NULL;
	if (CHECK_FAILURE(ret))
		return ret;
	system_monitor = false;
	ret = print_to_console(system_monitor_string);
	return RET_SUCCESS;	
}

unsigned short InteractiveSession::handle_sync_folder_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");

	unsigned short ret = RET_SUCCESS;
	// char folderpath[DEF_LONG_STRING_SIZE]; 
	string sync_folderpath;
	if (argc == 1)
	{
		if (is_leader)
		{
			WRITE_DEBUG("Use the folderpath in config file to synchorinize......");
			ret = manager->get(PARAM_CONFIGURATION_VALUE, (void*)CONF_FIELD_SYNC_FOLDERPATH, (void*)&sync_folderpath);
			if (CHECK_FAILURE(ret))
				return ret;
			if (strchr(sync_folderpath.c_str(), '~') != NULL)
			{
				ret = get_complete_sync_folderpath(sync_folderpath);
				if (CHECK_FAILURE(ret))
					return ret;
			}
		}
		else
		{
			WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
			print_to_console(incomplete_command_phrases);
			return RET_WARN_INTERACTIVE_COMMAND;
		}
	}
	else if (argc == 2)
	{
		sync_folderpath = string(argv[1]);
	}
	else
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;		
	}
	WRITE_FORMAT_DEBUG("Try to synchorinize the folder: %s", sync_folderpath.c_str());
	print_to_console(string(" folder: ") + sync_folderpath + string("  ***\n"));
	list<string> full_filepath_in_folder_list;
	get_filepath_in_folder_recursive(full_filepath_in_folder_list, sync_folderpath);
	list<string>::iterator iter = full_filepath_in_folder_list.begin();
	while (iter != full_filepath_in_folder_list.end())
	{
		string full_filepath = (string)(*iter);
		// printf("* %s\n", full_filepath.c_str());
		WRITE_FORMAT_DEBUG("Synchorinize the file: %s", full_filepath.c_str());
		print_to_console(string(" *** file synchorinization: ") + full_filepath + string("  ***\n"));
		ClusterFileTransferParam cluster_file_transfer_param;
	// Start to transfer the file
		cluster_file_transfer_param.session_id = session_id;
	    ret = manager->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)full_filepath.c_str());
	    usleep(100000);
	    // printf("[PARAM_FILE_TRANSFER], ret description: %s\n", GetErrorDescription(ret));
	 	if (CHECK_FAILURE(ret))
			return ret;
		iter++;
	}
	WRITE_EVT_RECORDER(SyncDataEventCfg, sync_folderpath.c_str(), (is_leader ? LEADER : FOLLOWER), node_token, 1);
	return ret;	
}

unsigned short InteractiveSession::handle_sync_file_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	char filepath[DEF_LONG_STRING_SIZE]; 
	const char* argv1_tmp = (const char*)argv[1];
	if (strchr(argv1_tmp, '/') == NULL)
	{
		if (is_leader)
		{
			string sync_folderpath;
			ret = manager->get(PARAM_CONFIGURATION_VALUE, (void*)CONF_FIELD_SYNC_FOLDERPATH, (void*)&sync_folderpath);
			if (CHECK_FAILURE(ret))
				return ret;
			if (strchr(sync_folderpath.c_str(), '~') != NULL)
			{
				ret = get_complete_sync_folderpath(sync_folderpath);
				if (CHECK_FAILURE(ret))
					return ret;
			}
			else
				snprintf(filepath, DEF_LONG_STRING_SIZE, "%s/%s", sync_folderpath.c_str(), argv1_tmp);
		}
		else
		{
			WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
			print_to_console(incomplete_command_phrases);
			return RET_WARN_INTERACTIVE_COMMAND;
		}			
	}
	else
		strcpy(filepath, argv1_tmp);

	WRITE_FORMAT_DEBUG("Try to synchorinize the file: %s", filepath);
	if (!check_file_exist(filepath))
	{
		WRITE_FORMAT_WARN("The file[%s] being synchronized does NOT exist", filepath);
		return RET_FAILURE_NOT_FOUND;
	}

	print_to_console(string(" *** file synchorinization  ***\n"));
	ClusterFileTransferParam cluster_file_transfer_param;
// Start to transfer the file
	cluster_file_transfer_param.session_id = session_id;
    ret = manager->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)filepath);
    // printf("[PARAM_FILE_TRANSFER], ret description: %s\n", GetErrorDescription(ret));
	WRITE_EVT_RECORDER(SyncDataEventCfg, filepath, (is_leader ? LEADER : FOLLOWER), node_token, 0);
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_remote_sync_folder_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	char buf[DEF_LONG_STRING_SIZE];
	int follower_node_id = atoi(argv[1]);
	const char* remote_folderpath = (char*)argv[2];
	char* follower_node_token;
	ret = manager->get(PARAM_NODE_TOKEN_LOOKUP, (void*)&follower_node_id, (void*)&follower_node_token);
	if (CHECK_FAILURE(ret))
	{
		if (ret == RET_FAILURE_NOT_FOUND)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The Follower ID[%d] does NOT exist", follower_node_id);
			WRITE_WARN(buf);
			print_to_console(string(buf) + string("\n"));
			return RET_WARN_INTERACTIVE_COMMAND;
		}
		else
		{
			WRITE_FORMAT_ERROR("Error occur while looking-up the token of Follower[%s], due to: %s", follower_node_id, GetErrorDescription(ret));
			return ret;
		}
	}
	WRITE_FORMAT_DEBUG("Trigger remote sync folder[%s] in Follower[%s]", remote_folderpath, follower_node_token);
	ret = manager->set(PARAM_REMOTE_SYNC_FOLDER, (void*)&follower_node_id, (void*)remote_folderpath);
	manager->set(PARAM_REMOTE_SYNC_FILE_FLAG_OFF);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_DEBUG("Error occur while triggering remote sync folder[%s] in Follower[%s], due to: %s", remote_folderpath, follower_node_token, GetErrorDescription(ret));
		// WRITE_EVT_RECORDER(SyncDataEventCfg, filepath, (is_leader ? LEADER : FOLLOWER), node_token, 0);
		return ret;
	}
	unsigned short remote_sync_file_ret;
	manager->get(PARAM_REMOTE_SYNC_FILE_RETURN_VALUE, (void*)&remote_sync_file_ret);
	WRITE_FORMAT_DEBUG("Return value of synchorizing the folder[%s] from Follower[%s]: %d, %s", remote_folderpath, follower_node_token, remote_sync_file_ret, GetErrorDescription(remote_sync_file_ret));
	if (CHECK_FAILURE(remote_sync_file_ret))
	{
		if (remote_sync_file_ret == RET_WARN_REMOTE_RESOURCE_BUSY)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The resource of transfering a folder[%s] is busy in Follower[%s]", remote_folderpath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf) + string("\n"));
			ret = RET_WARN_REMOTE_RESOURCE_BUSY;
		}
		else if (remote_sync_file_ret == RET_FAILURE_NOT_FOUND)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The folder[%s] does NOT exist in Follower[%s]", remote_folderpath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf));
			ret = RET_WARN_REMOTE_FILE_TRANSFER_FAILURE;
		}
		else
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "Error occurs while transfering a folder[%s] is busy in Follower[%s]", remote_folderpath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf));
			ret = RET_WARN_REMOTE_FILE_TRANSFER_FAILURE;
		}
	}
	else
	{
		WRITE_EVT_RECORDER(RemoteSyncDataEventCfg, remote_folderpath, follower_node_token);
		snprintf(buf, DEF_LONG_STRING_SIZE, "Remote transfer a file[%s] in Follower[%s] successfully\n", remote_folderpath, follower_node_token);
		WRITE_DEBUG(buf);
		print_to_console(string(buf));
	}
		
	return ret;	
}

unsigned short InteractiveSession::handle_remote_sync_file_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	char buf[DEF_LONG_STRING_SIZE];
	int follower_node_id = atoi(argv[1]);
	const char* remote_filepath = (char*)argv[2];
	char* follower_node_token;
	ret = manager->get(PARAM_NODE_TOKEN_LOOKUP, (void*)&follower_node_id, (void*)&follower_node_token);
	if (CHECK_FAILURE(ret))
	{
		if (ret == RET_FAILURE_NOT_FOUND)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The Follower ID[%d] does NOT exist", follower_node_id);
			WRITE_WARN(buf);
			print_to_console(string(buf) + string("\n"));
			return RET_WARN_INTERACTIVE_COMMAND;
		}
		else
		{
			WRITE_FORMAT_ERROR("Error occur while looking-up the token of Follower[%s], due to: %s", follower_node_id, GetErrorDescription(ret));
			return ret;
		}
	}
	WRITE_FORMAT_DEBUG("Trigger remote sync file[%s] in Follower[%s]", remote_filepath, follower_node_token);
	ret = manager->set(PARAM_REMOTE_SYNC_FILE, (void*)&follower_node_id, (void*)remote_filepath);
	manager->set(PARAM_REMOTE_SYNC_FILE_FLAG_OFF);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_DEBUG("Error occur while triggering remote sync file[%s] in Follower[%s], due to: %s", remote_filepath, follower_node_token, GetErrorDescription(ret));
		// WRITE_EVT_RECORDER(SyncDataEventCfg, filepath, (is_leader ? LEADER : FOLLOWER), node_token, 0);
		return ret;
	}
	unsigned short remote_sync_file_ret;
	manager->get(PARAM_REMOTE_SYNC_FILE_RETURN_VALUE, (void*)&remote_sync_file_ret);
	WRITE_FORMAT_DEBUG("Return value of synchorizing the file[%s] from Follower[%s]: %d, %s", remote_filepath, follower_node_token, remote_sync_file_ret, GetErrorDescription(remote_sync_file_ret));
	if (CHECK_FAILURE(remote_sync_file_ret))
	{
		if (remote_sync_file_ret == RET_WARN_REMOTE_RESOURCE_BUSY)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The resource of transfering a file[%s] is busy in Follower[%s]", remote_filepath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf) + string("\n"));
			ret = RET_WARN_REMOTE_RESOURCE_BUSY;
		}
		else if (remote_sync_file_ret == RET_FAILURE_NOT_FOUND)
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "The file[%s] does NOT exist in Follower[%s]", remote_filepath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf));
			ret = RET_WARN_REMOTE_FILE_TRANSFER_FAILURE;
		}
		else
		{
			snprintf(buf, DEF_LONG_STRING_SIZE, "Error occurs while transfering a file[%s] is busy in Follower[%s]", remote_filepath, follower_node_token);
			WRITE_WARN(buf);
			print_to_console(string(buf));
			ret = RET_WARN_REMOTE_FILE_TRANSFER_FAILURE;
		}
	}
	else
	{
		WRITE_EVT_RECORDER(RemoteSyncDataEventCfg, remote_filepath, follower_node_token);
		snprintf(buf, DEF_LONG_STRING_SIZE, "Remote transfer a file[%s] in Follower[%s] successfully\n", remote_filepath, follower_node_token);
		WRITE_DEBUG(buf);
		print_to_console(string(buf));
	}
		
	return ret;
}

unsigned short InteractiveSession::handle_get_simulator_version_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
// Get the data
	ClusterSimulatorVersionParam cluster_simulator_version_param; // = new SimulatorVersionParam(DEF_VERY_SHORT_STRING_SIZE);
	// if (simulator_version_param  == NULL)
	// 	throw bad_alloc();
    ret = manager->get(PARAM_SIMULATOR_VERSION, (void*)&cluster_simulator_version_param);
 	if (CHECK_FAILURE(ret))
		return ret;
    // SAFE_RELEASE(notify_cfg)
	if (CHECK_SUCCESS(ret))
	{
		// ClusterDetailParam cluster_detail_param;
	 //    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		// if (CHECK_FAILURE(ret))
		// 	return ret;
		// ClusterMap& cluster_map = cluster_detail_param.cluster_map;
		ClusterMap cluster_map;
	    ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
		if (CHECK_FAILURE(ret))
			return ret;

		char buf[DEF_STRING_SIZE];
		map<int, string>& cluster_simulator_version_map = cluster_simulator_version_param.cluster_data_map;
// Print data in cosole
		string simulator_version_string("simulator version\n");
		map<int, string>::iterator iter = cluster_simulator_version_map.begin();
		while (iter != cluster_simulator_version_map.end())
		{
			// simulator_version_string += string(simulator_version_param->simulator_version);
			// simulator_version_string += string("\n");
			int node_id = (int)iter->first;
			string node_token;
			ret = cluster_map.get_node_token(node_id, node_token);
			if (CHECK_FAILURE(ret))
				return ret;
			snprintf(buf, DEF_STRING_SIZE, "%s  %s\n", node_token.c_str(), ((string)iter->second).c_str());
			simulator_version_string += string(buf);
			++iter;
		}
		simulator_version_string += string("\n");
		ret = print_to_console(simulator_version_string);
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_trasnfer_simulator_package_command(int argc, char **argv)
{
	// assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	char* filepath = (char*)argv[1];
    char *extension = strchr(filepath, '.');  // Find the last dot in the filename
    if (strcmp(extension, ".tar.xz") != 0)
    {
		WRITE_FORMAT_WARN("WANRING!! Incorrect extension filename: %s", filepath);
		print_to_console(string("The extension should be .tar.xz"));
		return RET_WARN_INTERACTIVE_COMMAND;
    }
// 	if (!check_file_exist(filepath))
// 	{
// 		WRITE_FORMAT_WARN("The simulator package file[%s] does NOT exist", filepath);
// 		return RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND;
// 	}

// 	ClusterFileTransferParam cluster_file_transfer_param;
// // Start to transfer simulator package
// 	unsigned short ret = RET_SUCCESS;
// 	cluster_file_transfer_param.session_id = session_id;
//     ret = manager->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)filepath);
//  	if (CHECK_FAILURE(ret))
// 		return ret;
//     // SAFE_RELEASE(notify_cfg)
// // Wait for transferring done...
// 	// ClusterDetailParam cluster_detail_param;
// 	// ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
// 	// if (CHECK_FAILURE(ret))
// 	// 	return ret;
// 	// ClusterMap& cluster_map = cluster_detail_param.cluster_map;
// 	ClusterMap cluster_map;
// 	ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
// 	if (CHECK_FAILURE(ret))
// 		return ret;

// 	char buf[DEF_STRING_SIZE];
// 	map<int, string>& cluster_file_transfer_map = cluster_file_transfer_param.cluster_data_map;
// // Print data in cosole
// 	string file_transfer_string("file transfer\n");
// 	map<int, string>::iterator iter = cluster_file_transfer_map.begin();
// 	while (iter != cluster_file_transfer_map.end())
// 	{
// 		int node_id = (int)iter->first;
// 		string node_token;
// 		ret = cluster_map.get_node_token(node_id, node_token);
// 		if (CHECK_FAILURE(ret))
// 			return ret;
// 		snprintf(buf, DEF_STRING_SIZE, "%s  %s\n", node_token.c_str(), ((string)iter->second).c_str());
// 		file_transfer_string += string(buf);
// 		++iter;
// 	}
// 	file_transfer_string += string("\n");
// 	ret = print_to_console(file_transfer_string);
// 	return RET_SUCCESS;
	return handle_sync_file_command(argc, argv);
}

unsigned short InteractiveSession::handle_install_simulator_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Install Simulator..."));
// Notify the parent
	size_t notify_param_size = strlen(argv[1]) + 1;
	PNOTIFY_CFG notify_cfg = new NotifySimulatorInstallCfg((void*)argv[1], notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	unsigned short ret = observer->notify(NOTIFY_INSTALL_SIMULATOR, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_apply_fake_acspt_config_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Install Simulator..."));
	const char* new_fake_acspt_config_filepath = (const char*)argv[1];
	unsigned short ret = RET_SUCCESS;
// Read the new config
	list<string> new_config_line_list;
	ret = read_file_lines_ex(new_config_line_list, new_fake_acspt_config_filepath);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the new config file[%s], due to: %s", new_fake_acspt_config_filepath, GetErrorDescription(ret));
		return ret;
	}
// Serialize the new fake acspt config
	string new_config_line_list_str;
	list<string>::iterator iter = new_config_line_list.begin();
	while (iter != new_config_line_list.end())
	{
		string new_config_line = (string)*iter;
		if (new_config_line_list_str.length() != 0)
			new_config_line_list_str += string(",");
		new_config_line_list_str += new_config_line;
		iter++;
	}

// Notify the parent
	size_t notify_param_size = strlen(new_config_line_list_str.c_str()) + 1;
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptConfigApplyCfg((void*)new_config_line_list_str.c_str(), notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	ret = observer->notify(NOTIFY_APPLY_FAKE_ACSPT_CONFIG, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_get_fake_acspt_config_value_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Install Simulator..."));
	unsigned short ret = RET_SUCCESS;

	FakeAcsptConfigValueParam fake_acspt_config_value_param;
// Read the new config
	list<string> config_list;
	char* config_list_str = strdup(argv[1]);
	char* config_list_str_tmp = config_list_str;
// De-serialize the new fake acspt config
	char* rest_config_list_str = NULL;
	char* config_line;
	while ((config_line = strtok_r(config_list_str, ",", &rest_config_list_str)) != NULL)
	{
		string config_line_str(config_line);
		fake_acspt_config_value_param.config_list.push_back(config_line_str);
		if (config_list_str != NULL)
			config_list_str = NULL;
	}
	free(config_list_str_tmp);
	config_list_str_tmp = NULL;
// Get the data
    ret = manager->get(PARAM_FAKE_ACSPT_CONFIG_VALUE, (void*)&fake_acspt_config_value_param);
 	if (CHECK_FAILURE(ret))
		return ret;
	const list<string>& config_line_list = fake_acspt_config_value_param.config_line_list;
	list<string>::const_iterator iter = config_line_list.begin();
	string fake_acspt_config_value_string("*** Fake Acspt Config Value ***\n");
	while(iter != config_line_list.end())
	{
		string config_line = (string)*iter;
		fake_acspt_config_value_string += config_line;
		fake_acspt_config_value_string += string("\n");
		iter++;	
	}
	ret = print_to_console(fake_acspt_config_value_string);

	return ret;
}

unsigned short InteractiveSession::handle_apply_fake_usrept_config_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Install Simulator..."));
	const char* new_fake_usrept_config_filepath = (const char*)argv[1];
	unsigned short ret = RET_SUCCESS;
// Read the new config
	list<string> new_config_line_list;
	ret = read_file_lines_ex(new_config_line_list, new_fake_usrept_config_filepath);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to read the new config file[%s], due to: %s", new_fake_usrept_config_filepath, GetErrorDescription(ret));
		return ret;
	}
// Serialize the new fake acspt config
	string new_config_line_list_str;
	list<string>::iterator iter = new_config_line_list.begin();
	while (iter != new_config_line_list.end())
	{
		string new_config_line = (string)*iter;
		if (new_config_line_list_str.length() != 0)
			new_config_line_list_str += string(",");
		new_config_line_list_str += new_config_line;
		iter++;
	}

// Notify the parent
	size_t notify_param_size = strlen(new_config_line_list_str.c_str()) + 1;
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptConfigApplyCfg((void*)new_config_line_list_str.c_str(), notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	ret = observer->notify(NOTIFY_APPLY_FAKE_USREPT_CONFIG, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_start_fake_acspt_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Notify the parent
	FakeAcsptControlType fake_acspt_control_type = FAKE_ACSPT_START;
	size_t notify_param_size = sizeof(FakeAcsptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	unsigned short ret = observer->notify(NOTIFY_CONTROL_FAKE_ACSPT, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_stop_fake_acspt_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Stop FakeAcspts..."));
// Notify the parent
	FakeAcsptControlType fake_acspt_control_type = FAKE_ACSPT_STOP;
	size_t notify_param_size = sizeof(FakeAcsptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	unsigned short ret = observer->notify(NOTIFY_CONTROL_FAKE_ACSPT, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_start_fake_usrept_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Start FakeAcspts..."));
// Notify the parent
	FakeUsreptControlType fake_usrept_control_type = FAKE_USREPT_START;
	size_t notify_param_size = sizeof(FakeUsreptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptControlCfg((void*)&fake_usrept_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	unsigned short ret = observer->notify(NOTIFY_CONTROL_FAKE_USREPT, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_stop_fake_usrept_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

// Send message to the user
	// print_to_console(string("Stop FakeAcspts..."));
// Notify the parent
	FakeUsreptControlType fake_usrept_control_type = FAKE_USREPT_STOP;
	size_t notify_param_size = sizeof(FakeUsreptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptControlCfg((void*)&fake_usrept_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Synchronous event
	unsigned short ret = observer->notify(NOTIFY_CONTROL_FAKE_USREPT, notify_cfg);
    SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short InteractiveSession::handle_get_fake_acspt_state_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
// Get the data
	ClusterFakeAcsptStateParam cluster_fake_acspt_state_param;
    ret = manager->get(PARAM_FAKE_ACSPT_STATE, (void*)&cluster_fake_acspt_state_param);
 	if (CHECK_FAILURE(ret))
		return ret;
    // SAFE_RELEASE(notify_cfg)
	if (CHECK_SUCCESS(ret))
	{
		// ClusterDetailParam cluster_detail_param;
	 //    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		// if (CHECK_FAILURE(ret))
		// 	return ret;
		// ClusterMap& cluster_map = cluster_detail_param.cluster_map;
		ClusterMap cluster_map;
	    ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
		if (CHECK_FAILURE(ret))
			return ret;

		char buf[DEF_VERY_LONG_STRING_SIZE];
		map<int, string>& cluster_fake_acspt_state_map = cluster_fake_acspt_state_param.cluster_data_map;
// Print data in cosole
		string fake_acspt_state_string("*** Fake Acspt State ***\n");
		map<int, string>::iterator iter = cluster_fake_acspt_state_map.begin();
		while (iter != cluster_fake_acspt_state_map.end())
		{
			// simulator_version_string += string(simulator_version_param->simulator_version);
			// simulator_version_string += string("\n");
			int node_id = (int)iter->first;
			string node_token;
			ret = cluster_map.get_node_token(node_id, node_token);
			if (CHECK_FAILURE(ret))
				return ret;
			snprintf(buf, DEF_VERY_LONG_STRING_SIZE, "%s  %s\n", node_token.c_str(), ((string)iter->second).c_str());
			fake_acspt_state_string += string(buf);
			++iter;
		}
		fake_acspt_state_string += string("\n");
		ret = print_to_console(fake_acspt_state_string);
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_get_fake_acspt_detail_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
// Get the data
	ClusterFakeAcsptDetailParam cluster_fake_acspt_detail_param;
    ret = manager->get(PARAM_FAKE_ACSPT_DETAIL, (void*)&cluster_fake_acspt_detail_param);
 	if (CHECK_FAILURE(ret))
		return ret;
    // SAFE_RELEASE(notify_cfg)
	if (CHECK_SUCCESS(ret))
	{
		// ClusterDetailParam cluster_detail_param;
	 //    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		// if (CHECK_FAILURE(ret))
		// 	return ret;
		// ClusterMap& cluster_map = cluster_detail_param.cluster_map;
		ClusterMap cluster_map;
	    ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
		if (CHECK_FAILURE(ret))
			return ret;

		char buf[DEF_VERY_SHORT_STRING_SIZE];
		map<int, string>& cluster_fake_acspt_detail_map = cluster_fake_acspt_detail_param.cluster_data_map;
// Print data in cosole
		string fake_acspt_detail_string("*** Fake Acspt Detail ***\n");
		map<int, string>::iterator iter = cluster_fake_acspt_detail_map.begin();
		string newline_str("\n");
		while (iter != cluster_fake_acspt_detail_map.end())
		{
			int node_id = (int)iter->first;
			string node_token;
			ret = cluster_map.get_node_token(node_id, node_token);
			if (CHECK_FAILURE(ret))
				return ret;
			// snprintf(buf, DEF_VERY_SHORT_STRING_SIZE, "%s  %s\n", node_token.c_str(), ((string)iter->second).c_str());
			snprintf(buf, DEF_VERY_SHORT_STRING_SIZE, "%s  ", node_token.c_str());
			fake_acspt_detail_string += (string(buf) + newline_str + (string)iter->second);
			++iter;
		}
		fake_acspt_detail_string += newline_str;
		ret = print_to_console(fake_acspt_detail_string);
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_run_multi_clis_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	if (multi_clis_tid != 0)
	{

		int kill_ret = pthread_kill(multi_clis_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of running multiple CLIs did NOT exist......");
			multi_clis_tid = 0;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The worker thread of running multiple CLIs is invalid");
			multi_clis_tid = 0;
		}
		else
		{
			WRITE_ERROR("The worker thread of running multiple CLIs is STILL alive");
			return RET_FAILURE_INCORRECT_OPERATION;
		}
	}
	const char* filepath = (const char*)argv[1];
	if (!check_file_exist(filepath))
	{
		WRITE_FORMAT_WARN("The multiple CLIs file[%s] does NOT exist", filepath);
		return RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND;
	}
	assert(multi_clis_filepath == NULL && "multi_clis_filepath should be NULL");
	multi_clis_filepath = strdup(filepath);
	if (multi_clis_filepath == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: multi_clis_filepath");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	multi_clis_thread_ret = RET_SUCCESS;
	if (pthread_create(&multi_clis_tid, NULL, multi_clis_thread_handler, this) != 0)
	{
		WRITE_FORMAT_ERROR("Fail to create a handler thread of running multiple CLIs, due to: %s", strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	WRITE_DEBUG("Wait for the worker thread of running multiple CLIs's death...");
// Wait for interactive session thread's death
	pthread_join(multi_clis_tid, NULL);
	if (CHECK_SUCCESS(multi_clis_thread_ret))
		WRITE_DEBUG("Wait for the worker thread of running multiple CLIs's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of running multiple CLIs's death, due to: %s", GetErrorDescription(multi_clis_thread_ret));
		ret = multi_clis_thread_ret;
	}

	return ret;
}

unsigned short InteractiveSession::handle_switch_leader_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
// Notify the parent
	int node_id = atoi(argv[1]);
// Before switching leader, check if the node exists
	ClusterMap cluster_map;
	ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
	// printf("[InteractiveSession::handle_switch_leader_command] Check1: ret: %s\n", GetErrorDescription(ret));
	if (CHECK_FAILURE(ret))
		return ret;
	if (cluster_map.size() == 1)
	{
		print_to_console(string("Only single node in the cluster. Switching LEADER does NOT take effect\n"));
		return RET_WARN_INTERACTIVE_COMMAND;		
	}
	bool found = false;
	ret = cluster_map.check_exist_by_node_id(node_id, found);
	// printf("[InteractiveSession::handle_switch_leader_command] Check2: node_id: %d, ret: %s\n", node_id, GetErrorDescription(ret));
	if (CHECK_FAILURE(ret))
		return ret;
	if (!found)
	{
		char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Fails to switch unknown node[%d] to LEADER\n", node_id);
		WRITE_ERROR(buf);
		print_to_console(string(buf));
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	size_t notify_param_size = sizeof(int) + 1;
	PNOTIFY_CFG notify_cfg = new NotifySwitchLeaderCfg((void*)&node_id , notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
	// printf("[InteractiveSession::handle_switch_leader_command]  node_id: %d\n", ((PNOTIFY_SWITCH_LEADER_CFG)notify_cfg)->get_node_id());
// Asynchronous event: Synchronous in InteractiveServer and Asynchronous in ClusterManager
	ret = observer->notify(NOTIFY_SWITCH_LEADER, notify_cfg);
    SAFE_RELEASE(notify_cfg)

	return ret;
}

unsigned short InteractiveSession::handle_remove_follower_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
// Notify the parent
	int follower_node_id = atoi(argv[1]);
// Before switching leader, check if the node exists
	ClusterMap cluster_map;
	ret = manager->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
	// printf("[InteractiveSession::handle_remove_follower_command] Check1: ret: %s\n", GetErrorDescription(ret));
	if (CHECK_FAILURE(ret))
		return ret;
	if (cluster_map.size() == 1)
	{
		print_to_console(string("Only single node in the cluster. No FOLLOWERs exist !!!\n"));
		return RET_WARN_INTERACTIVE_COMMAND;		
	}
	bool found = false;
	ret = cluster_map.check_exist_by_node_id(follower_node_id, found);
	// printf("[InteractiveSession::handle_remove_follower_command] Check2: node_id: %d, ret: %s\n", node_id, GetErrorDescription(ret));
	if (CHECK_FAILURE(ret))
		return ret;
	if (!found)
	{
		char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Fails to remove unknown FOLLOWER[%d]\n", follower_node_id);
		WRITE_ERROR(buf);
		print_to_console(string(buf));
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	int leader_node_id;
	ret = cluster_map.get_node_id(node_token, leader_node_id);
	if (CHECK_FAILURE(ret))
		return ret;
	if (leader_node_id == follower_node_id)
	{
		char buf[DEF_STRING_SIZE];
		snprintf(buf, DEF_STRING_SIZE, "Fails to remove the node[%d] since it's LEADER\n", follower_node_id);
		WRITE_ERROR(buf);
		print_to_console(string(buf));
		return RET_WARN_INTERACTIVE_COMMAND;
	}

	size_t notify_param_size = sizeof(int) + 1;
	PNOTIFY_CFG notify_cfg = new NotifyRemoveFollowerCfg((void*)&follower_node_id , notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
	// printf("[InteractiveSession::handle_remove_follower_command]  node_id: %d\n", ((PNOTIFY_SWITCH_LEADER_CFG)notify_cfg)->get_node_id());
// Asynchronous event: Synchronous in InteractiveServer and Asynchronous in ClusterManager
	ret = observer->notify(NOTIFY_REMOVE_FOLLOWER, notify_cfg);
    SAFE_RELEASE(notify_cfg)

	return ret;
}

unsigned short InteractiveSession::handle_exit_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
// Send message to the user
	print_to_console(string("Bye bye !!!"));
// Notify the parent
	size_t notify_param_size = sizeof(int);
	PNOTIFY_CFG notify_cfg = new NotifySessionExitCfg((void*)&session_id, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Notify the event
	WRITE_FORMAT_WARN("[%s] The session is closed......", session_tag);
// Asynchronous event
	observer->notify(NOTIFY_SESSION_EXIT, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short InteractiveSession::handle_config_command(int argc, char **argv)
{
	typedef unsigned short (InteractiveSession::*handle_config_command_func_ptr)(int argc, char**argv);
	static handle_config_command_func_ptr handle_config_command_func_array[] =
	{
		&InteractiveSession::handle_config_help_command,
		&InteractiveSession::handle_config_search_event_command,
		&InteractiveSession::handle_config_cluster_setup_command,
		&InteractiveSession::handle_config_monitor_system_command,
		&InteractiveSession::handle_config_sync_cluster_command,
		&InteractiveSession::handle_config_exit_command
	};
	// assert (iter != command_map.end() && "Unknown command");
	CONFIG_COMMAND_MAP::iterator iter = config_command_map.find(string(argv[0]));
	// printf("key: %s\n", argv[0]);
	int config_command_type = (int)iter->second;
	// printf("valud: %d\n", config_command_type);
	return (this->*(handle_config_command_func_array[config_command_type]))(argc, argv);
}

unsigned short InteractiveSession::handle_config_help_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}

	unsigned short ret = RET_SUCCESS;
	string usage_string;
	usage_string += string("====================== Usage ======================\n");
	for (int i = 0; i < InteractiveSessionConfigCommandSize; i++)
	{
		if (CHECK_AUTHORITY(i, authority_mask))
			usage_string += string("* ") + GET_CONFIG_COMMAND(i) + string("\n Description: ") + GET_CONFIG_DESCRIPTION(i) + string("\n");	
	}
	usage_string += string("===================================================\n\n");

	ret = print_to_console(usage_string);
	return ret;
}

unsigned short InteractiveSession::handle_config_search_event_command(int argc, char **argv)
{
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s, config command count: %d", argv[0], argc);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	const char* rule_key = argv[1];
	const char* rule_value = argv[2];
	if (strcmp(rule_key, "time_option") == 0)
	{
		int select = atoi(rule_value) - 1;
		if (select < 0 || select >= TIME_INTERVAL_LIST_SIZE)
		{
				WRITE_FORMAT_WARN("Incorrect index to select time interval: %s", rule_value);
				return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
		}
		event_search_rule.need_search_event_time = true;
		event_search_rule.search_event_time_end = time(0);
		event_search_rule.search_event_time_begin = event_search_rule.search_event_time_end - TIME_INTERVAL_LIST[select];
	}
	else if (strcmp(rule_key, "time") == 0)
	{
		if (strcmp(interactive_session_unset_search_event_config_command, rule_value) == 0)
			event_search_rule.need_search_event_time = false;
		else
		{
			char* rule_value_tmp = strdup(rule_value);
			char *search_event_time_begin_str =  NULL;
			char *search_event_time_end_str =  NULL;
			search_event_time_begin_str = strtok_r(rule_value_tmp, "-", &search_event_time_end_str);
			if (search_event_time_begin_str == NULL || search_event_time_end_str == NULL)
			{
				WRITE_FORMAT_WARN("Incorrect search event time value: %s", rule_value);
				ret = RET_WARN_INTERACTIVE_CONFIG_COMMAND;
				goto OUT;
			}
			tm tm_begin;
			if (strptime(search_event_time_begin_str, "%Y/%m/%d_%H:%M", &tm_begin) == NULL)
			{
				WRITE_FORMAT_WARN("Incorrect search event start time format: %s", search_event_time_begin_str);
				ret = RET_WARN_INTERACTIVE_CONFIG_COMMAND;
				goto OUT;
			}
			else
			{
				tm_begin.tm_sec = 0;
				tm_begin.tm_isdst = -1; // Add this line to avoid the field is NOT defined overwise an out-of-range error occurs while calling mktime()
				// printf("Begin Time: %s -> %d/%02d/%02d %02d:%02d:%02d\n", search_event_time_begin_str, tm_begin.tm_year + 1900, tm_begin.tm_mon + 1, tm_begin.tm_mday, tm_begin.tm_hour, tm_begin.tm_min, tm_begin.tm_sec);
				event_search_rule.search_event_time_begin = mktime(&tm_begin);
			}
			tm tm_end;
			if (strptime(search_event_time_end_str, "%Y/%m/%d_%H:%M", &tm_end) == NULL)
			{
				WRITE_FORMAT_WARN("Incorrect search event end time format: %s", search_event_time_end_str);
				ret = RET_WARN_INTERACTIVE_CONFIG_COMMAND;
				goto OUT;
			}
			else
			{
				tm_end.tm_sec = 0;
				tm_end.tm_isdst = -1; // Add this line to avoid the field is NOT defined overwise an out-of-range error occurs while calling mktime()
				// printf("Time: %s -> %d/%02d/%02d %02d:%02d:%02d\n", search_event_time_end_str, tm_end.tm_year + 1900, tm_end.tm_mon + 1, tm_end.tm_mday, tm_end.tm_hour, tm_end.tm_min, tm_end.tm_sec);
				event_search_rule.search_event_time_end = mktime(&tm_end);
			}
			event_search_rule.need_search_event_time = true;
OUT:
			if(rule_value_tmp != NULL)
			{
				free(rule_value_tmp);
				rule_value_tmp = NULL;
			}
		}
	}
	else if (strcmp(rule_key, "type") == 0)
	{
		if (SEARCH_EVENT_TYPE_CONFIG_COMMAND_SIZE != EVENT_TYPE_SIZE)
		{
			static const char* errmsg = "ERROR!!! The definitions of event type are NOT identical. Terminate the process...";
			fprintf(stderr, "%s", errmsg);
			throw runtime_error(errmsg);
		}
		bool found = false;
		for (int i = 0 ; i < SEARCH_EVENT_TYPE_CONFIG_COMMAND_SIZE ; i++)
		{
			if (strcmp(interactive_session_search_event_type_config_command[i], rule_value) == 0)
			{
				event_search_rule.need_search_event_type = true;
				event_search_rule.search_event_type = (EventType)i;
				found = true;
			}
		}
		if (!found)
		{
			if (strcmp(interactive_session_unset_search_event_config_command, rule_value) == 0)
			{
				event_search_rule.need_search_event_type = false;
				found = true;
			}
		}
		if (!found)
		{
			WRITE_FORMAT_WARN("Unknown search event type value: %s", rule_value);
			return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
		}
	}
	else if (strcmp(rule_key, "severity") == 0)
	{
		if (SEARCH_EVENT_SEVERITY_CONFIG_COMMAND_SIZE != EVENT_SEVERITY_SIZE)
		{
			static const char* errmsg = "ERROR!!! The definitions of event severity are NOT identical. Terminate the process...";
			fprintf(stderr, "%s", errmsg);
			throw runtime_error(errmsg);
		}
		bool found = false;
		for (int i = 0 ; i < SEARCH_EVENT_SEVERITY_CONFIG_COMMAND_SIZE ; i++)
		{
			if (strcmp(interactive_session_search_event_severity_config_command[i], rule_value) == 0)
			{
				event_search_rule.need_search_event_severity = true;
				event_search_rule.search_event_severity = (EventSeverity)i;
				found = true;
			}
		}
		if (!found)
		{
			if (strcmp(interactive_session_unset_search_event_config_command, rule_value) == 0)
			{
				event_search_rule.need_search_event_severity = false;
				found = true;
			}
		}
		if (!found)
		{
			WRITE_FORMAT_WARN("Unknown search event severity value: %s", rule_value);
			return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
		}		
	}
	else if (strcmp(rule_key, "category") == 0)
	{
		if (SEARCH_EVENT_CATEGORY_CONFIG_COMMAND_SIZE != EVENT_CATEGORY_SIZE)
		{
			static const char* errmsg = "ERROR!!! The definitions of event category are NOT identical. Terminate the process...";
			fprintf(stderr, "%s", errmsg);
			throw runtime_error(errmsg);
		}
		bool found = false;
		for (int i = 0 ; i < SEARCH_EVENT_CATEGORY_CONFIG_COMMAND_SIZE ; i++)
		{
			if (strcmp(interactive_session_search_event_category_config_command[i], rule_value) == 0)
			{
				event_search_rule.need_search_event_category = true;
				event_search_rule.search_event_category = (EventCategory)i;
				found = true;
			}
		}
		if (!found)
		{
			if (strcmp(interactive_session_unset_search_event_config_command, rule_value) == 0)
			{
				event_search_rule.need_search_event_category = false;
				found = true;
			}
		}
		if (!found)
		{
			WRITE_FORMAT_WARN("Unknown search event category value: %s", rule_value);
			return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
		}
	}
	else if (strcmp(rule_key, "description") == 0)
	{
		if (strcmp(interactive_session_unset_search_event_config_command, rule_value) == 0)
		{
			event_search_rule.need_search_event_description = false;
		}
		else
		{
			event_search_rule.need_search_event_description = true;
			event_search_rule.search_event_description = rule_value;
		}
	}
	else
	{
    	WRITE_FORMAT_WARN("Unknown search_event key: %s", rule_key);
    	return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}

	return ret;
}

unsigned short InteractiveSession::handle_config_cluster_setup_command(int argc, char **argv)
{
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s, config command count: %d", argv[0], argc);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	bool cluster_is_single;
	ret = manager->get(PARAM_CLUSTER_IS_SINGLE, (void*)&cluster_is_single);
	if (CHECK_FAILURE(ret))
		return ret;
	if (!cluster_is_single)
	{
		static string error_string("Cluster is NOT a single node (No Followers)");
		print_to_console(error_string);
		return RET_WARN_CLUSTER_NOT_SINGLE;
	}
	const char* rule_key = argv[1];
	const char* rule_value = argv[2];
	if (strcmp(rule_key, "network") == 0)
	{
		string network = string(rule_value);
		ret = manager->set(PARAM_CLUSTER_SETUP_NETWORK, (void*)&network);
	}
	else if (strcmp(rule_key, "netmask_digits") == 0)
	{
		int netmask_digits = atoi(rule_value);
		ret = manager->set(PARAM_CLUSTER_SETUP_NETMASK_DIGITS, (void*)&netmask_digits);
	}
	else
	{
    	WRITE_FORMAT_WARN("Unknown monitor_system key: %s", rule_key);
    	return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	if (!cluster_config_updated) cluster_config_updated = true;
	return ret;
}

unsigned short InteractiveSession::handle_config_monitor_system_command(int argc, char **argv)
{
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s, config command count: %d", argv[0], argc);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	const char* rule_key = argv[1];
	const char* rule_value = argv[2];
	if (strcmp(rule_key, "period") == 0)
	{
		int system_monitor_period = atoi(rule_value);
		ret = manager->set(PARAM_SYSTEM_MONITOR_PERIOD, (void*)&system_monitor_period);
	}
	else
	{
    	WRITE_FORMAT_WARN("Unknown monitor_system key: %s", rule_key);
    	return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	if (!cluster_config_updated) cluster_config_updated = true;
	return ret;
}

unsigned short InteractiveSession::handle_config_sync_cluster_command(int argc, char **argv)
{
	if (argc != 3)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s, config command count: %d", argv[0], argc);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	unsigned short ret = RET_SUCCESS;
	const char* rule_key = argv[1];
	const char* rule_value = argv[2];
	if (strcmp(rule_key, "folderpath") == 0)
	{
		string folderpath = string(rule_value);
		ret = manager->set(PARAM_CLUSTER_SYNC_FOLDERPATH, (void*)&folderpath);
	}
	else
	{
    	WRITE_FORMAT_WARN("Unknown sync_cluster key: %s", rule_key);
    	return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	if (!cluster_config_updated) cluster_config_updated = true;
	return ret;
}

unsigned short InteractiveSession::handle_config_exit_command(int argc, char **argv)
{
	if (argc != 1)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect config command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_CONFIG_COMMAND;
	}
	if (!is_config_mode)
	{
		WRITE_ERROR("Incorrect operation: NOT in the configuraiton mode");
		print_to_console(incorrect_command_phrases);
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	if (cluster_config_updated)
	{
		WRITE_EVT_RECORDER(UpdateConfigEventCfg);
		cluster_config_updated = false;
	} 

	is_config_mode = false;
	return RET_SUCCESS;
}

unsigned short InteractiveSession::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
    	case NOTIFY_GET_SYSTEM_MONITOR:
    	{
    		string& system_monitor_string = *(string*)notify_param;
    		ret = print_to_console(system_monitor_string);
    	}
    	break;
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

unsigned short InteractiveSession::async_handle(NotifyCfg* notify_cfg)
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
    		// fprintf(stderr, "%s in InteractiveSession::async_handle()", buf);
		    fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}
