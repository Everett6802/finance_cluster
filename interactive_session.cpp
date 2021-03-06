#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <map>
// #include <string>
#include "interactive_session.h"


using namespace std;

// Command type definition
enum InteractiveSessionCommandType
{
	InteractiveSessionCommand_Help,
	InteractiveSessionCommand_Exit,
	InteractiveSessionCommand_GetClusterDetail,
	InteractiveSessionCommand_GetSystemInfo,
	// InteractiveSessionCommand_GetNodeSystemInfo,
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
	InteractiveSessionCommandSize
};

static const char *interactive_session_command[InteractiveSessionCommandSize] = 
{
	"help",
	"exit",
	"get_cluster_detail",
	"get_system_info",
	// "get_node_system_info",
	"get_simulator_version",
	"transfer_simulator_package",
	"install_simulator",
	"apply_fake_acspt_config",
	"get_fake_acspt_config_value",
	"apply_fake_usrept_config",
	"start_fake_acspt",
	"stop_fake_acspt",
	"start_fake_usrept",
	"stop_fake_usrept",
	"get_fake_acspt_state"
};

typedef map<string, InteractiveSessionCommandType> COMMAND_MAP;
typedef COMMAND_MAP::iterator COMMAND_MAP_ITER;

static const char* INTERACTIVE_PROMPT = "FC> ";
// static const char* INCORRECT_COMMAND_ARGUMENT_FORMAT = "Incorrect command[%s] argument: %s";

static string welcome_phrases = "\n************** Welcome to Finance Cluster CLI **************\n\n";
static string incomplete_command_phrases = "\nIncomplete Command\n\n";
static string incorrect_command_phrases = "\nIncorrect Command\n\n";

static COMMAND_MAP command_map;
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
				command_map.insert(make_pair(string(interactive_session_command[i]), (InteractiveSessionCommandType)i));
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

InteractiveSession::InteractiveSession(PINOTIFY notify, PIMANAGER mgr, int client_fd, const sockaddr_in& client_sockaddr, int interactive_session_id) :
	observer(notify),
	manager(mgr),
	session_exit(0),
	session_tid(0),
	session_thread_ret(RET_SUCCESS),
	sock_fd(client_fd),
	session_id(interactive_session_id),
	is_root(false)
{
	IMPLEMENT_MSG_DUMPER()
	init_command_map();
	memcpy(&sock_addr, &client_sockaddr, sizeof(sockaddr_in));
	memset(session_tag, 0x0, sizeof(char) * 64);
	snprintf(session_tag, 64, "%d (%s:%d)", session_id, inet_ntoa(sock_addr.sin_addr), htons(sock_addr.sin_port));
	is_root = is_root_user();
	// printf("is_root: %s\n", (is_root ? "True" : "False"));
}
	
InteractiveSession::~InteractiveSession()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "%s Error occurs in InteractiveSession::deinitialize(), due to :%s", session_tag, GetErrorDescription(ret));
		throw runtime_error(string(errmsg));
	}
	if (observer != NULL)
		observer = NULL;
	if (manager != NULL)
		manager = NULL;

	RELEASE_MSG_DUMPER()
}

unsigned short InteractiveSession::initialize()
{
	if (pthread_create(&session_tid, NULL, session_thread_handler, this) != 0)
	{
		WRITE_FORMAT_ERROR("Fail to create a handler thread of interactive session[%s], due to: %s", session_tag, strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}
	return RET_SUCCESS;
}

unsigned short InteractiveSession::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&session_exit, 1);
	// sleep(1);
	usleep(100000);
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
			WRITE_FORMAT_ERROR("The signal to the worker thread of interactive session[%s] is invalid", session_tag);
			ret = RET_FAILURE_HANDLE_THREAD;
		}
		else
		{
			WRITE_FORMAT_DEBUG("The signal to the worker thread of interactive session[%s] is STILL alive", session_tag);
// Kill the thread
		    if (pthread_cancel(session_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of interactive session[%s], due to: %s", session_tag, strerror(errno));
			// sleep(1);
			usleep(100000);
		}
	}

	WRITE_FORMAT_DEBUG("Wait for the worker thread of interactive session[%s]'s death...", session_tag);
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
// Wait for interactive session thread's death
	pthread_join(session_tid, NULL);
	if (CHECK_SUCCESS(session_thread_ret))
		WRITE_FORMAT_DEBUG("Wait for the worker thread of interactive session[%s]'s death Successfully !!!", session_tag);
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of interactive session[%s]'s death, due to: %s", session_tag, GetErrorDescription(session_thread_ret));
		ret = session_thread_ret;
	}
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

bool InteractiveSession::is_privilege_user_command(int command_type)
{
	static InteractiveSessionCommandType PRIVILEGE_USER_COMMAND_LIST[] = 
	{
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
		InteractiveSessionCommand_GetFakeAcsptState
	};
	static int PRIVILEGE_USER_COMMAND_LIST_LEN = sizeof(PRIVILEGE_USER_COMMAND_LIST) / sizeof(PRIVILEGE_USER_COMMAND_LIST[0]);
	for (int i = 0 ; i < PRIVILEGE_USER_COMMAND_LIST_LEN ; i++)
	{
		if (command_type == PRIVILEGE_USER_COMMAND_LIST[i])
			return true;
	}
	return false;
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
// Check if the command exist
					COMMAND_MAP::iterator iter = command_map.find(string(argv_inner[cur_argc_inner]));
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
// Some commmands require privilege user
						if (is_privilege_user_command((int)iter->second))
						{
							if (!is_root)
							{
								can_execute = false;
								WRITE_FORMAT_WARN("The %s command requires privilege user", argv_inner[0]);
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
				WRITE_FORMAT_DEBUG("Try to execute the %s command......", argv_inner[0]);
				ret = handle_command(cur_argc_inner, argv_inner);
				if (!CHECK_SUCCESS(ret))
					WRITE_FORMAT_DEBUG("Execute the %s command, ret: %s", argv_inner[0], GetErrorDescription(ret));
				if (CHECK_FAILURE(ret))
				{
					char rsp_buf[RSP_BUF_SIZE + 1];
					memset(rsp_buf, 0x0, sizeof(rsp_buf) / sizeof(rsp_buf[0]));
					snprintf(rsp_buf, RSP_BUF_SIZE, "Error occurs while executing the %s command, due to: %s\n Close the session: %s\n", argv_inner[0], GetErrorDescription(ret), session_tag);
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
			}
			if (command_line_outer != NULL)
				command_line_outer = NULL;
			cur_argc_outer++;
		}
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

unsigned short InteractiveSession::print_to_console(string response)const
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
	return print_to_console(prompt);
}

unsigned short InteractiveSession::handle_command(int argc, char **argv)
{
	typedef unsigned short (InteractiveSession::*handle_command_func_ptr)(int argc, char**argv);
	static handle_command_func_ptr handle_command_func_array[] =
	{
		&InteractiveSession::handle_help_command,
		&InteractiveSession::handle_exit_command,
		&InteractiveSession::handle_get_cluster_detail_command,
		&InteractiveSession::handle_get_system_info_command,
		// &InteractiveSession::handle_get_node_system_info_command,
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
		&InteractiveSession::handle_get_fake_acspt_state_command
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
	usage_string += string("* help\n Description: The usage\n");
	usage_string += string("* exit\n Description: Exit the session\n");
	usage_string += string("* get_cluster_detail\n Description: Get the cluster detail info\n");
	usage_string += string("* get_system_info\n Description: Get the system info in the cluster\n");
	// usage_string += string("* get_node_system_info\n Description: Get the system info of certain a node\n");
	usage_string += string("  Param: Node ID/IP\n");
	usage_string += string("    Format 1: Node ID: (ex. 1)\n");
	usage_string += string("    Format 2: Node IP: (ex. 10.206.24.219)\n");
	if (is_root)
	{
		usage_string += string("* get_simulator_version\n Description: Get simulator version in the cluster\n");
		usage_string += string("* transfer_simulator_package\n Description: Leader transfers the simulator package to each follower\n");
		usage_string += string("  Param: Simulator package filepath (ex. /home/super/simulator-v5.2-23-u1804.tar.xz)\n");
		usage_string += string("* install_simulator\n Description: Install simulator in the cluster\n");
		usage_string += string("  Param: Simulator package filepath (ex. /home/super/simulator-v5.2-23-u1804.tar.xz)\n");
		usage_string += string("* apply_fake_acspt_config\n Description: Apply new config to all fake acepts in the cluster\n");
		usage_string += string("  Param: Fake acspt config filepath (ex. /home/super/new_fake_acspt_sim.cfg)\n");
		usage_string += string("* get_fake_acspt_config_value\n Description: Get the config value from fake acspts config file\n");
		usage_string += string("  Param: Acspt config list string (ex. CONFIG1,CONFIG2,CONFIG3)\n");
		usage_string += string("* apply_fake_usrept_config\n Description: Apply new config to all fake usrepts in the cluster\n");
		usage_string += string("  Param: Fake usrept config filepath (ex. /home/super/new_fake_usrept.cfg)\n");
		usage_string += string("* start_fake_acspt\n Description: Start fake acepts in the cluster\n");
		usage_string += string("* stop_fake_acspt\n Description: Stop fake acepts in the cluster\n");
		usage_string += string("* start_fake_usrept\n Description: Start fake usrepts in the cluster\n");
		usage_string += string("* stop_fake_usrept\n Description: Stop fake usrepts in the cluster\n");
		usage_string += string("* get_fake_acspt_state\n Description: Get the states of all fake acepts in the cluster\n");
	}
	usage_string += string("===================================================\n");

	ret = print_to_console(usage_string);
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
// Print data in cosole
	string cluster_detail_string(CLUSTER_DETAIL_TITLE);
	ClusterMap::const_iterator iter = cluster_detail_param.cluster_map.begin();
	char cluster_node_ip[RSP_BUF_VERY_SHORT_SIZE];
	while(iter != cluster_detail_param.cluster_map.end())
	{
		const ClusterNode& cluster_node = *iter;
		// snprintf(cluster_node_ip, RSP_BUF_VERY_SHORT_SIZE, "%s", cluster_node.node_ip.c_str());
		strcpy(cluster_node_ip, cluster_node.node_ip.c_str());
		// strcpy(cluster_node_ip, "10.206.24.219");
		int node_type_index = (strcmp(cluster_node_ip, cluster_detail_param.cluster_ip) == 0 ? LEADER : FOLLOWER);
		bool is_local_node = (cluster_detail_param.node_id == cluster_node.node_id ? true : false);
		char buf[RSP_BUF_SIZE];
		snprintf(buf, RSP_BUF_SIZE, (is_local_node ? "%d %s %s *\n":  "%d %s %s\n"), cluster_node.node_id, cluster_node_ip, NODE_TYPE_LIST[node_type_index]);
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
// Get the data
	ClusterSystemInfoParam cluster_system_info_param; // = new SimulatorVersionParam(DEF_VERY_SHORT_STRING_SIZE);
	// if (simulator_version_param  == NULL)
	// 	throw bad_alloc();
    ret = manager->get(PARAM_SYSTEM_INFO, (void*)&cluster_system_info_param);
 	if (CHECK_FAILURE(ret))
		return ret;
    // SAFE_RELEASE(notify_cfg)
	if (CHECK_SUCCESS(ret))
	{
		ClusterDetailParam cluster_detail_param;
	    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		if (CHECK_FAILURE(ret))
			return ret;
		ClusterMap& cluster_map = cluster_detail_param.cluster_map;

		char buf[DEF_STRING_SIZE];
		map<int, string>& clusuter_system_info_map = cluster_system_info_param.clusuter_system_info_map;
// Print data in cosole
		string system_info_string("*** System Info ***\n");
		map<int, string>::iterator iter = clusuter_system_info_map.begin();
		while (iter != clusuter_system_info_map.end())
		{
			// simulator_version_string += string(simulator_version_param->simulator_version);
			// simulator_version_string += string("\n");
			int node_id = (int)iter->first;
			string node_ip;
			ret = cluster_map.get_node_ip(node_id, node_ip);
			if (CHECK_FAILURE(ret))
				return ret;
			snprintf(buf, DEF_STRING_SIZE, "%s  %s\n", node_ip.c_str(), ((string)iter->second).c_str());
			system_info_string += string(buf);
			++iter;
		}
		system_info_string += string("\n");
		ret = print_to_console(system_info_string);
	}
	return RET_SUCCESS;
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
// 	snprintf(system_info_param.node_ip_buf, VERY_SHORT_STRING_SIZE, "%s", argv[1]);
//     ret = manager->get(PARAM_SYSTEM_INFO, (void*)&system_info_param);
// 	if (CHECK_FAILURE(ret))
// 		return ret;
// // Print data in cosole
// 	string node_system_info_string(NODE_SYSTEM_INFO_TITLE);
// 	char cluster_node[RSP_BUF_VERY_SHORT_SIZE];
// 	snprintf(cluster_node,  RSP_BUF_VERY_SHORT_SIZE, "Node %s\n", system_info_param.node_ip_buf);
// 	node_system_info_string += string(cluster_node);
// 	node_system_info_string += system_info_param.system_info;
// 	node_system_info_string += string("\n");
// 	ret = print_to_console(node_system_info_string);
// 	return RET_SUCCESS;
// }

unsigned short InteractiveSession::handle_trasnfer_simulator_package_command(int argc, char **argv)
{
	assert(observer != NULL && "observer should NOT be NULL");
	if (argc != 2)
	{
		WRITE_FORMAT_WARN("WANRING!! Incorrect command: %s", argv[0]);
		print_to_console(incorrect_command_phrases);
		return RET_WARN_INTERACTIVE_COMMAND;
	}
	const char* filepath = (const char*)argv[1];
	if (!check_file_exist(filepath))
	{
		WRITE_FORMAT_WARN("The simulator package file[%s] does NOT exist", filepath);
		return RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND;
	}

	ClusterFileTransferParam cluster_file_transfer_param;
// Start to transfer simulator package
	unsigned short ret = RET_SUCCESS;
	cluster_file_transfer_param.session_id = session_id;
    ret = manager->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)filepath);
 	if (CHECK_FAILURE(ret))
		return ret;
    // SAFE_RELEASE(notify_cfg)
// Wait for transferring done...
	ClusterDetailParam cluster_detail_param;
	ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
	if (CHECK_FAILURE(ret))
		return ret;
	ClusterMap& cluster_map = cluster_detail_param.cluster_map;

	char buf[DEF_STRING_SIZE];
	map<int, string>& clusuter_file_transfer_map = cluster_file_transfer_param.clusuter_file_transfer_map;
// Print data in cosole
	string file_transfer_string("file transfer\n");
	map<int, string>::iterator iter = clusuter_file_transfer_map.begin();
	while (iter != clusuter_file_transfer_map.end())
	{
		int node_id = (int)iter->first;
		string node_ip;
		ret = cluster_map.get_node_ip(node_id, node_ip);
		if (CHECK_FAILURE(ret))
			return ret;
		snprintf(buf, DEF_STRING_SIZE, "%s  %s\n", node_ip.c_str(), ((string)iter->second).c_str());
		file_transfer_string += string(buf);
		++iter;
	}
	file_transfer_string += string("\n");
	ret = print_to_console(file_transfer_string);
	return RET_SUCCESS;
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
		ClusterDetailParam cluster_detail_param;
	    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		if (CHECK_FAILURE(ret))
			return ret;
		ClusterMap& cluster_map = cluster_detail_param.cluster_map;

		char buf[DEF_STRING_SIZE];
		map<int, string>& clusuter_simulator_version_map = cluster_simulator_version_param.clusuter_simulator_version_map;
// Print data in cosole
		string simulator_version_string("simulator version\n");
		map<int, string>::iterator iter = clusuter_simulator_version_map.begin();
		while (iter != clusuter_simulator_version_map.end())
		{
			// simulator_version_string += string(simulator_version_param->simulator_version);
			// simulator_version_string += string("\n");
			int node_id = (int)iter->first;
			string node_ip;
			ret = cluster_map.get_node_ip(node_id, node_ip);
			if (CHECK_FAILURE(ret))
				return ret;
			snprintf(buf, DEF_STRING_SIZE, "%s  %s\n", node_ip.c_str(), ((string)iter->second).c_str());
			simulator_version_string += string(buf);
			++iter;
		}
		simulator_version_string += string("\n");
		ret = print_to_console(simulator_version_string);
	}
	return RET_SUCCESS;
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
	// print_to_console(string("Install Simulator in the cluster..."));
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
	// print_to_console(string("Install Simulator in the cluster..."));
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
	// print_to_console(string("Install Simulator in the cluster..."));
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
	// print_to_console(string("Install Simulator in the cluster..."));
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
	// print_to_console(string("Stop FakeAcspts in the cluster..."));
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
	// print_to_console(string("Start FakeAcspts in the cluster..."));
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
	// print_to_console(string("Stop FakeAcspts in the cluster..."));
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
		ClusterDetailParam cluster_detail_param;
	    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
		if (CHECK_FAILURE(ret))
			return ret;
		ClusterMap& cluster_map = cluster_detail_param.cluster_map;

		char buf[DEF_VERY_LONG_STRING_SIZE];
		map<int, string>& cluster_fake_acspt_state_map = cluster_fake_acspt_state_param.cluster_fake_acspt_state_map;
// Print data in cosole
		string fake_acspt_state_string("*** Fake Acspt State ***\n");
		map<int, string>::iterator iter = cluster_fake_acspt_state_map.begin();
		while (iter != cluster_fake_acspt_state_map.end())
		{
			// simulator_version_string += string(simulator_version_param->simulator_version);
			// simulator_version_string += string("\n");
			int node_id = (int)iter->first;
			string node_ip;
			ret = cluster_map.get_node_ip(node_id, node_ip);
			if (CHECK_FAILURE(ret))
				return ret;
			snprintf(buf, DEF_VERY_LONG_STRING_SIZE, "%s  %s\n", node_ip.c_str(), ((string)iter->second).c_str());
			fake_acspt_state_string += string(buf);
			++iter;
		}
		fake_acspt_state_string += string("\n");
		ret = print_to_console(fake_acspt_state_string);
	}
	return RET_SUCCESS;
}
