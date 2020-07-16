// #include <netdb.h>
// #include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
// #include <arpa/inet.h>
// #include <sys/socket.h>
#include "cluster_mgr.h"
#include "leader_node.h"
#include "follower_node.h"


using namespace std;

static KeepaliveTimerTask keepalive_timer_task;
static void timer_sigroutine(int signo)
{
	switch (signo)
	{
	case SIGALRM:
	{
//        printf("Catch a signal -- SIGALRM \n");
		unsigned short ret = keepalive_timer_task.trigger();
		if (CHECK_SUCCESS(ret))
			signal(SIGALRM, timer_sigroutine);
	}
	break;
	}
}

const char* ClusterMgr::SERVER_LIST_CONF_FILENAME = "server_list.conf";
const int ClusterMgr::RETRY_WAIT_CONNECTION_TIME = 3; // 3 seconds
const int ClusterMgr::TRY_TIMES = 3;

unsigned short ClusterMgr::parse_config()
{
	unsigned short ret = RET_SUCCESS;
	list<string> conf_line_list;
	ret = read_config_file_lines(conf_line_list, FINANCE_CLUSTER_CONF_FILENAME);
	if (CHECK_FAILURE(ret))
		return ret;
	list<string>::iterator iter = conf_line_list.begin();
	while (iter != conf_line_list.end())
	{
		string line = (string)*iter;
		char* line_tmp = strdup(line.c_str());
		char* conf_name = strtok(line_tmp, "=");
		if (conf_name == NULL)
		{
			WRITE_FORMAT_ERROR("Incorrect configuration name: %s", line_tmp);
			return RET_FAILURE_INCORRECT_CONFIG;
		}
		char* conf_value = strtok(NULL, "=");
		if (conf_value == NULL)
		{
			WRITE_FORMAT_ERROR("Incorrect configuration value: %s", line_tmp);
			return RET_FAILURE_INCORRECT_CONFIG;
		}

		if (strcmp(conf_name, CONF_FIELD_CLUSTER_NETWORK) == 0)
		{
			cluster_network = string(conf_value);
			WRITE_FORMAT_DEBUG("CONF Name: %s, Value: %s", CONF_FIELD_CLUSTER_NETWORK, cluster_network.c_str());
		}
		else if (strcmp(conf_name, CONF_FIELD_CLUSTER_NETMASK_DIGITS) == 0)
		{
			cluster_netmask_digits = atoi(conf_value);
			WRITE_FORMAT_DEBUG("CONF Name: %s, Value: %d", CONF_FIELD_CLUSTER_NETMASK_DIGITS, cluster_netmask_digits);
		}
		else
		{
			static const int ERRMSG_SIZE = 64;
			char errmsg[ERRMSG_SIZE];
			snprintf(errmsg, ERRMSG_SIZE, "Unknown config field: %s", conf_name);
			throw invalid_argument(errmsg);
		}

		if (line_tmp != NULL)
		{
			free(line_tmp);
			line_tmp = NULL;
		}
		iter++;
	}
	return RET_SUCCESS;
}

unsigned short ClusterMgr::find_local_ip()
{
	unsigned short ret = RET_SUCCESS;

	map<string, string> interface_ip_map;
	ret = get_local_interface_ip(interface_ip_map);
	if (CHECK_FAILURE(ret))
		return ret;

	bool found = false;
	map<string, string>::iterator iter = interface_ip_map.begin();
	while (iter != interface_ip_map.end())
	{
		string interface = iter->first;
      	string ip = iter->second;
      	IPv4Addr ipv4_addr(ip.c_str());
      	if (ipv4_addr.is_same_network(cluster_netmask_digits, cluster_network.c_str()))
      	{
      		local_ip = strdup(ip.c_str());
      		WRITE_FORMAT_DEBUG("The local IP: %s", local_ip);
      		found = true;
      		break;
      	}
		iter++;
	}
	if (!found)
	{
		WRITE_FORMAT_ERROR("Fail to find the interface in the network: %s/%d", cluster_network.c_str(), cluster_netmask_digits);
		return RET_FAILURE_INCORRECT_CONFIG;
	}

	return ret;
}

ClusterMgr::ClusterMgr() :
	notify_thread(NULL),
	local_ip(NULL),
	cluster_ip(NULL),
	node_type(NONE),
	cluster_node(NULL),
	interactive_server(NULL),
	simulator_handler(NULL),
	simulator_installed(false)
{
	IMPLEMENT_MSG_DUMPER()
}

ClusterMgr::~ClusterMgr()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in ClusterMgr::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(string(errmsg));
	}

	if (cluster_node != NULL)
	{
		delete cluster_node;
		cluster_node = NULL;
	}

	if (cluster_ip != NULL)
	{
		delete[] cluster_ip;
		cluster_ip = NULL;
	}

	if (local_ip != NULL)
	{
		delete[] local_ip;
		local_ip = NULL;
	}

	RELEASE_MSG_DUMPER()
}

void ClusterMgr::set_keepalive_timer_interval(int delay, int period)
{
	struct itimerval value, ovalue;

	value.it_value.tv_sec = delay;
	value.it_value.tv_usec = 0;
	value.it_interval.tv_sec = period;
	value.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &value, &ovalue);
}

unsigned short ClusterMgr::start_keepalive_timer()
{
	WRITE_DEBUG("Start the keep-alive timer");
	keepalive_timer_task.initialize(this);
	signal(SIGALRM, timer_sigroutine);
	set_keepalive_timer_interval(KEEPALIVE_DELAY_TIME, KEEPALIVE_PERIOD);

	return RET_SUCCESS;
}

void ClusterMgr::stop_keepalive_timer()
{
// To stop the keep-alive timer
	WRITE_DEBUG("Stop the keep-alive timer");
	set_keepalive_timer_interval();
	keepalive_timer_task.deinitialize();
}

unsigned short ClusterMgr::become_leader()
{
	assert(local_ip != NULL && "local_ip should NOT be NULL");
	cluster_node = new LeaderNode(this, local_ip);
	if (cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: cluster_node (Leader)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	unsigned short ret = cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = LEADER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a Leader !!!", local_ip);
	return RET_SUCCESS;
}

unsigned short ClusterMgr::become_follower(bool need_rebuild_cluster)
{
	assert(local_ip != NULL && "local_ip should NOT be NULL");
	assert(cluster_ip != NULL && "cluster_ip should NOT be NULL");

	cluster_node = new FollowerNode(this, cluster_ip, local_ip);
	if (cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: cluster_node (Follower)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	unsigned short ret = RET_SUCCESS;
	ret = cluster_node->set(PARAM_CONNECTION_RETRY, (void*)&need_rebuild_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = FOLLOWER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a Follower !!!", local_ip);
	return ret;
}

// unsigned short ClusterMgr::start_connection(bool need_rebuild_cluster)
// {
// 	unsigned short ret = RET_SUCCESS;

// 	if (cluster_ip != NULL)
// 	{
// 		WRITE_FORMAT_DEBUG("Node[%s] Try to become follower of cluster[%s]...", local_ip, cluster_ip);
// // Try to become the follower node
// 		ret = become_follower();
// 		// if (CHECK_FAILURE(ret) || IS_TRY_CONNECTION_TIMEOUT(ret))
// 		// {
// 		// 	if (node_type != NONE)
// 		// 	{
// 		// 		WRITE_FORMAT_ERROR("Node[%s] type should be None at this moment", local_ip);
// 		// 		return RET_FAILURE_INCORRECT_OPERATION;
// 		// 	}
// 		// }
// 	}
// 	else
// 	{
// 		WRITE_FORMAT_DEBUG("Node[%s] Try to become leader...", local_ip);
// // Try to become the leader node
// 		ret = become_leader();		
// 	}

// 	return ret;
// }

unsigned short ClusterMgr::stop_connection()
{
	if (cluster_node != NULL)
	{
		unsigned short ret = cluster_node->deinitialize();
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Error occur while closing the %s[%s]", (is_leader() ? "Leader" : "Follower"), local_ip);
			return ret;
		}
		delete cluster_node;
		cluster_node = NULL;
		node_type = NONE;
	}

	return RET_SUCCESS;
}

unsigned short ClusterMgr::rebuild_cluster()
{
	if (node_type == LEADER)
	{
		WRITE_FORMAT_ERROR("Leader [%s] NEVER tries to re-connect", local_ip);
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	assert(cluster_ip != NULL && "cluster_ip should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
// Get the cluster map from the follower
	ClusterMap cluster_map;
    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
	if (CHECK_FAILURE(ret))
		return ret;
	if (cluster_map.is_empty())
	{
		WRITE_FORMAT_ERROR("The cluster map in Follower[%s] is empty", local_ip);
		return RET_FAILURE_RUNTIME;
	}
// Pops up the first node: Leader
	int first_node_id;
	std::string first_node_ip;
	ret = cluster_map.get_first_node(first_node_id, first_node_ip);
	if (CHECK_FAILURE(ret))
		return ret;
	string cluster_ip_string(cluster_ip);
	assert(strcmp(first_node_ip.c_str(), cluster_ip) == 0 && "The first node in cluster should be Leader");
// Get the node ID from the follower
	int node_id;
    ret = cluster_node->get(PARAM_NODE_ID, (void*)&node_id);
	if (CHECK_FAILURE(ret))
		return ret;
// Close the old connection
	ret = stop_connection();
	if (CHECK_FAILURE(ret))
		return ret;
// Try to re-establish the cluster from the cluster map
    while (!cluster_map.is_empty())
    {
    	int leader_candidate_node_id;
        string leader_candidate_node_ip;
        ret = cluster_map.get_first_node(leader_candidate_node_id, leader_candidate_node_ip);
        if (CHECK_FAILURE(ret))
        {
        	WRITE_ERROR("Fails to get the candidate of the Leader");
        	return ret;
        }
        // fprintf(stderr, "ID: %d candidate: id: %d, ip: %s\n", node_id, leader_candidate_node_id, leader_candidate_node_ip.c_str());
        if (leader_candidate_node_id == node_id)
        {
// Leader
	        WRITE_FORMAT_DEBUG("Node[%s] try to becomme the Leader in the Cluster......", local_ip);
        	if (cluster_ip != NULL)
        	{
        		free(cluster_ip);
        		cluster_ip = NULL;
        	}
        	ret = become_leader();
        }
        else
        {
// Follower
	        WRITE_FORMAT_DEBUG("Node[%s] try to join the Cluster[%s]......", local_ip, cluster_ip);
        	set_cluster_ip(leader_candidate_node_ip.c_str());
        	ret = become_follower(true);
	        if (IS_TRY_CONNECTION_TIMEOUT(ret))
	        	continue;
        }
        break;
    }
    if (CHECK_FAILURE(ret))
    {
    	WRITE_FORMAT_ERROR("Node[%s] fails to rebuild the cluster, due to: %s", local_ip, GetErrorDescription(ret));
    }
	return ret;
}

void ClusterMgr::check_keepalive()
{
	if (cluster_node != NULL)
	{
		WRITE_DEBUG("Check Keep-Alive...");
		unsigned short ret = cluster_node->send(MSG_CHECK_KEEPALIVE);
		if (node_type == FOLLOWER)
		{
// Follower
			if (CHECK_FAILURE(ret))
			{
				if (!IS_KEEP_ALIVE_TIMEOUT(ret))
				{
					WRITE_ERROR("Error should NOT occur when checking keep-alive on the client side !!!");
					// notify_exit(ret);
					// return;
					FPRINT_ERROR("Follower[%s] keep-alive time-out !!!\n", local_ip);
					raise(SIGTERM);
				}
				else
				{
// Stop a keep-alive timer
					stop_keepalive_timer();
// The leader is dead, try to find the new leader
					ret = rebuild_cluster();
					if (CHECK_FAILURE(ret))
					{
						// notify_exit(ret);
						// return;
						FPRINT_ERROR("Node[%s] fails to re-connect, due to: %s\n", local_ip, GetErrorDescription(ret));
						raise(SIGTERM);
					}
// Start a keep-alive timer
					ret = start_keepalive_timer();
					if (CHECK_FAILURE(ret))
					{
						// notify_exit(ret);
						// return;
						FPRINT_ERROR("Node[%s] fails to start keep-alive timer, due to: %s\n", local_ip, GetErrorDescription(ret));
						raise(SIGTERM);
					}
				}
			}
		}
		else
		{
// Leader
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Termiate the Leader[%s] due to: %s", local_ip, GetErrorDescription(ret));
				// notify_exit(ret);
				// return;
				FPRINT_ERROR("Leader[%s] fails to check keep-alive, due to: %s\n", local_ip, GetErrorDescription(ret));
				raise(SIGTERM);
			}
		}
	}
}

void ClusterMgr::dump_interactive_session_data_list(int session_id)const
{
	fprintf(stderr, "The interactive session[%d] data:\n", session_id);
	const std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_data_list[session_id];
	std::list<PNOTIFY_CFG>::const_iterator iter = interactive_session_data.begin();
	while (iter != interactive_session_data.end())
	{
		PNOTIFY_CFG nodify_cfg = (PNOTIFY_CFG)*iter;
		fprintf(stderr, "NotifyType: %d\n", nodify_cfg->get_notify_type());
		++iter;
	}
}

unsigned short ClusterMgr::initialize()
{
	unsigned short ret = RET_SUCCESS;
	ret = parse_config();
	if (CHECK_FAILURE(ret))
		return ret;
// Find local IP
	if (local_ip == NULL)
	{
		ret  = find_local_ip();
		if (CHECK_FAILURE(ret))
			return ret;
		// WRITE_FORMAT_DEBUG("The local IP of this Node: %s", local_ip);
		if (cluster_ip != NULL)
		{
// Check if local_ip and cluster_ip are in the same network
	      	IPv4Addr ipv4_addr(cluster_ip);
	      	if (!ipv4_addr.is_same_network(cluster_netmask_digits, cluster_network.c_str()))
	      	{
	      		WRITE_FORMAT_ERROR("The local IP[%s] and cluster IP[%s] are NOT in the same network[%s/%s]", local_ip, cluster_ip, cluster_network.c_str(), cluster_netmask_digits);
	      		return RET_FAILURE_INCORRECT_CONFIG;
	      	}
		}
	}
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "ClusterMgr Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
	// sleep(1);
	usleep(100000);
// Define a leader/follower and establish the connection
	// ret = start_connection();
	if (cluster_ip != NULL)
	{
		WRITE_FORMAT_DEBUG("Node[%s] Try to become follower of cluster[%s]...", local_ip, cluster_ip);
		ret = become_follower();
	}
	else
	{
		WRITE_FORMAT_DEBUG("Node[%s] Try to become leader...", local_ip);
		ret = become_leader();		
	}
	if (CHECK_FAILURE(ret))
		return ret;
// Start a keep-alive timer
	ret = start_keepalive_timer();
	if (CHECK_FAILURE(ret))
		return ret;
// Initialize the session server
	interactive_server = new InteractiveServer(this);
	if (interactive_server == NULL)
		throw bad_alloc();
	ret = interactive_server->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
// Initialize the simulator handler
	simulator_handler = new SimulatorHandler(this);
	if (simulator_handler == NULL)
		throw bad_alloc();
	ret = simulator_handler->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
	simulator_installed = simulator_handler->is_simulator_installed();
	WRITE_INFO((simulator_installed ? "The simulator is installed" : "The simulator is NOT installed"));

	return ret;
}

unsigned short ClusterMgr::deinitialize()
{
// Deinitialize the simulator handler
	if (simulator_handler != NULL)
	{
		simulator_handler->deinitialize();
		delete simulator_handler;
		simulator_handler = NULL;	
	}
// Deinitialize the session server
	if (interactive_server != NULL)
	{
		interactive_server->deinitialize();
		delete interactive_server;
		interactive_server = NULL;	
	}
// Stop a keep-alive timer
	stop_keepalive_timer();
// Close the connection
	unsigned short ret = stop_connection();
// Stop the event thread
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}

	return ret;
}

// void ClusterMgr::notify_exit(unsigned short exit_reason)
// {
// 	WRITE_FORMAT_DEBUG("Notify the parent it's time to leave, exit reason: %s", GetErrorDescription(exit_reason));

// 	pthread_mutex_lock(&mtx_runtime_ret);
// 	runtime_ret = exit_reason;
// 	pthread_cond_signal(&cond_runtime_ret);
// 	pthread_mutex_unlock(&mtx_runtime_ret);
// }

// void* ClusterMgr::thread_handler(void* pvoid)
// {
// 	ClusterMgr* pthis = (ClusterMgr*)pvoid;
// 	assert(pthis != NULL && "pvoid should NOT be NULL");
// 	pthis->runtime_ret = pthis->thread_handler_internal();

// 	pthread_exit((CHECK_SUCCESS(pthis->runtime_ret) ? NULL : (void*)GetErrorDescription(pthis->runtime_ret)));
// }

// unsigned short ClusterMgr::thread_handler_internal()
// {
// 	unsigned short ret = RET_SUCCESS;

// 	pthread_mutex_lock(&mtx_runtime_ret);
// 	pthread_cond_wait(&cond_runtime_ret, &mtx_runtime_ret);
// 	WRITE_DEBUG("Notify the parent it's time to leave......");
// 	ret = deinitialize();
// 	pthread_mutex_unlock(&mtx_runtime_ret);

// 	return ret;
// }

unsigned short ClusterMgr::set_cluster_ip(const char* ip)
{
	if (ip == NULL)
	{
		WRITE_DEBUG("ip should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	if (cluster_ip != NULL)
		free(cluster_ip);
	cluster_ip = strdup(ip);
	return RET_SUCCESS;
}

unsigned short ClusterMgr::transmit_text(const char* data, const char* remote_ip)
{
	if (node_type == NONE)
	{
		WRITE_ERROR("node_type should NOT be NONE");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	else if (node_type == FOLLOWER)
	{
		if (remote_ip != NULL)
		{
			WRITE_ERROR("remote_ip should be NULL in follower");
			return RET_FAILURE_INVALID_ARGUMENT;
		}
	}
	assert(cluster_node != NULL && "cluster_node shuold NOT be NULL");
	return cluster_node->send(MSG_TRANSMIT_TEXT, (void*)data, (void*)remote_ip);
}

unsigned short ClusterMgr::set(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short ClusterMgr::get(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	case PARAM_CLUSTER_DETAIL:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		PCLUSTER_DETAIL_PARAM cluster_detail_param = (PCLUSTER_DETAIL_PARAM)param1;
    		assert(cluster_detail_param != NULL && "cluster_detail_param should NOT be NULL");
    		assert(cluster_node != NULL && "cluster_node should NOT be NULL");
		    ret = cluster_node->get(PARAM_NODE_ID, (void*)&cluster_detail_param->node_id);
			if (CHECK_FAILURE(ret))
				return ret;
		    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_detail_param->cluster_map);
			if (CHECK_FAILURE(ret))
				return ret;
			cluster_detail_param->node_type = node_type;
			assert(local_ip != NULL && "local_ip should NOT be NULL");
			strcpy(cluster_detail_param->local_ip, local_ip);
			if (node_type == NONE)
			{
    			WRITE_FORMAT_ERROR("The node_type[%d] is NOT defined", node_type);
    			return RET_FAILURE_INVALID_ARGUMENT;				
			}
			strcpy(cluster_detail_param->cluster_ip, (node_type == LEADER ? local_ip : cluster_ip));
    	}
    	break;
    	case PARAM_SYSTEM_INFO:
    	{
    		PSYSTEM_INFO_PARAM system_info_param = (PSYSTEM_INFO_PARAM)param1;
    		assert(system_info_param != NULL && "system_info_param should NOT be NULL");
// Get the node ip from the cluster map
			ClusterMap cluster_map;
		    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
			if (CHECK_FAILURE(ret))
				return ret;
			string node_ip;
			if (check_string_is_number(system_info_param->node_ip_buf))
			{
// Find the node IP from the node id
				int node_id = atoi(system_info_param->node_ip_buf);
				ret = cluster_map.get_node_ip(node_id, node_ip);
				if (CHECK_FAILURE(ret))
				{
	    			WRITE_FORMAT_ERROR("The node id[%d] does NOT exist in the cluster", node_id);
	    			return ret;		
				}
			}
			else
			{
				node_ip = string(system_info_param->node_ip_buf);
				int node_id;
				ret = cluster_map.get_node_id(node_ip, node_id);
				if (CHECK_FAILURE(ret))
				{
	    			WRITE_FORMAT_ERROR("The node ip[%s] does NOT exist in the cluster", node_ip.c_str());
	    			return ret;		
				}
			}
			// fprintf(stderr, "node_ip: %s\n", node_ip.c_str());
// Get the system info of the local node
    		if (strcmp(node_ip.c_str(), local_ip) == 0)
    		{
				ret = get_system_info(system_info_param->system_info);
				if (CHECK_FAILURE(ret))
					return ret;
    		}
    		else
    		{
// Get the system info of the remote node
// Only leader node can query the node system info in the cluster
	    		if (node_type != LEADER)
				{
	    			WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect, should be Leader", node_type);
	    			return RET_FAILURE_INCORRECT_OPERATION;				
				}
	    		assert(cluster_node != NULL && "cluster_node should NOT be NULL");
// Send the request
			    ret = cluster_node->send(MSG_QUERY_SYSTEM_INFO, (void*)&system_info_param->session_id, (void*)node_ip.c_str());
				if (CHECK_FAILURE(ret))
					return ret;
// Receive the response
				PNOTIFY_CFG notify_cfg = NULL;
				bool found = false;
				pthread_mutex_lock(&interactive_session_mtx[system_info_param->session_id]);
				pthread_cond_wait(&interactive_session_cond[system_info_param->session_id], &interactive_session_mtx[system_info_param->session_id]);
				// dump_interactive_session_data_list(system_info_param->session_id);
				std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_data_list[system_info_param->session_id];
				std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
				while (iter != interactive_session_data.end())
				{
					notify_cfg = (PNOTIFY_CFG)*iter;
					if (notify_cfg->get_notify_type() == NOTIFY_SYSTEM_INFO)
					{
						found = true;
						interactive_session_data.erase(iter);
						break;
					}
					iter++;
				}
				pthread_mutex_unlock(&interactive_session_mtx[system_info_param->session_id]);
    			if (!found)
    			{
	    			WRITE_FORMAT_ERROR("Fail to find Node[%s] system info for the session[%d]", system_info_param->node_ip_buf, system_info_param->session_id);
					return RET_FAILURE_NOT_FOUND;
				}
				PNOTIFY_SYSTEM_INFO_CFG notify_system_info_cfg = (PNOTIFY_SYSTEM_INFO_CFG)notify_cfg;
				assert(system_info_param->session_id == notify_system_info_cfg->get_session_id() && "The session ID is NOT identical");
				system_info_param->system_info = string(notify_system_info_cfg->get_system_info());
    			SAFE_RELEASE(notify_system_info_cfg)
    		}
    	}
    	break;
    	case PARAM_SIMULATOR_VERSION:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
			if (!simulator_installed)
			{
				WRITE_INFO("The simulator is NOT installed");
				return RET_WARN_SIMULATOR_NOT_INSTALLED;
			}
    		PSIMULATOR_VERSION_PARAM simulator_version_param = (PSIMULATOR_VERSION_PARAM)param1;
    		assert(simulator_version_param != NULL && "simulator_version_param should NOT be NULL");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			ret = simulator_handler->get_simulator_version(simulator_version_param->simulator_version, simulator_version_param->simulator_version_buf_size);
			if (CHECK_SUCCESS(ret))
			{
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					// ret = cluster_node->send(MSG_INSTALL_SIMULATOR, (void*)simulator_package_filepath);
				}
			}
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short ClusterMgr::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    // PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    // printf("notify_type: %d\n", notify_type);
    // assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
	switch (notify_type)
	{
// Synchronous event
		case NOTIFY_CHECK_KEEPALIVE:
		{
// Cautin: Don't carray any parameters, no need to pass PNOTIFY_XXX_CFG object
			check_keepalive();
		}
		break;
		case NOTIFY_INSTALL_SIMULATOR:
		{
     		assert(node_type != NONE && "node type should be NONE");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			PNOTIFY_SIMULATOR_INSTALL_CFG notify_simulator_install_cfg = (PNOTIFY_SIMULATOR_INSTALL_CFG)notify_param;
			assert(notify_simulator_install_cfg != NULL && "notify_simulator_install_cfg should NOT be NULL");
			const char* simulator_package_filepath = notify_simulator_install_cfg->get_simulator_package_filepath();
			ret = simulator_handler->install_simulator(simulator_package_filepath);
			if (CHECK_SUCCESS(ret))
			{
				simulator_installed = true;
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_INSTALL_SIMULATOR, (void*)simulator_package_filepath);
				}
			}
		}
		break;
		case NOTIFY_CONTROL_FAKE_ACSPT:
		{
			if (!simulator_installed)
			{
				WRITE_INFO("The simulator is NOT installed");
				return RET_WARN_SIMULATOR_NOT_INSTALLED;
			}
     		assert(node_type != NONE && "node type should be NONE");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			PNOTIFY_FAKE_ACSPT_CONTROL_CFG notify_fake_acspt_control_cfg = (PNOTIFY_FAKE_ACSPT_CONTROL_CFG)notify_param;
			assert(notify_fake_acspt_control_cfg != NULL && "notify_fake_acspt_control_cfg should NOT be NULL");
			FakeAcsptControlType fake_acspt_control_type = notify_fake_acspt_control_cfg->get_fake_acspt_control_type();
			switch(fake_acspt_control_type)
			{
				case FAKE_ACSPT_START:
				{
// Control simulator in the local node
					ret = simulator_handler->start_fake_acspt();
				}
				break;
				case FAKE_ACSPT_STOP:
				{
					ret = simulator_handler->stop_fake_acspt();
				}
				break;
				default:
				{
		    		static const int BUF_SIZE = 256;
		    		char buf[BUF_SIZE];
		    		snprintf(buf, BUF_SIZE, "Unknown simulator ap control type: %d", fake_acspt_control_type);
		    		throw std::invalid_argument(buf);
				}
				break;
			}
			if (CHECK_SUCCESS(ret) && node_type == LEADER)
			{
				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				ret = cluster_node->send(MSG_CONTROL_FAKE_ACSPT, (void*)&fake_acspt_control_type);
			}
		}
		break;
		case NOTIFY_CONTROL_FAKE_USREPT:
		{
			if (!simulator_installed)
			{
				WRITE_INFO("The simulator is NOT installed");
				return RET_WARN_SIMULATOR_NOT_INSTALLED;
			}
     		assert(node_type != NONE && "node type should be NONE");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			PNOTIFY_FAKE_USREPT_CONTROL_CFG notify_fake_usrept_control_cfg = (PNOTIFY_FAKE_USREPT_CONTROL_CFG)notify_param;
			assert(notify_fake_usrept_control_cfg != NULL && "notify_fake_usrept_control_cfg should NOT be NULL");
			FakeUsreptControlType fake_usrept_control_type = notify_fake_usrept_control_cfg->get_fake_usrept_control_type();
			switch(fake_usrept_control_type)
			{
				case FAKE_USREPT_START:
				{
					ret = simulator_handler->start_fake_usrept();
				}
				break;
				case FAKE_USREPT_STOP:
				{
					ret = simulator_handler->stop_fake_usrept();
				}
				break;
				default:
				{
		    		static const int BUF_SIZE = 256;
		    		char buf[BUF_SIZE];
		    		snprintf(buf, BUF_SIZE, "Unknown simulator ue control type: %d", fake_usrept_control_type);
		    		throw std::invalid_argument(buf);
				}
				break;
			}
			if (CHECK_SUCCESS(ret) && node_type == LEADER)
			{
				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				ret = cluster_node->send(MSG_CONTROL_FAKE_USREPT, (void*)&fake_usrept_control_type);
			}
		}
		break;
// Asynchronous event:
      	case NOTIFY_NODE_DIE:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == FOLLOWER && "node type should be FOLLOWER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_FORMAT_WARN("The leader[%s] dies, try to re-build the cluster", cluster_ip);
    		ret = notify_thread->add_event(notify_cfg);
    	}
		break;
		case NOTIFY_SYSTEM_INFO:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the system info for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
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


unsigned short ClusterMgr::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
      	case NOTIFY_NODE_DIE:
    	{
    		// string leader_ip((char*)notify_cfg->get_notify_param());
    		WRITE_DEBUG("Start to re-build the cluster......");
    		ret = rebuild_cluster();
    	}
    	break;
    	case NOTIFY_SYSTEM_INFO:
    	{
    		PNOTIFY_SYSTEM_INFO_CFG notify_system_info_cfg = (PNOTIFY_SYSTEM_INFO_CFG)notify_cfg;
			// assert(notify_system_info_cfg != NULL && "notify_system_info_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_system_info_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_system_info_cfg->get_session_id();
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_mtx[session_id]);
			interactive_session_data_list[session_id].push_back(notify_system_info_cfg);
// It's required to sleep for a while before notifying to accessing the list in another thread
			usleep(1000); // A MUST
			pthread_cond_signal(&interactive_session_cond[session_id]);
			pthread_mutex_unlock(&interactive_session_mtx[session_id]);
    	}
    	break;
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