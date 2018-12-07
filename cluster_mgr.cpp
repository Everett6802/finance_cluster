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
// #include "keepalive_timer_task.h"


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
// DECLARE_MSG_DUMPER_PARAM();

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
	local_ip(NULL),
	cluster_ip(NULL),
	// msg_trasnfer(NULL),
	node_type(NONE),
	cluster_node(NULL)
	// pid(0),
	// runtime_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()
}

ClusterMgr::~ClusterMgr()
{
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

	// list<char*>::iterator iter = server_list.begin();
	// while (iter != server_list.end())
	// 	delete [] (char*)*iter++;
	// server_list.clear();lr

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
	cluster_node = new LeaderNode(local_ip);
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

unsigned short ClusterMgr::become_follower()
{
	assert(local_ip != NULL && "local_ip should NOT be NULL");
	assert(cluster_ip != NULL && "cluster_ip should NOT be NULL");

	cluster_node = new FollowerNode(cluster_ip, local_ip);
	if (cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: cluster_node (Follower)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	unsigned short ret = cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = FOLLOWER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a Follower !!!", local_ip);
	return ret;
}

unsigned short ClusterMgr::start_connection()
{
	unsigned short ret = RET_SUCCESS;

	if (cluster_ip != NULL)
	{
		WRITE_FORMAT_DEBUG("Node[%s] Try to become follower of cluster[%s]...", local_ip, cluster_ip);
	// Try to find the follower node
		ret = become_follower();
		// if (CHECK_FAILURE(ret) || IS_TRY_CONNECTION_TIMEOUT(ret))
		// {
		// 	if (node_type != NONE)
		// 	{
		// 		WRITE_FORMAT_ERROR("Node[%s] type should be None at this moment", local_ip);
		// 		return RET_FAILURE_INCORRECT_OPERATION;
		// 	}
		// }
	}
	else
	{
		WRITE_FORMAT_DEBUG("Node[%s] Try to become leader...", local_ip);
// Try to find the leader node
		ret = become_leader();		
	}

	return ret;
}

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

unsigned short ClusterMgr::try_reconnection()
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
	else
	{
		if (cluster_map.is_empty())
		{
			WRITE_FORMAT_ERROR("Leader [%s] NEVER tries to re-connect", local_ip);
			return RET_FAILURE_RUNTIME;
		}		
	}
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
        if (leader_candidate_node_id == node_id)
        {
// Leader
        	if (cluster_ip != NULL)
        	{
        		free(cluster_ip);
        		cluster_ip = NULL;
        	}
        }
        else
        {
// Follower
        	set_cluster_ip(leader_candidate_node_ip.c_str());
        }
        ret = start_connection();
        if (CHECK_FAILURE(ret))
        {
        	if (IS_TRY_CONNECTION_TIMEOUT(ret))
        	{
        		WRITE_FORMAT_DEBUG("Node[%s] try to join the Cluster[%s], but time-out", local_ip, cluster_ip);
        	}
        	else
        	{
        	    break;	
        	}
        	
        }
        else
        {
        	WRITE_DEBUG("Rebuild the cluster successfully !!!");
        	break;
        }
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
					ret = try_reconnection();
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
// Define a leader/follower and establish the connection
	ret = start_connection();
	if (CHECK_FAILURE(ret))
		return ret;
// Start a keep-alive timer
	ret = start_keepalive_timer();
	if (CHECK_FAILURE(ret))
		return ret;

	return ret;
}

unsigned short ClusterMgr::deinitialize()
{
// Stop a keep-alive timer
	stop_keepalive_timer();

	unsigned short ret = RET_SUCCESS;
// Close the connection
	ret = stop_connection();
	if (CHECK_FAILURE(ret))
		return ret;

	return RET_SUCCESS;
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

// unsigned short ClusterMgr::start()
// {
// // Initialize
// 	unsigned short ret = initialize();
// // Start the thread of listening the connection requests
// 	if (CHECK_SUCCESS(ret))
// 	{
// 		mtx_runtime_ret = PTHREAD_MUTEX_INITIALIZER;
// 		cond_runtime_ret = PTHREAD_COND_INITIALIZER;
// 		if (pthread_create(&pid, NULL, thread_handler, this) != 0)
// 		{
// 			WRITE_FORMAT_ERROR("Fail to create a worker thread of listening the connection requests, due to: %s",strerror(errno));
// 			return RET_FAILURE_HANDLE_THREAD;
// 		}
// 	}

// 	return ret;
// }

// unsigned short ClusterMgr::wait_to_stop()
// {
// 	unsigned short ret = RET_SUCCESS;
// 	void* status;
// //	if (pid == 0)
// //		goto OUT;
// //
// //	int kill_ret = pthread_kill(pid, 0);
// //	if(kill_ret == ESRCH)
// //	{
// //		WRITE_WARN("The worker thread of waiting to stop did NOT exist......");
// //		ret = RET_SUCCESS;
// //		goto OUT;
// //	}
// //	else if(kill_ret == EINVAL)
// //	{
// //		WRITE_ERROR("The signal to the worker thread of waiting to stop is invalid");
// //		ret = RET_FAILURE_HANDLE_THREAD;
// //		goto OUT;
// //	}

// 	WRITE_DEBUG("Wait for the worker thread of waiting to stop's death...");
// 	pthread_join(pid, &status);
// 	if (status == NULL)
// 		WRITE_DEBUG("Wait for the worker thread of waiting to stop's death Successfully !!!");
// 	else
// 	{
// 		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of waiting to stop's death, due to: %s", (char*)status);
// 		ret = runtime_ret;
// 	}

// 	return ret;
// }

// unsigned short ClusterMgr::recv(const std::string ip, const std::string message)
// {
// 	return RET_SUCCESS;
// }

// unsigned short ClusterMgr::send(NotifyType message_type, void* param1, void* param2, void* param3)
// {
// 	switch (message_type)
// 	{
// 	case MSG_CHECK_KEEPALIVE:
// 		check_keepalive();
// 		break;
// 	default:
// 		WRITE_FORMAT_ERROR("Un-supported type: %d", message_type);
// 		return RET_FAILURE_IO_OPERATION;
// 	}
// 	return RET_SUCCESS;
// }

unsigned short ClusterMgr::notify(NotifyType notify_type, void* param)
{
	switch (notify_type)
	{
	case NOTIFY_CHECK_KEEPALIVE:
	{
		check_keepalive();
	}
	break;
	default:
		WRITE_FORMAT_ERROR("Un-supported type: %d", notify_type);
		return RET_FAILURE_IO_OPERATION;
	}
	return RET_SUCCESS;
}
