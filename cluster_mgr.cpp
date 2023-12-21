#include <signal.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/mman.h>
#include <fcntl.h>
// #include <arpa/inet.h>
// #include <sys/socket.h>
#include "cluster_mgr.h"
#include "leader_node.h"
#include "follower_node.h"
#include "file_sender.h"
#include "file_receiver.h"


using namespace std;

static unsigned char COMPONENT_MASK_INTERACTIVE_SESSION = 0x1 << 0;
static unsigned char COMPONENT_MASK_SIMULATOR_HANDLER = 0x1 << 1;
static unsigned char COMPONENT_MASK_SYSTEM_OPERATOR = 0x1 << 2;
static unsigned char COMPONENT_MASK_ALL = 0xFF;
static unsigned char COMPONENT_MASK_NOT_LOCAL_FOLLOWER = COMPONENT_MASK_INTERACTIVE_SESSION | COMPONENT_MASK_SIMULATOR_HANDLER;

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
const int ClusterMgr::WAIT_RETRY_CONNECTION_TIME = 3; // 3 seconds
const int ClusterMgr::TRY_TIMES = 3;
const int ClusterMgr::WAIT_MESSAGE_RESPONSE_TIME = 20; // 20 seconds
const int ClusterMgr::WAIT_FILE_TRANSFER_TIME = 60; // 60 seconds

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

		// fprintf(stderr, "conf_name: %s, conf_value: %s\n", conf_name, conf_value);
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
		else if (strcmp(conf_name, CONF_FIELD_LOCAL_CLUSTER) == 0)
		{
			char* conf_value_new = strdup(conf_value);
			assert (conf_value_new != NULL && "conf_value_new should NOT be NULL");
			char* conf_value_ptr = conf_value_new;
			while (*conf_value_ptr != '\0')
			{
				*conf_value_ptr = tolower(*conf_value_ptr);
				conf_value_ptr++;
			}
			// fprintf(stderr, "conf_value_new: %s\n", conf_value_new);
			if (strcmp(conf_value_new, "yes") == 0)
				local_cluster = true;
			else if (strcmp(conf_value_new, "no") == 0)
				local_cluster = false;
			else
			{
				WRITE_FORMAT_ERROR("Incorrect configuration value: %s, should be 'yes' or 'no'", conf_value_new);
				return RET_FAILURE_INCORRECT_CONFIG;				
			}
			if (conf_value_new != NULL)
			{
				free(conf_value_new);
				conf_value_new = NULL;
			}
			WRITE_FORMAT_DEBUG("CONF Name: %s, Value: %s", CONF_FIELD_LOCAL_CLUSTER, (local_cluster ? "yes" : "no"));
			// fprintf(stderr, "CONF Name: %s, Value: %s\n", CONF_FIELD_LOCAL_CLUSTER, (local_cluster ? "yes" : "no"));
		}
		else if (strcmp(conf_name, CONF_FIELD_SYSTEM_MONITOR_PERIOD) == 0)
		{
			system_monitor_period = atoi(conf_value);
			WRITE_FORMAT_DEBUG("CONF Name: %s, Value: %d", CONF_FIELD_SYSTEM_MONITOR_PERIOD, system_monitor_period);
		}
		else if (strcmp(conf_name, CONF_FIELD_SYNC_FOLDERPATH) == 0)
		{
			sync_folderpath = string(conf_value);
			WRITE_FORMAT_DEBUG("CONF Name: %s, Value: %s", CONF_FIELD_SYNC_FOLDERPATH, sync_folderpath.c_str());
		}
		else
		{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown config field: %s", conf_name);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
			throw invalid_argument(buf);
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

bool ClusterMgr::check_interface_exist(const char* network_interface)const
{
	assert(network_interface != NULL && "network_interface should NOT be NULL");
	static const char* LINUX_INTERFACE_PREFIX1 = "eth";
	static const int LINUX_INTERFACE_PREFIX1_LEN = strlen(LINUX_INTERFACE_PREFIX1);
	static const char* LINUX_INTERFACE_PREFIX2 = "enp";
	static const int LINUX_INTERFACE_PREFIX2_LEN = strlen(LINUX_INTERFACE_PREFIX2);
	static const char* LINUX_INTERFACE_PREFIX3 = "ens";
	static const int LINUX_INTERFACE_PREFIX3_LEN = strlen(LINUX_INTERFACE_PREFIX3);
	static const char* LINUX_INTERFACE_PREFIX_LIST[] = {
		LINUX_INTERFACE_PREFIX1,
		LINUX_INTERFACE_PREFIX2,
		LINUX_INTERFACE_PREFIX3
	};
	static const int LINUX_INTERFACE_PREFIX_LEN_LIST[] = {
		LINUX_INTERFACE_PREFIX1_LEN,
		LINUX_INTERFACE_PREFIX2_LEN,
		LINUX_INTERFACE_PREFIX3_LEN
	};
	static int LINUX_INTERFACE_PREFIX_LIST_SIZE = sizeof(LINUX_INTERFACE_PREFIX_LIST) / sizeof(LINUX_INTERFACE_PREFIX_LIST[0]);
	for (int i = 0; i < LINUX_INTERFACE_PREFIX_LIST_SIZE ; i++)
	{
		if (strncmp(network_interface, LINUX_INTERFACE_PREFIX_LIST[i], LINUX_INTERFACE_PREFIX_LEN_LIST[i]) == 0)
			return true;
	}
	return false;
}

unsigned short ClusterMgr::find_local_ip(bool need_check_network)
{
	if (local_cluster)
	{
		WRITE_ERROR("Should NOT find local IP for local cluster");
		return RET_FAILURE_INCORRECT_OPERATION;		
	}
	// static const char* LOCAL_INTERFACE_NAME = "lo";
	// static const char* LINUX_INTERFACE_PREFIX1 = "eth";
	// static const int LINUX_INTERFACE_PREFIX1_LEN = strlen(LINUX_INTERFACE_PREFIX1);
	// static const char* LINUX_INTERFACE_PREFIX2 = "enp";
	// static const int LINUX_INTERFACE_PREFIX2_LEN = strlen(LINUX_INTERFACE_PREFIX2);
	// static const char* LINUX_INTERFACE_PREFIX3 = "ens";
	// static const int LINUX_INTERFACE_PREFIX3_LEN = strlen(LINUX_INTERFACE_PREFIX3);
	unsigned short ret = RET_SUCCESS;

	map<string, string> interface_ip_map;
	ret = get_local_interface_ip(interface_ip_map);

	if (CHECK_FAILURE(ret))
		return ret;

	if (!need_check_network)
	{
		int cnt = 0;
		map<string, string>::iterator iter_cnt = interface_ip_map.begin();
		while (iter_cnt != interface_ip_map.end())
		{
			string interface = iter_cnt->first;
			// if (strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX1, LINUX_INTERFACE_PREFIX1_LEN) == 0
			//  || strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX2, LINUX_INTERFACE_PREFIX2_LEN) == 0
			//  || strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX3, LINUX_INTERFACE_PREFIX3_LEN) == 0)
			if (check_interface_exist(interface.c_str()))
				cnt++;
			iter_cnt++;	
		}
		if (cnt >= 2)
		{
			WRITE_FORMAT_WARN("The network interface[%d] is more than 2, fail to auto-select network interface", interface_ip_map.size());
			need_check_network = true;
		}
		else if (cnt == 0)
		{
			WRITE_ERROR("No interfaces are found");
			return RET_FAILURE_NOT_FOUND;
		}

	}
	if (!need_check_network)
		WRITE_DEBUG("Ignore checking network.....");
	else
		WRITE_DEBUG("Need to check network.....");

	bool found = false;
	map<string, string>::iterator iter = interface_ip_map.begin();
	while (iter != interface_ip_map.end())
	{
		string interface = iter->first;
      	string ip = iter->second;
      	IPv4Addr ipv4_addr(ip.c_str());

      	if (need_check_network)
      	{
	      	if (ipv4_addr.is_same_network(cluster_netmask_digits, cluster_network.c_str()))
      			found = true;
      	}
      	else
      	{
      		// if (strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX1, LINUX_INTERFACE_PREFIX1_LEN) == 0
      		//  || strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX2, LINUX_INTERFACE_PREFIX2_LEN) == 0
      		//  || strncmp(interface.c_str(), LINUX_INTERFACE_PREFIX3, LINUX_INTERFACE_PREFIX3_LEN) == 0)
      		if (check_interface_exist(interface.c_str()))
      			found = true;
      	}
      	if (found)
      	{
	      	local_token = strdup(ip.c_str());
	      	char* local_interface = strdup(interface.c_str());
	      	WRITE_FORMAT_DEBUG("The local IP: %s, local interface: %s", local_token, local_interface);
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
	local_cluster(true),
	local_token(NULL),
	cluster_token(NULL),
	node_type(NONE),
	file_tx_type(TX_NONE),
	cluster_node(NULL),
	file_tx(NULL),
	interactive_server(NULL),
	simulator_handler(NULL),
	simulator_installed(false)
{
	IMPLEMENT_MSG_DUMPER()
	// memset(interactive_session_event_count, 0x0, sizeof(int) / MAX_INTERACTIVE_SESSION);
	for (int i = 0 ; i < MAX_INTERACTIVE_SESSION ; i++)
	{
		interactive_session_param[i].event_count = 0;
		interactive_session_param[i].follower_node_amount = 0;
	}
}

ClusterMgr::~ClusterMgr()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in ClusterMgr::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (file_tx != NULL)
	{
		delete file_tx;
		file_tx = NULL;
	}
	if (cluster_node != NULL)
	{
		delete cluster_node;
		cluster_node = NULL;
	}

	if (cluster_token != NULL)
	{
		delete[] cluster_token;
		cluster_token = NULL;
	}

	if (local_token != NULL)
	{
		// delete[] local_token;
		free(local_token);
		local_token = NULL;
	}

	RELEASE_MSG_DUMPER()
}

void ClusterMgr::set_keepalive_timer_interval(int delay, int period)
{
// https://blog.xuite.net/lidj37/twblog/179517551
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
	cluster_node = new LeaderNode(this, local_token);
	if (cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: cluster_node (Leader)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	unsigned short ret = RET_SUCCESS;
	ret = cluster_node->set(PARAM_LOCAL_CLUSTER, (void*)&local_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = LEADER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a Leader !!!", local_token);
	return RET_SUCCESS;
}

unsigned short ClusterMgr::become_follower(bool need_rebuild_cluster)
{
	cluster_node = new FollowerNode(this, cluster_token, local_token);
	if (cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: cluster_node (Follower)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	unsigned short ret = RET_SUCCESS;
	ret = cluster_node->set(PARAM_LOCAL_CLUSTER, (void*)&local_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = cluster_node->set(PARAM_CONNECTION_RETRY, (void*)&need_rebuild_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
	node_type = FOLLOWER;
	WRITE_FORMAT_DEBUG("This Node[%s] is Follower !!!", local_token);
	return ret;
}

unsigned short ClusterMgr::become_file_sender()
{
	file_tx = new FileSender(this, local_token);
	if (file_tx == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: file_tx (sender)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	unsigned short ret = RET_SUCCESS;
	ret = file_tx->set(PARAM_LOCAL_CLUSTER, (void*)&local_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = file_tx->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	file_tx_type = TX_SENDER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a File Sender !!!", local_token);
	return RET_SUCCESS;
}

unsigned short ClusterMgr::become_file_receiver()
{
	file_tx = new FileReceiver(this, cluster_token, local_token);
	if (file_tx == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: file_tx (receiver)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	unsigned short ret = RET_SUCCESS;
	ret = file_tx->set(PARAM_LOCAL_CLUSTER, (void*)&local_cluster);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = file_tx->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	file_tx_type = TX_RECEIVER;
	WRITE_FORMAT_DEBUG("This Node[%s] is a File Receiver !!!", local_token);
	return RET_SUCCESS;
}

// unsigned short ClusterMgr::start_connection(bool need_rebuild_cluster)
// {
// 	unsigned short ret = RET_SUCCESS;

// 	if (cluster_token != NULL)
// 	{
// 		WRITE_FORMAT_DEBUG("Node[%s] Try to become follower of cluster[%s]...", local_token, cluster_token);
// // Try to become the follower node
// 		ret = become_follower();
// 		// if (CHECK_FAILURE(ret) || IS_TRY_CONNECTION_TIMEOUT(ret))
// 		// {
// 		// 	if (node_type != NONE)
// 		// 	{
// 		// 		WRITE_FORMAT_ERROR("Node[%s] type should be None at this moment", local_token);
// 		// 		return RET_FAILURE_INCORRECT_OPERATION;
// 		// 	}
// 		// }
// 	}
// 	else
// 	{
// 		WRITE_FORMAT_DEBUG("Node[%s] Try to become leader...", local_token);
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
			WRITE_FORMAT_ERROR("Error occur while closing the %s[%s]", (is_leader() ? "Leader" : "Follower"), local_token);
			return ret;
		}
		delete cluster_node;
		cluster_node = NULL;
		node_type = NONE;
	}

	return RET_SUCCESS;
}

unsigned short ClusterMgr::close_console()
{
	bool local_follower = false;
	if (local_cluster)
		is_local_follower(local_follower);
	if (!local_follower)
	{
		static string close_console_message = "Switch Rule: Follower -> Leader\nThe session will be closed due to authority change\nPlease reconnect...\n";
		assert(interactive_server != NULL && "interactive_server should NOT be NULL");
		WRITE_FORMAT_DEBUG("Close the console seesion in the Node[%s]...", local_token);
		interactive_server->print_console(close_console_message);
		usleep(300000);
		// interactive_server->deinitialize();
		// delete interactive_server;
		// interactive_server = NULL;
		deinitialize_components(COMPONENT_MASK_INTERACTIVE_SESSION);
	}
	return RET_SUCCESS;
}

unsigned short ClusterMgr::rebuild_cluster(int new_leader_node_id)
{
	if (node_type == LEADER)
	{
		WRITE_FORMAT_ERROR("Leader [%s] NEVER tries to re-connect", local_token);
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	assert(cluster_token != NULL && "cluster_token should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
// Get the cluster map from the follower
	ClusterMap cluster_map;
    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
	if (CHECK_FAILURE(ret))
		return ret;
	if (cluster_map.is_empty())
	{
		WRITE_FORMAT_ERROR("The cluster map in Follower[%s] is empty", local_token);
		return RET_FAILURE_RUNTIME;
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

// Pops up the first node: Leader
	int first_node_id;
	std::string first_node_token;
	ret = cluster_map.get_first_node(first_node_id, first_node_token);
	if (CHECK_FAILURE(ret))
		return ret;
	string cluster_token_string(cluster_token);
	assert(strcmp(first_node_token.c_str(), cluster_token) == 0 && "The first node in cluster should be Leader");
	assert(!cluster_map.is_empty() && "Cluster map should NOT be empty");

	if (new_leader_node_id != -1)
	{
// User assign a specific FOLLOWER as the new LEADER. 
// Modify the cluster map, so that the sepecific FOLLOWER becoms the leader candidate
        ret = cluster_map.set_first_node(new_leader_node_id);
        if (CHECK_FAILURE(ret))
        {
        	WRITE_FORMAT_ERROR("Fails to set the new Leader: %d in the cluster map, due to: %s", new_leader_node_id, GetErrorDescription(ret));
        	return ret;
        }
	}
// In algorithm, select the fisrt FOLLOWER as the next new LEADER
    int leader_candidate_node_id;
    string leader_candidate_node_token;
    ret = cluster_map.get_first_node(leader_candidate_node_id, leader_candidate_node_token);
    if (CHECK_FAILURE(ret))
    {
       	WRITE_ERROR("Fails to get the candidate of the Leader in the cluster map");
        return ret;
    }

// Try to re-establish the cluster from the cluster map
        // fprintf(stderr, "ID: %d candidate: id: %d, ip: %s\n", node_id, leader_candidate_node_id, leader_candidate_node_ip.c_str());
    if (leader_candidate_node_id == node_id)
    {
// Leader
		WRITE_FORMAT_DEBUG("Node[%s] try to becomme the Leader in the Cluster......", local_token);
		if (cluster_token != NULL)
		{
        	free(cluster_token);
        	cluster_token = NULL;
		}
// Switch node's rule. The console should be closed. Notify the user to reconnect the console...
		close_console();
// Switch to leader and re-initialize the required components
		ret = become_leader();
        if (CHECK_FAILURE(ret))
			return ret;
		// if (CHECK_SUCCESS(ret))
		// {
  //       	assert(interactive_server == NULL && "interactive_server should be NULL");
  //       	WRITE_FORMAT_DEBUG("[%s] Re-Initialize the session server......", local_token);
  //       	interactive_server = new InteractiveServer(this);
  //       	if (interactive_server == NULL)
		// 		throw bad_alloc();
  //       	ret = interactive_server->initialize(system_monitor_period);
  //       	if (CHECK_FAILURE(ret))
		// 		return ret;
		// }
		initialize_components(COMPONENT_MASK_NOT_LOCAL_FOLLOWER);
    }
    else
    {
// Follower
	    WRITE_FORMAT_DEBUG("Node[%s] try to join the Cluster[%s]......", local_token, cluster_token);
		srand((unsigned)time(NULL));
		int rand_num = rand() % 13 + 1;
		usleep(rand_num * 100000);
		if (cluster_token != NULL)
			free(cluster_token);
		cluster_token = strdup(leader_candidate_node_token.c_str());
		ret = become_follower(true);
        if (CHECK_FAILURE(ret))
			return ret;
		if (local_cluster)
			deinitialize_components(COMPONENT_MASK_NOT_LOCAL_FOLLOWER);
		else
    		initialize_components(COMPONENT_MASK_NOT_LOCAL_FOLLOWER);

    }

	// // fprintf(stderr, "cluster_token: %s, local_token: %s\n", cluster_token, local_token);
	// if (local_cluster && node_type == LEADER)
	// {
	// 	ret = initialize_components();
	// 	if (CHECK_FAILURE(ret))
	// 		return ret;
	// }
    if (CHECK_FAILURE(ret))
    	WRITE_FORMAT_ERROR("Node[%s] fails to rebuild the cluster, due to: %s", local_token, GetErrorDescription(ret));
	return ret;
}

unsigned short ClusterMgr::initialize_components(unsigned short component_mask)
{
	unsigned short ret= RET_SUCCESS;
	if (component_mask & COMPONENT_MASK_INTERACTIVE_SESSION)
	{
// Initialize the session server
		WRITE_FORMAT_DEBUG("[%s] Initialize the session server......", local_token);
		// assert(interactive_server == NULL && "interactive_server should be NULL");
		if (interactive_server != NULL)
			deinitialize_components(COMPONENT_MASK_INTERACTIVE_SESSION);
		interactive_server = new InteractiveServer(this);
		if (interactive_server == NULL)
			throw bad_alloc();
		ret = interactive_server->initialize(system_monitor_period);
		if (CHECK_FAILURE(ret))
			return ret;
	}
	if (component_mask & COMPONENT_MASK_SIMULATOR_HANDLER)
	{
// Initialize the simulator handler
		WRITE_FORMAT_DEBUG("[%s] Initialize the simulator handler......", local_token);
		// assert(simulator_handler == NULL && "simulator_handler should be NULL");
		if (simulator_handler != NULL)
			deinitialize_components(COMPONENT_MASK_SIMULATOR_HANDLER);
		simulator_handler = new SimulatorHandler(this);
		if (simulator_handler == NULL)
			throw bad_alloc();
		ret = simulator_handler->initialize();
		if (CHECK_FAILURE(ret))
			return ret;
		simulator_installed = simulator_handler->is_simulator_installed();
		WRITE_INFO((simulator_installed ? "The simulator is installed" : "The simulator is NOT installed"));
	}
// Initialize the system operater
	if (component_mask & COMPONENT_MASK_SYSTEM_OPERATOR)
	{
		WRITE_FORMAT_DEBUG("[%s] Initialize the system operater......", local_token);
		// assert(system_operator == NULL && "system_operator should be NULL");
		if (system_operator != NULL)
			deinitialize_components(COMPONENT_MASK_SYSTEM_OPERATOR);
		system_operator = new SystemOperator(this);
		if (system_operator == NULL)
			throw bad_alloc();
		ret = system_operator->initialize(cluster_network.c_str(), cluster_netmask_digits);
		if (CHECK_FAILURE(ret))
			return ret;
	}
	return ret;
}

unsigned short ClusterMgr::deinitialize_components(unsigned short component_mask)
{
	unsigned short ret= RET_SUCCESS;
	if (component_mask & COMPONENT_MASK_INTERACTIVE_SESSION)
	{
// Deinitialize the session server
		WRITE_FORMAT_DEBUG("[%s] De-Initialize the session server......", local_token);
		if (interactive_server != NULL)
		{
			interactive_server->deinitialize();
			delete interactive_server;
			interactive_server = NULL;	
		}
	}
	if (component_mask & COMPONENT_MASK_SIMULATOR_HANDLER)
	{
// Deinitialize the simulator handler
		WRITE_FORMAT_DEBUG("[%s] De-Initialize the simulator handler......", local_token);
		if (simulator_handler != NULL)
		{
			simulator_handler->deinitialize();
			delete simulator_handler;
			simulator_handler = NULL;	
		}	
	}
	if (system_operator == NULL)
	{
// DeInitialize the system operater
		WRITE_FORMAT_DEBUG("[%s] De-Initialize the system operater......", local_token);
		if (system_operator != NULL)
		{
			system_operator->deinitialize();
			delete system_operator;
			system_operator = NULL;	
		}
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
					WRITE_FORMAT_ERROR("Error occurs while checking keep-alive on the client side, due to: %s", GetErrorDescription(ret));
					// notify_exit(ret);
					// return;
					FPRINT_ERROR("Follower[%s] keep-alive time-out, due to: %s\n", local_token, GetErrorDescription(ret));
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
						FPRINT_ERROR("Node[%s] fails to re-connect, due to: %s\n", local_token, GetErrorDescription(ret));
						raise(SIGTERM);
					}
// Start a keep-alive timer
					ret = start_keepalive_timer();
					if (CHECK_FAILURE(ret))
					{
						// notify_exit(ret);
						// return;
						FPRINT_ERROR("Node[%s] fails to start keep-alive timer, due to: %s\n", local_token, GetErrorDescription(ret));
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
				WRITE_FORMAT_ERROR("Termiate the Leader[%s] due to: %s", local_token, GetErrorDescription(ret));
				// notify_exit(ret);
				// return;
				FPRINT_ERROR("Leader[%s] fails to check keep-alive, due to: %s\n", local_token, GetErrorDescription(ret));
				raise(SIGTERM);
			}
		}
	}
}

void ClusterMgr::dump_interactive_session_data_list(int session_id)const
{
	fprintf(stderr, "The interactive session[%d] data:\n", session_id);
	const std::list<PNOTIFY_CFG>& interactive_session_data_list = interactive_session_param[session_id].data_list;
	std::list<PNOTIFY_CFG>::const_iterator iter = interactive_session_data_list.begin();
	while (iter != interactive_session_data_list.end())
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
// Find local token
	if (local_token == NULL)
	{
		if (local_cluster)
		{
			char local_token_tmp[LOCAL_CLUSTER_SHM_BUFSIZE];
			// srand(time(NULL));   // Initialization, should only be called once.
			// snprintf(local_token_tmp, LOCAL_CLUSTER_SHM_BUFSIZE, LOCAL_CLUSTER_TOKEN_SHM_FORMOAT, rand() % 100000);
			snprintf(local_token_tmp, LOCAL_CLUSTER_SHM_BUFSIZE, LOCAL_CLUSTER_TOKEN_SHM_FORMOAT, getpid());
			local_token = strdup(local_token_tmp);
		}
		else
		{
			ret  = find_local_ip();
			if (CHECK_FAILURE(ret))
				return ret;
			// WRITE_FORMAT_DEBUG("The local IP of this Node: %s", local_token);
			if (cluster_token != NULL)
			{
// Check if local_token and cluster_token are in the same network
		      	IPv4Addr ipv4_addr(cluster_token);
		      	if (!ipv4_addr.is_same_network(cluster_netmask_digits, cluster_network.c_str()))
		      	{
		      		WRITE_FORMAT_ERROR("The local IP[%s] and cluster IP[%s] are NOT in the same network[%s/%s]", local_token, cluster_token, cluster_network.c_str(), cluster_netmask_digits);
		      		return RET_FAILURE_INCORRECT_CONFIG;
		      	}
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
	// fprintf(stderr, "cluster_token: %s, local_token: %s\n", cluster_token, local_token);
	bool local_follower = false;
	if (local_cluster)
	{
		ret = is_local_follower(local_follower);
		if (CHECK_FAILURE(ret))
			return ret;
		if (local_follower)
		{
			// printf("shm_open: %s, read only !!!\n", LOCAL_CLUSTER_SHM_FILENAME);
			int shm_fd = shm_open(LOCAL_CLUSTER_SHM_FILENAME, O_RDONLY, 0666);
		  	if (shm_fd < 0) 
		  	{
		    	WRITE_FORMAT_ERROR("shm_open() fails, due to: %s", strerror(errno));
		    	return RET_FAILURE_SYSTEM_API;
		  	}
		  	char *cluster_token_data = (char *)mmap(0, LOCAL_CLUSTER_SHM_BUFSIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
		  	WRITE_FORMAT_DEBUG("cluster token, mapped address: %p, data: %s", &cluster_token_data, cluster_token_data);
			cluster_token = strdup(cluster_token_data);
		  	munmap(cluster_token_data, LOCAL_CLUSTER_SHM_BUFSIZE);
		  	close(shm_fd);

			WRITE_DEBUG("Node Try to become follower of cluster...(LOCAL)");
			ret = become_follower();
			// init_components = false;
		}
		else
		{
			WRITE_DEBUG("Node Try to become leader...(LOCAL)");
			ret = become_leader();	
		}
	}
	else
	{
		if (cluster_token != NULL)
		{
			WRITE_FORMAT_DEBUG("Node[%s] Try to become follower of cluster[%s]...", local_token, cluster_token);
			ret = become_follower();
		}
		else
		{
			WRITE_FORMAT_DEBUG("Node[%s] Try to become leader...", local_token);
			ret = become_leader();	
		}
	}
	if (CHECK_FAILURE(ret))
		return ret;
// Start a keep-alive timer
	ret = start_keepalive_timer();
	if (CHECK_FAILURE(ret))
		return ret;
	unsigned short component_mask = local_follower ? COMPONENT_MASK_SYSTEM_OPERATOR : COMPONENT_MASK_ALL;
	// printf("local_follower: %s, component_mask: %d", (local_follower ? "True" : "False"), component_mask);
	ret = initialize_components(component_mask);
	if (CHECK_FAILURE(ret))
		return ret;
	return ret;
}

unsigned short ClusterMgr::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	ret = deinitialize_components(COMPONENT_MASK_ALL);
// // Deinitialize the system operator
// 	if (system_operator != NULL)
// 	{
// 		system_operator->deinitialize();
// 		delete system_operator;
// 		system_operator = NULL;	
// 	}
// // Deinitialize the simulator handler
// 	if (simulator_handler != NULL)
// 	{
// 		simulator_handler->deinitialize();
// 		delete simulator_handler;
// 		simulator_handler = NULL;	
// 	}
// // Deinitialize the session server
// 	if (interactive_server != NULL)
// 	{
// 		interactive_server->deinitialize();
// 		delete interactive_server;
// 		interactive_server = NULL;	
// 	}
// Stop a keep-alive timer
	stop_keepalive_timer();
// Close the connection
	ret = stop_connection();
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

unsigned short ClusterMgr::set_cluster_token(const char* token)
{
	assert(token != NULL && "token should NOT be NULL");
	// if (local_cluster)
	// {
	// 	if (token != NULL)
	// 	{
	// 		WRITE_ERROR("token should be NULL");
	// 		return RET_FAILURE_INVALID_ARGUMENT;
	// 	}
	// }
	// else
	// {
	// 	if (token == NULL)
	// 	{
	// 		WRITE_ERROR("token should NOT be NULL");
	// 		return RET_FAILURE_INVALID_ARGUMENT;
	// 	}
	// 	if (cluster_token != NULL)
	// 		free(cluster_token);
	// 	cluster_token = strdup(token);
	// }
	cluster_token = strdup(token);
	if (cluster_token == NULL)
		throw bad_alloc();

	return RET_SUCCESS;
}

unsigned short ClusterMgr::is_local_follower(bool& local_follower) const
{
	unsigned short ret = RET_SUCCESS;
	local_follower = false;
	if (local_cluster)
	{
		int process_count = 0;
		ret = get_process_count(PROCESS_NAME, process_count);
		if (CHECK_FAILURE(ret))
			return ret;
		assert(process_count != 0 && "process_count should NOT be 0");
		if (process_count > 1)
			local_follower = true;
	}
	return ret;
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
    	case PARAM_FILE_TRANSFER:
    	{
// // Only leader can do the file transfer to the follower
// 	    	if (node_type != LEADER)
// 			{
// 	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect, should be Leader", node_type);
// 	    		return RET_FAILURE_INCORRECT_OPERATION;
// 			}
        	if (param1 == NULL || param2 == NULL)
    		{
    			WRITE_ERROR("The param1/param2 should NOT be NULL");
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
	    	assert(file_tx == NULL && "file_tx should be NULL");
	    	unsigned short ret = RET_SUCCESS;
	    	PCLUSTER_FILE_TRANSFER_PARAM cluster_file_transfer_param = (PCLUSTER_FILE_TRANSFER_PARAM)param1;
	    	assert(cluster_file_transfer_param != NULL && "cluster_file_transfer_param should NOT be NULL");
	    	const char* filepath = (const char*)param2;
	    	assert(filepath != NULL && "filepath should NOT be NULL");

		    int cluster_node_amount;
			ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
			if (CHECK_FAILURE(ret))
				return ret;
			assert(cluster_node_amount != 0 && "cluster_node_amount should NOT be 0");
			// printf("Cluster Node Count: %d\n", cluster_node_amount);
			if (cluster_node_amount == 1)
			{
				WRITE_FORMAT_ERROR("No follwer nodes in the cluster, no need to transfer the file: %s", filepath);
				return RET_SUCCESS;
			}
// Start the file transfer sender
			FileTransferParam file_transfer_param;
			file_transfer_param.session_id = cluster_file_transfer_param->session_id;
			file_transfer_param.filepath = new char[strlen(filepath) + 1];
			if (file_transfer_param.filepath == NULL)
				throw bad_alloc();
			memset(file_transfer_param.filepath, 0x0, sizeof(char) * (strlen(filepath) + 1));
			strcpy(file_transfer_param.filepath, filepath);
			WRITE_FORMAT_DEBUG("Session[%d]: Transfer the file[%s] to %d follower(s)", cluster_file_transfer_param->session_id, filepath, cluster_node_amount - 1);
			ret = become_file_sender();
			if (CHECK_FAILURE(ret))
				return ret;
			ret = file_tx->set(PARAM_FILE_TRANSFER, (void*)&file_transfer_param);
			if (CHECK_FAILURE(ret))
				return ret;
// Reset the counter 
			pthread_mutex_lock(&interactive_session_param[cluster_file_transfer_param->session_id].mtx);
			interactive_session_param[cluster_file_transfer_param->session_id].follower_node_amount = cluster_node_amount - 1;
			interactive_session_param[cluster_file_transfer_param->session_id].event_count = 0;
			pthread_mutex_unlock(&interactive_session_param[cluster_file_transfer_param->session_id].mtx);
// Nodify the remote Node
			usleep(100000);
			ret = cluster_node->set(PARAM_FILE_TRANSFER, (void*)&file_transfer_param);
			if (CHECK_FAILURE(ret))
				return ret;
// Receive the response
			bool found = false;
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += WAIT_FILE_TRANSFER_TIME;
			pthread_mutex_lock(&interactive_session_param[cluster_file_transfer_param->session_id].mtx);
			int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[cluster_file_transfer_param->session_id].cond, &interactive_session_param[cluster_file_transfer_param->session_id].mtx, &ts);
// Stop the listening thread
			// ret = cluster_node->set(PARAM_FILE_TRANSFER_DONE);
			ret = file_tx->set(PARAM_FILE_TRANSFER_DONE);
			if (CHECK_FAILURE(ret))
				return ret;

			if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
			{
		    	WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
				return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
			}
					// dump_interactive_session_data_list(session_id);
			std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[cluster_file_transfer_param->session_id].data_list;
			std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
			std::list<PNOTIFY_CFG> interactive_session_file_transfer_data;
			while (iter != interactive_session_data.end())
			{
				PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
				if (notify_cfg->get_notify_type() == NOTIFY_COMPLETE_FILE_TRANSFER)
				{
					interactive_session_file_transfer_data.push_back(notify_cfg);
					interactive_session_data.erase(iter);
					if ((int)interactive_session_file_transfer_data.size() == interactive_session_param[cluster_file_transfer_param->session_id].follower_node_amount)
					{
						found = true;
						break;
					}
				}
				iter++;
			}
			pthread_mutex_unlock(&interactive_session_param[cluster_file_transfer_param->session_id].mtx);
	    	if (!found)
	    	{
		    	WRITE_FORMAT_ERROR("Lack of file transfer complete notification from some followers in the session[%d], expected: %d, actual: %d", cluster_file_transfer_param->session_id, cluster_node_amount - 1, interactive_session_file_transfer_data.size());
				return RET_FAILURE_NOT_FOUND;
			}
			std::list<PNOTIFY_CFG>::iterator iter_file_transfer= interactive_session_file_transfer_data.begin();
			while (iter_file_transfer != interactive_session_file_transfer_data.end())
			{
				PNOTIFY_FILE_TRANSFER_COMPLETE_CFG notify_file_transfer_cfg = (PNOTIFY_FILE_TRANSFER_COMPLETE_CFG)*iter_file_transfer;
				assert(cluster_file_transfer_param->session_id == notify_file_transfer_cfg->get_session_id() && "The session ID is NOT identical");
				// string node_ip;
				// ret = cluster_node->get(PARAM_CLUSTER_ID2IP, (void*)&notify_file_transfer_cfg->get_cluster_id(), (void*)&node_ip);
				if (CHECK_FAILURE(ret))
					return ret;
				char buf[DEF_STRING_SIZE];
				if (CHECK_SUCCESS(notify_file_transfer_cfg->get_return_code()))
				{
					static const char* success_str = "Success";
					// static int success_str_len = strlen(success_str);
					strcpy(buf, success_str);
				}
				else
					snprintf(buf, DEF_STRING_SIZE, "Fail, due to: %s", GetErrorDescription(notify_file_transfer_cfg->get_return_code()));
				cluster_file_transfer_param->cluster_data_map[notify_file_transfer_cfg->get_cluster_id()] = string(buf);					
				iter_file_transfer++;
				SAFE_RELEASE(notify_file_transfer_cfg)
			}
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
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
    	case PARAM_NODE_TYPE:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		*((NodeType*)param1) = node_type;
    	}
    	break;
    	case PARAM_CLUSTER_MAP:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		PCLUSTER_MAP cluster_map = (ClusterMap*)param1;
 		    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)cluster_map);
			if (CHECK_FAILURE(ret))
				return ret;
    	}
    	break;
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
			assert(local_token != NULL && "local_token should NOT be NULL");
			strcpy(cluster_detail_param->local_token, local_token);
			if (node_type == NONE)
			{
    			WRITE_FORMAT_ERROR("The node_type[%d] is NOT defined", node_type);
    			return RET_FAILURE_INVALID_ARGUMENT;				
			}
			strcpy(cluster_detail_param->cluster_token, (node_type == LEADER ? local_token : cluster_token));
    	}
    	break;
    	case PARAM_SYSTEM_INFO:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
   			assert(system_operator != NULL && "system_operator should NOT be NULL");

			if (node_type == LEADER)
			{
// Leader node
	    		PCLUSTER_SYSTEM_INFO_PARAM cluster_system_info_param = (PCLUSTER_SYSTEM_INFO_PARAM)param1;
	    		assert(cluster_system_info_param != NULL && "cluster_system_info_param should NOT be NULL");
				PSYSTEM_INFO_PARAM system_info_param = new SystemInfoParam();
				if (system_info_param  == NULL)
					throw bad_alloc();
				ret = system_operator->get_system_info(system_info_param->system_info);
				// printf("* system_info: %s\n", system_info_param->system_info.c_str());
				if (CHECK_FAILURE(ret))
					return ret;
// Cluster ID of the Leader node: 1
				cluster_system_info_param->cluster_data_map[1] = system_info_param->system_info;
				if (system_info_param != NULL)
				{
					delete system_info_param;
					system_info_param = NULL;
				}
				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				int cluster_node_amount;
			    ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
				if (CHECK_FAILURE(ret))
					return ret;
				// printf("Cluster Node Count: %d\n", cluster_node_amount);
				if (cluster_node_amount > 1)
				{
					int session_id = cluster_system_info_param->session_id;
// Not one node cluster, send notification to the followers
// Reset the counter 
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					interactive_session_param[session_id].follower_node_amount = cluster_node_amount - 1;
					interactive_session_param[session_id].event_count = 0;
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
// Send the request
				    ret = cluster_node->send(MSG_GET_SYSTEM_INFO, (void*)&session_id);
					if (CHECK_FAILURE(ret))
						return ret;
// Receive the response
					bool found = false;
				    struct timespec ts;
				    clock_gettime(CLOCK_REALTIME, &ts);
				    ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[session_id].cond, &interactive_session_param[session_id].mtx, &ts);
					if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
					{
		    			WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
						return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
					}
					// dump_interactive_session_data_list(session_id);
					std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[session_id].data_list;
					std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
					std::list<PNOTIFY_CFG> interactive_session_system_info_data;
					while (iter != interactive_session_data.end())
					{
						PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
						if (notify_cfg->get_notify_type() == NOTIFY_GET_SYSTEM_INFO)
						{
							// found = true;
							interactive_session_system_info_data.push_back(notify_cfg);
							interactive_session_data.erase(iter);
							if ((int)interactive_session_system_info_data.size() == interactive_session_param[session_id].follower_node_amount)
							{
								found = true;
								break;
							}
						}
						iter++;
					}
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
	    			if (!found)
	    			{
		    			WRITE_FORMAT_ERROR("Lack of system info from some followers in the session[%d], expected: %d, actual: %d", session_id, cluster_node_amount - 1, interactive_session_system_info_data.size());
						return RET_FAILURE_NOT_FOUND;
					}
					std::list<PNOTIFY_CFG>::iterator iter_system_info = interactive_session_system_info_data.begin();
					while (iter_system_info != interactive_session_system_info_data.end())
					{
						PNOTIFY_SYSTEM_INFO_CFG notify_system_info_cfg = (PNOTIFY_SYSTEM_INFO_CFG)*iter_system_info;
						assert(session_id == notify_system_info_cfg->get_session_id() && "The session ID is NOT identical");
						cluster_system_info_param->cluster_data_map[notify_system_info_cfg->get_cluster_id()] = string(notify_system_info_cfg->get_system_info());
						iter_system_info++;
						SAFE_RELEASE(notify_system_info_cfg)
					}
				}
			}
			else if (node_type == FOLLOWER)
			{
	    		PSYSTEM_INFO_PARAM system_info_param = (PSYSTEM_INFO_PARAM)param1;
	    		assert(system_info_param != NULL && "system_info_param should NOT be NULL");
				ret = system_operator->get_system_info(system_info_param->system_info);
				if (CHECK_FAILURE(ret))
					return ret;
			}
			else
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
			}
    	}
    	break;
//     	case PARAM_NODE_SYSTEM_INFO:
//     	{
//     		PSYSTEM_INFO_PARAM system_info_param = (PSYSTEM_INFO_PARAM)param1;
//     		assert(system_info_param != NULL && "system_info_param should NOT be NULL");
// // Get the node ip from the cluster map
// 			ClusterMap cluster_map;
// 		    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
// 			if (CHECK_FAILURE(ret))
// 				return ret;
// 			string node_ip;
// 			if (check_string_is_number(system_info_param->node_ip_buf))
// 			{
// // Find the node IP from the node id
// 				int node_id = atoi(system_info_param->node_ip_buf);
// 				ret = cluster_map.get_node_ip(node_id, node_ip);
// 				if (CHECK_FAILURE(ret))
// 				{
// 	    			WRITE_FORMAT_ERROR("The node id[%d] does NOT exist in the cluster", node_id);
// 	    			return ret;		
// 				}
// 			}
// 			else
// 			{
// 				node_ip = string(system_info_param->node_ip_buf);
// 				int node_id;
// 				ret = cluster_map.get_node_id(node_ip, node_id);
// 				if (CHECK_FAILURE(ret))
// 				{
// 	    			WRITE_FORMAT_ERROR("The node ip[%s] does NOT exist in the cluster", node_ip.c_str());
// 	    			return ret;		
// 				}
// 			}
// 			// fprintf(stderr, "node_ip: %s\n", node_ip.c_str());
// // Get the system info of the local node
//     		if (strcmp(node_ip.c_str(), local_token) == 0)
//     		{
// 				ret = get_system_info(system_info_param->system_info);
// 				if (CHECK_FAILURE(ret))
// 					return ret;
//     		}
//     		else
//     		{
// // Get the system info of the remote node
// // Only leader node can query the node system info in the cluster
// 	    		if (node_type != LEADER)
// 				{
// 	    			WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect, should be Leader", node_type);
// 	    			return RET_FAILURE_INCORRECT_OPERATION;				
// 				}
// 	    		assert(cluster_node != NULL && "cluster_node should NOT be NULL");
// // Send the request
// 			    ret = cluster_node->send(MSG_GET_SYSTEM_INFO, (void*)&system_info_param->session_id, (void*)node_ip.c_str());
// 				if (CHECK_FAILURE(ret))
// 					return ret;
// // Receive the response
// 				PNOTIFY_CFG notify_cfg = NULL;
// 				bool found = false;
// 				struct timespec ts;
// 				clock_gettime(CLOCK_REALTIME, &ts);
// 				ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
// 				pthread_mutex_lock(&interactive_session_param[system_info_param->session_id].mtx);
// 				// pthread_cond_wait(&interactive_session_param[system_info_param->session_id].cond, &interactive_session_param[system_info_param->session_id].mtx);
// 				int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[system_info_param->session_id].cond, &interactive_session_param[system_info_param->session_id].mtx, &ts);
// 				if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
// 				{
// 		    		WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
// 					return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
// 				}
// 				// dump_interactive_session_data_list(system_info_param->session_id);
// 				std::list<PNOTIFY_CFG>& interactive_session_data_list = interactive_session_param[system_info_param->session_id].data_list;
// 				std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data_list.begin();
// 				while (iter != interactive_session_data_list.end())
// 				{
// 					notify_cfg = (PNOTIFY_CFG)*iter;
// 					if (notify_cfg->get_notify_type() == NOTIFY_GET_SYSTEM_INFO)
// 					{
// 						found = true;
// 						interactive_session_data_list.erase(iter);
// 						break;
// 					}
// 					iter++;
// 				}
// 				pthread_mutex_unlock(&interactive_session_param[system_info_param->session_id].mtx);
//     			if (!found)
//     			{
// 	    			WRITE_FORMAT_ERROR("Fail to find Node[%s] system info for the session[%d]", system_info_param->node_ip_buf, system_info_param->session_id);
// 					return RET_FAILURE_NOT_FOUND;
// 				}
// 				PNOTIFY_SYSTEM_INFO_CFG notify_system_info_cfg = (PNOTIFY_SYSTEM_INFO_CFG)notify_cfg;
// 				assert(system_info_param->session_id == notify_system_info_cfg->get_session_id() && "The session ID is NOT identical");
// 				system_info_param->system_info = string(notify_system_info_cfg->get_system_info());
//     			SAFE_RELEASE(notify_system_info_cfg)
//     		}
//     	}
//     	break;
    	case PARAM_CONFIGURATION_SETUP:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		string& configuration_setup_string = *(string*)param1;
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
				configuration_setup_string += (string(conf_name) + string(": ") + string(conf_value) + string("\n"));
				if (line_tmp != NULL)
				{
					free(line_tmp);
					line_tmp = NULL;
				}
				iter++;
			}
			configuration_setup_string += string("\n");
    	}
    	break;
    	case PARAM_CONFIGURATION_VALUE:
    	{
        	if (param1 == NULL || param2 == NULL)
    		{
    			WRITE_ERROR("The param1/param2 should NOT be NULL");
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		const char* conf_name = (const char*)param1;
			if (strcmp(conf_name, CONF_FIELD_CLUSTER_NETWORK) == 0)
			{
				string& conf_value = *(string*)param2;
				conf_value = cluster_network;
			}
			else if (strcmp(conf_name, CONF_FIELD_CLUSTER_NETMASK_DIGITS) == 0)
			{
				int& conf_value = *(int*)param2;
				conf_value = cluster_netmask_digits;
			}
			else if (strcmp(conf_name, CONF_FIELD_LOCAL_CLUSTER) == 0)
			{
				bool& conf_value = *(bool*)param2;
				conf_value = local_cluster;
			}
			else if (strcmp(conf_name, CONF_FIELD_SYSTEM_MONITOR_PERIOD) == 0)
			{
				int& conf_value = *(int*)param2;
				conf_value = system_monitor_period;
			}
			else if (strcmp(conf_name, CONF_FIELD_SYNC_FOLDERPATH) == 0)
			{
				string& conf_value = *(string*)param2;
				conf_value = sync_folderpath;
			}
			else
			{
	    		static const int BUF_SIZE = 256;
	    		char buf[BUF_SIZE];
	    		snprintf(buf, BUF_SIZE, "Unknown config field: %s", conf_name);
	    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
				throw invalid_argument(buf);
			}
		}
    	break;
    	case PARAM_SYSTEM_MONITOR:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
   			assert(system_operator != NULL && "system_operator should NOT be NULL");

			if (node_type == LEADER)
			{
// Leader node
	    		PCLUSTER_SYSTEM_MONITOR_PARAM cluster_system_monitor_param = (PCLUSTER_SYSTEM_MONITOR_PARAM)param1;
	    		assert(cluster_system_monitor_param != NULL && "cluster_system_monitor_param should NOT be NULL");
				PSYSTEM_MONITOR_PARAM system_monitor_param = new SystemMonitorParam();
				if (system_monitor_param  == NULL)
					throw bad_alloc();
				ret = system_operator->get_system_monitor_data(system_monitor_param->system_monitor_data);
				// printf("* system_monitor: %s\n", system_monitor_param->system_monitor_data.c_str());
				if (CHECK_FAILURE(ret))
					return ret;
// Cluster ID of the Leader node: 1
				cluster_system_monitor_param->cluster_data_map[1] = system_monitor_param->system_monitor_data;
				if (system_monitor_param != NULL)
				{
					delete system_monitor_param;
					system_monitor_param = NULL;
				}
				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				int cluster_node_amount;
			    ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
				if (CHECK_FAILURE(ret))
					return ret;
				// printf("Cluster Node Count: %d\n", cluster_node_amount);
				if (cluster_node_amount > 1)
				{
					int session_id = cluster_system_monitor_param->session_id;
// Not one node cluster, send notification to the followers
// Reset the counter 
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					interactive_session_param[session_id].follower_node_amount = cluster_node_amount - 1;
					interactive_session_param[session_id].event_count = 0;
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
// Send the request
				    ret = cluster_node->send(MSG_GET_SYSTEM_MONITOR, (void*)&session_id);
					if (CHECK_FAILURE(ret))
						return ret;
// Receive the response
					bool found = false;
				    struct timespec ts;
				    clock_gettime(CLOCK_REALTIME, &ts);
				    ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[session_id].cond, &interactive_session_param[session_id].mtx, &ts);
					if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
					{
		    			WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
						return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
					}
					// dump_interactive_session_data_list(session_id);
					std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[session_id].data_list;
					std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
					std::list<PNOTIFY_CFG> interactive_session_system_monitor_data;
					while (iter != interactive_session_data.end())
					{
						PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
						if (notify_cfg->get_notify_type() == NOTIFY_GET_SYSTEM_MONITOR)
						{
							// found = true;
							interactive_session_system_monitor_data.push_back(notify_cfg);
							interactive_session_data.erase(iter);
							if ((int)interactive_session_system_monitor_data.size() == interactive_session_param[session_id].follower_node_amount)
							{
								found = true;
								break;
							}
						}
						iter++;
					}
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
	    			if (!found)
	    			{
		    			WRITE_FORMAT_ERROR("Lack of system monitor from some followers in the session[%d], expected: %d, actual: %d", session_id, cluster_node_amount - 1, interactive_session_system_monitor_data.size());
						return RET_FAILURE_NOT_FOUND;
					}
					std::list<PNOTIFY_CFG>::iterator iter_system_monitor = interactive_session_system_monitor_data.begin();
					while (iter_system_monitor != interactive_session_system_monitor_data.end())
					{
						PNOTIFY_SYSTEM_MONITOR_CFG notify_system_monitor_cfg = (PNOTIFY_SYSTEM_MONITOR_CFG)*iter_system_monitor;
						assert(session_id == notify_system_monitor_cfg->get_session_id() && "The session ID is NOT identical");
						cluster_system_monitor_param->cluster_data_map[notify_system_monitor_cfg->get_cluster_id()] = string(notify_system_monitor_cfg->get_system_monitor_data());
						iter_system_monitor++;
						SAFE_RELEASE(notify_system_monitor_cfg)
					}
				}
			}
			else if (node_type == FOLLOWER)
			{
	    		PSYSTEM_MONITOR_PARAM system_monitor_param = (PSYSTEM_MONITOR_PARAM)param1;
	    		assert(system_monitor_param != NULL && "system_monitor_param should NOT be NULL");
				ret = system_operator->get_system_monitor_data(system_monitor_param->system_monitor_data);
				if (CHECK_FAILURE(ret))
					return ret;
			}
			else
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
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

			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			if (node_type == LEADER)
			{
// Leader node
	    		PCLUSTER_SIMULATOR_VERSION_PARAM cluster_simulator_version_param = (PCLUSTER_SIMULATOR_VERSION_PARAM)param1;
	    		assert(cluster_simulator_version_param != NULL && "cluster_simulator_version_param should NOT be NULL");
				if (simulator_installed)
				{
					PSIMULATOR_VERSION_PARAM simulator_version_param = new SimulatorVersionParam(DEF_VERY_SHORT_STRING_SIZE);
					if (simulator_version_param  == NULL)
						throw bad_alloc();
					ret = simulator_handler->get_simulator_version(simulator_version_param->simulator_version, simulator_version_param->simulator_version_buf_size);
					if (CHECK_FAILURE(ret))
						return ret;
// Cluster ID of the Leader node: 1
					cluster_simulator_version_param->cluster_data_map[1] = string(simulator_version_param->simulator_version);
					if (simulator_version_param != NULL)
					{
						delete simulator_version_param;
						simulator_version_param = NULL;
					}
				}
				else
				{
					WRITE_INFO("The simulator is NOT installed");
					// return RET_WARN_SIMULATOR_NOT_INSTALLED;
// Cluster ID of the Leader node: 1
					cluster_simulator_version_param->cluster_data_map[1] = string("Not installed");
				}

				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				int cluster_node_amount;
			    ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
				if (CHECK_FAILURE(ret))
					return ret;
				// printf("Cluster Node Count: %d\n", cluster_node_amount);
				if (cluster_node_amount > 1)
				{
					int session_id = cluster_simulator_version_param->session_id;
// Not one node cluster, send notification to the followers
// Reset the counter 
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					interactive_session_param[session_id].follower_node_amount = cluster_node_amount - 1;
					interactive_session_param[session_id].event_count = 0;
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
// Send the request
				    ret = cluster_node->send(MSG_GET_SIMULATOR_VERSION, (void*)&session_id);
					if (CHECK_FAILURE(ret))
						return ret;
// Receive the response
					bool found = false;
				    struct timespec ts;
				    clock_gettime(CLOCK_REALTIME, &ts);
				    ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[session_id].cond, &interactive_session_param[session_id].mtx, &ts);
					if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
					{
		    			WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
						return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
					}
					// dump_interactive_session_data_list(session_id);
					std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[session_id].data_list;
					std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
					std::list<PNOTIFY_CFG> interactive_session_simulator_version_data;
					while (iter != interactive_session_data.end())
					{
						PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
						if (notify_cfg->get_notify_type() == NOTIFY_GET_SIMULATOR_VERSION)
						{
							// found = true;
							interactive_session_simulator_version_data.push_back(notify_cfg);
							interactive_session_data.erase(iter);
							if ((int)interactive_session_simulator_version_data.size() == interactive_session_param[session_id].follower_node_amount)
							{
								found = true;
								break;
							}
						}
						iter++;
					}
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
	    			if (!found)
	    			{
		    			WRITE_FORMAT_ERROR("Lack of simulator version from some followers in the session[%d], expected: %d, actual: %d", session_id, cluster_node_amount - 1, interactive_session_simulator_version_data.size());
						return RET_FAILURE_NOT_FOUND;
					}
					std::list<PNOTIFY_CFG>::iterator iter_simulator_version = interactive_session_simulator_version_data.begin();
					while (iter_simulator_version != interactive_session_simulator_version_data.end())
					{
						PNOTIFY_SIMULATOR_VERSION_CFG notify_simulator_version_cfg = (PNOTIFY_SIMULATOR_VERSION_CFG)*iter_simulator_version;
						assert(session_id == notify_simulator_version_cfg->get_session_id() && "The session ID is NOT identical");
						cluster_simulator_version_param->cluster_data_map[notify_simulator_version_cfg->get_cluster_id()] = string(notify_simulator_version_cfg->get_simulator_version());
						iter_simulator_version++;
						SAFE_RELEASE(notify_simulator_version_cfg)
					}
				}
			}
			else if (node_type == FOLLOWER)
			{
	    		PSIMULATOR_VERSION_PARAM simulator_version_param = (PSIMULATOR_VERSION_PARAM)param1;
	    		assert(simulator_version_param != NULL && "simulator_version_param should NOT be NULL");
				if (simulator_installed)
				{
					ret = simulator_handler->get_simulator_version(simulator_version_param->simulator_version, simulator_version_param->simulator_version_buf_size);
					if (CHECK_FAILURE(ret))
						return ret;
				}
				else
				{
					WRITE_INFO("The simulator is NOT installed");
					memset(simulator_version_param->simulator_version, 0x0, simulator_version_param->simulator_version_buf_size);
					snprintf(simulator_version_param->simulator_version, simulator_version_param->simulator_version_buf_size, "%s", "Not installed");
				}
			}
			else
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
			}
    	}
    	break;
    	case PARAM_FAKE_ACSPT_CONFIG_VALUE:
    	{
    		PFAKE_ACSPT_CONFIG_VALUE_PARAM fake_acspt_config_value_param = (PFAKE_ACSPT_CONFIG_VALUE_PARAM)param1;
    		assert(fake_acspt_config_value_param != NULL && "fake_acspt_config_value_param should NOT be NULL");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			if (node_type != LEADER)
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
			}
			ret = simulator_handler->get_fake_acspt_config_value(fake_acspt_config_value_param->config_list, fake_acspt_config_value_param->config_line_list);
    	}
    	break;
    	case PARAM_FAKE_ACSPT_STATE:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}

			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			if (node_type == LEADER)
			{
// Leader node
	    		PCLUSTER_FAKE_ACSPT_STATE_PARAM cluster_fake_acspt_state_param = (PCLUSTER_FAKE_ACSPT_STATE_PARAM)param1;
	    		assert(cluster_fake_acspt_state_param != NULL && "cluster_fake_acspt_state_param should NOT be NULL");
				if (simulator_installed)
				{
					PFAKE_ACSPT_STATE_PARAM fake_acspt_state_param = new FakeAcsptStateParam();
					if (fake_acspt_state_param  == NULL)
						throw bad_alloc();
					ret = simulator_handler->get_fake_acspt_state(fake_acspt_state_param->fake_acspt_state, fake_acspt_state_param->fake_acspt_state_buf_size);
					if (CHECK_FAILURE(ret))
						return ret;
					// printf("fake_acspt_state_param->fake_acspt_state: %s\n", fake_acspt_state_param->fake_acspt_state);
// Cluster ID of the Leader node: 1
					cluster_fake_acspt_state_param->cluster_data_map[1] = string(fake_acspt_state_param->fake_acspt_state);
					if (fake_acspt_state_param != NULL)
					{
						delete fake_acspt_state_param;
						fake_acspt_state_param = NULL;
					}
				}
				else
				{
					WRITE_INFO("The simulator is NOT installed");
					// return RET_WARN_SIMULATOR_NOT_INSTALLED;
// Cluster ID of the Leader node: 1
					cluster_fake_acspt_state_param->cluster_data_map[1] = string("Not installed");
				}

				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				int cluster_node_amount;
			    ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
				if (CHECK_FAILURE(ret))
					return ret;
				// printf("Cluster Node Count: %d\n", cluster_node_amount);
				if (cluster_node_amount > 1)
				{
					int session_id = cluster_fake_acspt_state_param->session_id;
// Not one node cluster, send notification to the followers
// Reset the counter 
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					interactive_session_param[session_id].follower_node_amount = cluster_node_amount - 1;
					interactive_session_param[session_id].event_count = 0;
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
// Send the request
				    ret = cluster_node->send(MSG_GET_FAKE_ACSPT_STATE, (void*)&session_id);
					if (CHECK_FAILURE(ret))
						return ret;
// Receive the response
					bool found = false;
				    struct timespec ts;
				    clock_gettime(CLOCK_REALTIME, &ts);
				    ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[session_id].cond, &interactive_session_param[session_id].mtx, &ts);
					if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
					{
		    			WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
						return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
					}
					// dump_interactive_session_data_list(session_id);
					std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[session_id].data_list;
					std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
					std::list<PNOTIFY_CFG> interactive_session_fake_acspt_state_data;
					while (iter != interactive_session_data.end())
					{
						PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
						if (notify_cfg->get_notify_type() == NOTIFY_GET_FAKE_ACSPT_STATE)
						{
							// found = true;
							interactive_session_fake_acspt_state_data.push_back(notify_cfg);
							interactive_session_data.erase(iter);
							if ((int)interactive_session_fake_acspt_state_data.size() == interactive_session_param[session_id].follower_node_amount)
							{
								found = true;
								break;
							}
						}
						iter++;
					}
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
	    			if (!found)
	    			{
		    			WRITE_FORMAT_ERROR("Lack of fake acspt state from some followers in the session[%d], expected: %d, actual: %d", session_id, cluster_node_amount - 1, interactive_session_fake_acspt_state_data.size());
						return RET_FAILURE_NOT_FOUND;
					}
					std::list<PNOTIFY_CFG>::iterator iter_fake_acspt_state = interactive_session_fake_acspt_state_data.begin();
					while (iter_fake_acspt_state != interactive_session_fake_acspt_state_data.end())
					{
						PNOTIFY_FAKE_ACSPT_STATE_CFG notify_fake_acspt_state_cfg = (PNOTIFY_FAKE_ACSPT_STATE_CFG)*iter_fake_acspt_state;
						assert(session_id == notify_fake_acspt_state_cfg->get_session_id() && "The session ID is NOT identical");
						cluster_fake_acspt_state_param->cluster_data_map[notify_fake_acspt_state_cfg->get_cluster_id()] = string(notify_fake_acspt_state_cfg->get_fake_acspt_state());
						iter_fake_acspt_state++;
						SAFE_RELEASE(notify_fake_acspt_state_cfg)
					}
				}
			}
			else if (node_type == FOLLOWER)
			{
	    		PFAKE_ACSPT_STATE_PARAM fake_acspt_state_param = (PFAKE_ACSPT_STATE_PARAM)param1;
	    		assert(fake_acspt_state_param != NULL && "fake_acspt_state_param should NOT be NULL");
				if (simulator_installed)
				{
					ret = simulator_handler->get_fake_acspt_state(fake_acspt_state_param->fake_acspt_state, fake_acspt_state_param->fake_acspt_state_buf_size);
					if (CHECK_FAILURE(ret))
						return ret;
				}
				else
				{
					WRITE_INFO("The simulator is NOT installed");
					memset(fake_acspt_state_param->fake_acspt_state, 0x0, fake_acspt_state_param->fake_acspt_state_buf_size);
					snprintf(fake_acspt_state_param->fake_acspt_state, fake_acspt_state_param->fake_acspt_state_buf_size, "%s", "Not installed");
				}
			}
			else
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
			}
    	}
    	break;
    	case PARAM_FAKE_ACSPT_DETAIL:
    	{
        	if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}

			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			if (node_type == LEADER)
			{
// Leader node
	    		PCLUSTER_FAKE_ACSPT_DETAIL_PARAM cluster_fake_acspt_detail_param = (PCLUSTER_FAKE_ACSPT_DETAIL_PARAM)param1;
	    		assert(cluster_fake_acspt_detail_param != NULL && "cluster_fake_acspt_detail_param should NOT be NULL");
				PFAKE_ACSPT_DETAIL_PARAM fake_acspt_detail_param = new FakeAcsptDetailParam();
				if (fake_acspt_detail_param  == NULL)
					throw bad_alloc();
				ret = simulator_handler->get_fake_acspt_detail(fake_acspt_detail_param->fake_acspt_detail);
				if (CHECK_FAILURE(ret))
					return ret;
// Cluster ID of the Leader node: 1
				cluster_fake_acspt_detail_param->cluster_data_map[1] = fake_acspt_detail_param->fake_acspt_detail;
				if (fake_acspt_detail_param != NULL)
				{
					delete fake_acspt_detail_param;
					fake_acspt_detail_param = NULL;
				}
				assert(cluster_node != NULL && "cluster_node should NOT be NULL");
				int cluster_node_amount;
			    ret = cluster_node->get(PARAM_CLUSTER_NODE_AMOUNT, (void*)&cluster_node_amount);
				if (CHECK_FAILURE(ret))
					return ret;
				// printf("Cluster Node Count: %d\n", cluster_node_amount);
				if (cluster_node_amount > 1)
				{
					int session_id = cluster_fake_acspt_detail_param->session_id;
// Not one node cluster, send notification to the followers
// Reset the counter 
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					interactive_session_param[session_id].follower_node_amount = cluster_node_amount - 1;
					interactive_session_param[session_id].event_count = 0;
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
// Send the request
				    ret = cluster_node->send(MSG_GET_FAKE_ACSPT_DETAIL, (void*)&session_id);
					if (CHECK_FAILURE(ret))
						return ret;
// Receive the response
					bool found = false;
				    struct timespec ts;
				    clock_gettime(CLOCK_REALTIME, &ts);
				    ts.tv_sec += WAIT_MESSAGE_RESPONSE_TIME;
					pthread_mutex_lock(&interactive_session_param[session_id].mtx);
					int timedwait_ret = pthread_cond_timedwait(&interactive_session_param[session_id].cond, &interactive_session_param[session_id].mtx, &ts);
					if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
					{
		    			WRITE_FORMAT_ERROR("pthread_cond_timedwait() fails, due to: %s", pthread_cond_timedwait_err(timedwait_ret));
						return RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT;						
					}
					// dump_interactive_session_data_list(session_id);
					std::list<PNOTIFY_CFG>& interactive_session_data = interactive_session_param[session_id].data_list;
					std::list<PNOTIFY_CFG>::iterator iter = interactive_session_data.begin();
					std::list<PNOTIFY_CFG> interactive_session_fake_acspt_detail_data;
					while (iter != interactive_session_data.end())
					{
						PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)*iter;
						if (notify_cfg->get_notify_type() == NOTIFY_GET_FAKE_ACSPT_DETAIL)
						{
							// found = true;
							interactive_session_fake_acspt_detail_data.push_back(notify_cfg);
							interactive_session_data.erase(iter);
							if ((int)interactive_session_fake_acspt_detail_data.size() == interactive_session_param[session_id].follower_node_amount)
							{
								found = true;
								break;
							}
						}
						iter++;
					}
					pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
	    			if (!found)
	    			{
		    			WRITE_FORMAT_ERROR("Lack of fake acspt detail from some followers in the session[%d], expected: %d, actual: %d", session_id, cluster_node_amount - 1, interactive_session_fake_acspt_detail_data.size());
						return RET_FAILURE_NOT_FOUND;
					}
					std::list<PNOTIFY_CFG>::iterator iter_fake_acspt_detail = interactive_session_fake_acspt_detail_data.begin();
					while (iter_fake_acspt_detail != interactive_session_fake_acspt_detail_data.end())
					{
						PNOTIFY_FAKE_ACSPT_DETAIL_CFG notify_fake_acspt_detail_cfg = (PNOTIFY_FAKE_ACSPT_DETAIL_CFG)*iter_fake_acspt_detail;
						assert(session_id == notify_fake_acspt_detail_cfg->get_session_id() && "The session ID is NOT identical");
						cluster_fake_acspt_detail_param->cluster_data_map[notify_fake_acspt_detail_cfg->get_cluster_id()] = string(notify_fake_acspt_detail_cfg->get_fake_acspt_detail());
						iter_fake_acspt_detail++;
						SAFE_RELEASE(notify_fake_acspt_detail_cfg)
					}
				}
			}
			else if (node_type == FOLLOWER)
			{
	    		PFAKE_ACSPT_DETAIL_PARAM fake_acspt_detail_param = (PFAKE_ACSPT_DETAIL_PARAM)param1;
	    		assert(fake_acspt_detail_param != NULL && "fake_acspt_detail_param should NOT be NULL");
				ret = simulator_handler->get_fake_acspt_detail(fake_acspt_detail_param->fake_acspt_detail);
				if (CHECK_FAILURE(ret))
					return ret;
			}
			else
			{
	    		WRITE_FORMAT_ERROR("The node_type[%d] is Incorrect", node_type);
	    		return RET_FAILURE_INCORRECT_OPERATION;		
			}
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
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
// Cautin: Don't carry any parameters, no need to pass PNOTIFY_XXX_CFG object
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
				if ((!local_cluster) && (node_type == LEADER))
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_INSTALL_SIMULATOR, (void*)simulator_package_filepath);
				}
			}
		}
		break;
		case NOTIFY_APPLY_FAKE_ACSPT_CONFIG:
		{
     		assert(node_type != NONE && "node type should be NONE");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			PNOTIFY_FAKE_ACSPT_CONFIG_APPLY_CFG notify_fake_acspt_config_apply_cfg = (PNOTIFY_FAKE_ACSPT_CONFIG_APPLY_CFG)notify_param;
			assert(notify_fake_acspt_config_apply_cfg != NULL && "notify_fake_acspt_config_apply_cfg should NOT be NULL");

			char* config_line_list_str = strdup(notify_fake_acspt_config_apply_cfg->get_fake_acspt_config_line_list_str());
			char* config_line_list_str_tmp = config_line_list_str;
// De-serialize the new fake acspt config
			char* rest_config_line_list_str = NULL;
			char* config_line;
			list<string> new_config_line_list;
			while ((config_line = strtok_r(config_line_list_str, ",", &rest_config_line_list_str)) != NULL)
			{
				string config_line_str(config_line);
				new_config_line_list.push_back(config_line_str);
				if (config_line_list_str != NULL)
					config_line_list_str = NULL;
			}
			free(config_line_list_str_tmp);
			config_line_list_str_tmp = NULL;

			ret = simulator_handler->apply_new_fake_acspt_config(new_config_line_list);
			if (CHECK_SUCCESS(ret) && (!local_cluster))
			{
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_APPLY_FAKE_ACSPT_CONFIG, (void*)notify_fake_acspt_config_apply_cfg->get_fake_acspt_config_line_list_str());
				}
			}
		}
		break;
		case NOTIFY_APPLY_FAKE_USREPT_CONFIG:
		{
			static const char* START_PKT_PROFILE_TAG = "START_PKT_PROFILES";
			static const int START_PKT_PROFILE_TAG_LEN = strlen(START_PKT_PROFILE_TAG);
			static const char* START_WLAN_PROFILE_TAG = "START_WLAN_PROFILES";										
			static const int START_WLAN_PROFILE_TAG_LEN = strlen(START_WLAN_PROFILE_TAG);
     		assert(node_type != NONE && "node type should be NONE");
			assert(simulator_handler != NULL && "simulator_handler should NOT be NULL");
			PNOTIFY_FAKE_USREPT_CONFIG_APPLY_CFG notify_fake_usrept_config_apply_cfg = (PNOTIFY_FAKE_USREPT_CONFIG_APPLY_CFG)notify_param;
			assert(notify_fake_usrept_config_apply_cfg != NULL && "notify_fake_usrept_config_apply_cfg should NOT be NULL");

			char* config_line_list_str = strdup(notify_fake_usrept_config_apply_cfg->get_fake_usrept_config_line_list_str());
			char* config_line_list_str_tmp = config_line_list_str;
// De-serialize the new fake acspt config
			char* rest_config_line_list_str = NULL;
			char* config_line;
			list<string> new_config_line_list;
			list<string> new_pkt_profile_config_line_list;
			list<string> new_wlan_profile_config_line_list;
			UsreptConfigType usrept_config_type = NORMAL;
			// int line_cnt = 0;
			while ((config_line = strtok_r(config_line_list_str, ",", &rest_config_line_list_str)) != NULL)
			{
				string config_line_str(config_line);
				if (config_line_str.compare(0, START_PKT_PROFILE_TAG_LEN, START_PKT_PROFILE_TAG) == 0)
					usrept_config_type = PKT_PROFILE;
				else if (config_line_str.compare(0, START_WLAN_PROFILE_TAG_LEN, START_WLAN_PROFILE_TAG) == 0)
					usrept_config_type = WLAN_PROFILE;
				// fprintf(stderr, "%d line: %s, type: %d\n", ++line_cnt, config_line, usrept_config_type);
				switch (usrept_config_type)
				{
					case NORMAL:
					{
						new_config_line_list.push_back(config_line_str);
					}
					break;
					case PKT_PROFILE:
					{
						new_pkt_profile_config_line_list.push_back(config_line_str);
					}
					break;
					case WLAN_PROFILE:
					{
						new_wlan_profile_config_line_list.push_back(config_line_str);
					}
					break;
					default:
					{
			    		static const int BUF_SIZE = 256;
			    		char buf[BUF_SIZE];
			    		snprintf(buf, BUF_SIZE, "Unknown usrept config type: %d", usrept_config_type);
			    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
			    		throw std::invalid_argument(buf);
					}
					break;
				}
				
				if (config_line_list_str != NULL)
					config_line_list_str = NULL;
			}
			free(config_line_list_str_tmp);
			config_line_list_str_tmp = NULL;

			// fprintf(stderr, "%d: %d, %d\n", new_config_line_list.size(), new_pkt_profile_config_line_list.size(), new_wlan_profile_config_line_list.size());
			ret = simulator_handler->apply_new_fake_usrept_config(new_config_line_list, new_pkt_profile_config_line_list, new_wlan_profile_config_line_list);
			if (CHECK_SUCCESS(ret) && (!local_cluster))
			{
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_APPLY_FAKE_USREPT_CONFIG, (void*)notify_fake_usrept_config_apply_cfg->get_fake_usrept_config_line_list_str());
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
		    		snprintf(buf, BUF_SIZE, "Unknown simulator acspt control type: %d", fake_acspt_control_type);
		    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
		    		throw std::invalid_argument(buf);
				}
				break;
			}
			if (CHECK_SUCCESS(ret) && (!local_cluster))
			{
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_CONTROL_FAKE_ACSPT, (void*)&fake_acspt_control_type);	
				}
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
		    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
		    		throw std::invalid_argument(buf);
				}
				break;
			}
			if (CHECK_SUCCESS(ret) && (!local_cluster))
			{
				if (node_type == LEADER)
				{
					assert(cluster_node != NULL && "cluster_node should NOT be NULL");
					ret = cluster_node->send(MSG_CONTROL_FAKE_USREPT, (void*)&fake_usrept_control_type);					
				}
			}
		}
		break;
		case NOTIFY_SEND_FILE_DONE:
		{
    		PNOTIFY_SEND_FILE_DONE_CFG notify_send_file_done_cfg = (PNOTIFY_SEND_FILE_DONE_CFG)notify_param;
			assert(notify_send_file_done_cfg != NULL && "notify_send_file_done_cfg should NOT be NULL");
    		int tx_session_id = notify_send_file_done_cfg->get_session_id();
    		string remote_token(notify_send_file_done_cfg->get_remote_token());
    		// fprintf(stderr, "[ClusterMgr::async_handle]  tx_session_id: %d, remote_token: %s\n", tx_session_id, remote_token.c_str());

			assert(cluster_node != NULL && "cluster_node should NOT be NULL");
			cluster_node->send(MSG_COMPLETE_FILE_TRANSFER, (void*)&tx_session_id, (void*)remote_token.c_str());
		}
		break;
// Asynchronous event:
      	case NOTIFY_NODE_DIE:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == FOLLOWER && "node type should be FOLLOWER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_FORMAT_WARN("The leader[%s] dies, try to re-build the cluster", cluster_token);
    		ret = notify_thread->add_event(notify_cfg);
    	}
		break;
		case NOTIFY_GET_SYSTEM_INFO:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the system info for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
		case NOTIFY_GET_SYSTEM_MONITOR:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the system monitor data for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
		case NOTIFY_GET_SIMULATOR_VERSION:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the simulator version for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
		case NOTIFY_GET_FAKE_ACSPT_STATE:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the fake acspt state for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
		case NOTIFY_CONNECT_FILE_TRANSFER:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

     		// assert(node_type == LEADER && "node type should be LEADER");
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the notification of establishing connection for file transfer for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
		case NOTIFY_COMPLETE_FILE_TRANSFER:
		{
			assert(file_tx_type != TX_NONE && "file tx type should NOT be TX_NONE");
			if (file_tx_type == TX_SENDER)
			{
	    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
	    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

	     		// assert(node_type == LEADER && "node type should be LEADER");
	    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
	    		WRITE_DEBUG("Receive the notification of transfering file completely for session......");
	    		ret = notify_thread->add_event(notify_cfg);				
			}
			else if (file_tx_type == TX_RECEIVER)
			{
				assert(file_tx != NULL && "file_tx(Receiver) should NOT be NULL");
				ret = file_tx->set(PARAM_FILE_TRANSFER_DONE);
				if (CHECK_SUCCESS(ret))
				{
					ret = file_tx->deinitialize();	
					delete file_tx;
					file_tx = NULL;
				}
			}
		}
		break;
		case NOTIFY_SWITCH_LEADER:
		{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		WRITE_DEBUG("Receive the notification of switching leader for session......");
    		ret = notify_thread->add_event(notify_cfg);
		}
		break;
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
    	case NOTIFY_GET_SYSTEM_INFO:
    	{
    		PNOTIFY_SYSTEM_INFO_CFG notify_system_info_cfg = (PNOTIFY_SYSTEM_INFO_CFG)notify_cfg;
			// assert(notify_system_info_cfg != NULL && "notify_system_info_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_system_info_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_system_info_cfg->get_session_id();
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_system_info_cfg);
			interactive_session_param[session_id].event_count++;
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
// It's required to sleep for a while before notifying to accessing the list in another thread
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_cond_signal(&interactive_session_param[session_id].cond);
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
    	}
    	break;
    	case NOTIFY_GET_SYSTEM_MONITOR:
    	{
    		PNOTIFY_SYSTEM_MONITOR_CFG notify_system_monitor_cfg = (PNOTIFY_SYSTEM_MONITOR_CFG)notify_cfg;
			// assert(notify_system_monitor_cfg != NULL && "notify_system_monitor_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_system_monitor_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_system_monitor_cfg->get_session_id();
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_system_monitor_cfg);
			interactive_session_param[session_id].event_count++;
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
// It's required to sleep for a while before notifying to accessing the list in another thread
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
    	}
    	break;
    	case NOTIFY_GET_SIMULATOR_VERSION:
    	{
    		PNOTIFY_SIMULATOR_VERSION_CFG notify_simulator_version_cfg = (PNOTIFY_SIMULATOR_VERSION_CFG)notify_cfg;
			// assert(notify_system_info_cfg != NULL && "notify_system_info_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_simulator_version_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_simulator_version_cfg->get_session_id();
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_simulator_version_cfg);
			interactive_session_param[session_id].event_count++;
// It's required to sleep for a while before notifying to accessing the list in another thread
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
    	}
    	break;
    	case NOTIFY_GET_FAKE_ACSPT_STATE:
    	{
    		PNOTIFY_FAKE_ACSPT_STATE_CFG notify_fake_acspt_state_cfg = (PNOTIFY_FAKE_ACSPT_STATE_CFG)notify_cfg;
			// assert(notify_system_info_cfg != NULL && "notify_system_info_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_fake_acspt_state_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_fake_acspt_state_cfg->get_session_id();
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_fake_acspt_state_cfg);
			interactive_session_param[session_id].event_count++;
// It's required to sleep for a while before notifying to accessing the list in another thread
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
    	}
    	break;
       	case NOTIFY_GET_FAKE_ACSPT_DETAIL:
    	{
    		PNOTIFY_FAKE_ACSPT_DETAIL_CFG notify_fake_acspt_detail_cfg = (PNOTIFY_FAKE_ACSPT_DETAIL_CFG)notify_cfg;
			// assert(notify_fake_acspt_detail_cfg != NULL && "notify_system_info_cfg should NOT be NULL");ri
// Caution: Required to add reference count, since another thread will access it
			notify_fake_acspt_detail_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_fake_acspt_detail_cfg->get_session_id();
			// const char* fake_acspt_detail = notify_fake_acspt_detail_cfg->get_fake_acspt_detail();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_fake_acspt_detail_cfg);
			interactive_session_param[session_id].event_count++;
// It's required to sleep for a while before notifying to accessing the list in another thread
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
    	}
    	break;
    	case NOTIFY_CONNECT_FILE_TRANSFER:
    	{
			unsigned short ret = RET_SUCCESS;
    		ret = become_file_receiver();
			if (CHECK_FAILURE(ret))
				return ret;
			ret = file_tx->notify(NOTIFY_CONNECT_FILE_TRANSFER, (void*)notify_cfg);
			if (CHECK_FAILURE(ret))
				return ret;
			// ret = cluster_node->set(PARAM_FILE_TRANSFER, (void*)&file_transfer_param);
			// if (CHECK_FAILURE(ret))
			// 	return ret;
    	}
    	break;
    	case NOTIFY_COMPLETE_FILE_TRANSFER:
    	{
    		PNOTIFY_FILE_TRANSFER_COMPLETE_CFG notify_file_transfer_complete_cfg = (PNOTIFY_FILE_TRANSFER_COMPLETE_CFG)notify_cfg;
			// assert(notify_system_info_cfg != NULL && "notify_system_info_cfg should NOT be NULL");
// Caution: Required to add reference count, since another thread will access it
			notify_file_transfer_complete_cfg->addref(__FILE__, __LINE__);
			int session_id = notify_file_transfer_complete_cfg->get_session_id();
			WRITE_FORMAT_DEBUG("Remote[%s] notify receviving data complete !", notify_file_transfer_complete_cfg->get_remote_token());
			usleep(100);
			file_tx->set(PARAM_REMOVE_FILE_CHANNEL, (void*)notify_file_transfer_complete_cfg->get_remote_token());
			assert(interactive_server != NULL && "interactive_server should NOT be NULL");
			string console_message = string(" ") + string(notify_file_transfer_complete_cfg->get_remote_token()) + string(" ... DONE\n");
			interactive_server->print_console(console_message, session_id);
			// const char* system_info = notify_system_info_cfg->get_system_info();
			pthread_mutex_lock(&interactive_session_param[session_id].mtx);
			interactive_session_param[session_id].data_list.push_back(notify_file_transfer_complete_cfg);
			interactive_session_param[session_id].event_count++;
// It's required to sleep for a while before notifying to accessing the list in another thread
			if (interactive_session_param[session_id].event_count == interactive_session_param[session_id].follower_node_amount)
			{
				usleep(1000); // A MUST
				pthread_cond_signal(&interactive_session_param[session_id].cond);
			}
			pthread_mutex_unlock(&interactive_session_param[session_id].mtx);
			WRITE_DEBUG("Complete transferring the file. Release the sender....");
			assert(file_tx != NULL && "file_tx(Sender) should NOT be NULL");
			file_tx->deinitialize();
			delete file_tx;
			file_tx = NULL;	
    	}
    	break;
    	case NOTIFY_SWITCH_LEADER:
    	{
    		PNOTIFY_SWITCH_LEADER_CFG notify_switch_leader_cfg = (PNOTIFY_SWITCH_LEADER_CFG)notify_cfg;
    		int leader_candidate_node_id = notify_switch_leader_cfg->get_node_id();
    		if (node_type == LEADER)
    		{
				ClusterMap cluster_map;
			    ret = cluster_node->get(PARAM_CLUSTER_MAP, (void*)&cluster_map);
				if (CHECK_FAILURE(ret))
					return ret;
				string leader_candidate_node_token;
			    ret = cluster_map.get_node_token(leader_candidate_node_id, leader_candidate_node_token);
				if (CHECK_FAILURE(ret))
					return ret;
// Notify the Followers to rebuild the cluster
				ret = cluster_node->send(MSG_SWITCH_LEADER, (void*)&leader_candidate_node_id);
				if (CHECK_FAILURE(ret))
					return ret;
// Leader stop connection
				ret = stop_connection();
				if (CHECK_FAILURE(ret))
					return ret;
// Leader switch role to Follower and join the new cluster
				if (cluster_token != NULL)
					free(cluster_token);
				close_console();
				WRITE_FORMAT_DEBUG("Leader -> Follower, re-connect to new Leader[%d: %s]", leader_candidate_node_id, leader_candidate_node_token.c_str());
				cluster_token = strdup(leader_candidate_node_token.c_str());
				ret = become_follower(true);
		        if (CHECK_FAILURE(ret))
					return ret;
	        	assert(interactive_server == NULL && "interactive_server should be NULL");
	        	WRITE_FORMAT_DEBUG("[%s] Re-Initialize the session server due to role switch...", local_token);
	        	interactive_server = new InteractiveServer(this);
	        	if (interactive_server == NULL)
					throw bad_alloc();
	        	ret = interactive_server->initialize(system_monitor_period);
	        	if (CHECK_FAILURE(ret))
					return ret;
    		}
    		else if (node_type == FOLLOWER)
    		{
    			ret = rebuild_cluster(leader_candidate_node_id);
				if (CHECK_FAILURE(ret))
				{
					WRITE_FORMAT_ERROR("Rebuild cluster fails while switching rule, due to: %s", GetErrorDescription(ret));
					return ret;
				}
    		}
    		else
    		{
				WRITE_FORMAT_ERROR("Unknown node type: %d while switching rule", node_type);
				return RET_FAILURE_INCORRECT_OPERATION;    			
    		}
    	}
    	break;
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