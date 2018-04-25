#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "cluster_mgr.h"
#include "leader_node.h"
#include "follower_node.h"
#include "keepalive_timer_task.h"


using namespace std;

static KeepaliveTimerTask keepalive_timer_task;
static void timer_sigroutine(int signo)
{
	switch (signo)
	{
	case SIGALRM:
//        printf("Catch a signal -- SIGALRM \n");
		keepalive_timer_task.run();
		signal(SIGALRM, timer_sigroutine);
		break;
	}
}

const char* ClusterMgr::SERVER_LIST_CONF_FILENAME = "server_list.conf";
const int ClusterMgr::RETRY_WAIT_CONNECTION_TIME = 3; // 3 seconds
const int ClusterMgr::TRY_TIMES = 3;
// DECLARE_MSG_DUMPER_PARAM();

unsigned short ClusterMgr::find_local_ip()
{
	unsigned short ret = RET_SUCCESS;
	char current_path[LONG_STRING_SIZE];
	getcwd(current_path, sizeof(current_path));

	char server_list_conf_filepath[EX_LONG_STRING_SIZE];
	snprintf(server_list_conf_filepath, EX_LONG_STRING_SIZE, "%s/%s/%s", current_path, CONF_FODLERNAME, SERVER_LIST_CONF_FILENAME);

	WRITE_FORMAT_DEBUG("Check the file[%s] exist", server_list_conf_filepath);

	FILE* fp = fopen(server_list_conf_filepath, "r");
	if (fp == NULL)
	{
		WRITE_FORMAT_ERROR("The server list configuration file[%s] does NOT exist", server_list_conf_filepath);
		return RET_FAILURE_NOT_FOUND;
	}
// Parse the server IP list
	char buf[STRING_SIZE];
	while (fgets(buf, sizeof(char) * STRING_SIZE, fp) != NULL)
	{
		bool found = false;
		int index = 0;
		for (int i = 0 ; i < STRING_SIZE ; i++)
		{
			if (buf[i] == '\n')
			{
				buf[i] = '\0';
				found = true;
				index = i;
				break;
			}
		}
		if (!found)
		{
			WRITE_ERROR("Incorrect config format in the server list");
			return MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
		}

		if (index == 0)
			continue;
//		WRITE_FORMAT_DEBUG("Param content: %s", buf);
//		fprintf(stderr, "Param content: %s\n", buf);

		int str_len = strlen(buf);
		char* new_ip = new char[str_len + 1];
		if (new_ip == NULL)
		{
			WRITE_ERROR("Fail to allocate memory: new_ip");
			return MSG_DUMPER_FAILURE_INSUFFICIENT_MEMORY;
		}
		new_ip[str_len] = '\0';
		memcpy(new_ip, buf, sizeof(char) * str_len);
		server_list.push_back(new_ip);
	}
	fclose(fp);
	fp = NULL;

	list<char*>::iterator iter_show = server_list.begin();
	WRITE_DEBUG("Server IP List:");
	while (iter_show != server_list.end())
		WRITE_FORMAT_ERROR("%s", *iter_show++);

	struct ifaddrs* ifAddrStruct = NULL;
	void* tmpAddrPtr = NULL;

	getifaddrs(&ifAddrStruct);

// Traverse the ethernet card on local PC
	WRITE_DEBUG("Traverse the all IPs bounded to local network interface...");
	bool found = false;
	for (struct ifaddrs* ifa = ifAddrStruct ; ifa != NULL ; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) // check it is IP4
		{
			tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			WRITE_FORMAT_DEBUG("%s IPv4 Address %s", ifa->ifa_name, addressBuffer);

// Check if the IP found in the server list
			list<char*>::iterator iter = server_list.begin();
			while (iter != server_list.end())
			{
				if (strcmp(*iter++, addressBuffer) == 0)
				{
					found = true;
					WRITE_FORMAT_DEBUG("Find Address %s", addressBuffer);
					int len = strlen(addressBuffer) + 1;
					local_ip = new char[len];
					if (local_ip == NULL)
					{
						WRITE_ERROR("Fail to allocate memory: local_ip");
						return MSG_DUMPER_FAILURE_INSUFFICIENT_MEMORY;
					}
					memcpy(local_ip, addressBuffer, len);
					break;
				}
			}
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6) // check it is IP6
		{
			tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
			char addressBuffer[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			WRITE_FORMAT_DEBUG("%s IPv6 Address %s", ifa->ifa_name, addressBuffer);
		}
	}

// Release the resource
	if (ifAddrStruct!=NULL)
		freeifaddrs(ifAddrStruct);

	if (!found)
	{
		WRITE_ERROR("There are no IPs existing in the server list");
		return MSG_DUMPER_FAILURE_INCORRECT_CONFIG;
	}

	return ret;
}

ClusterMgr::ClusterMgr() :
	local_ip(NULL),
	msg_trasnfer(NULL),
	cluster_node(NULL),
	pid(0),
	runtime_ret(RET_SUCCESS),
	node_type(NONE)
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

	if (local_ip != NULL)
	{
		delete[] local_ip;
		local_ip = NULL;
	}

	list<char*>::iterator iter = server_list.begin();
	while (iter != server_list.end())
		delete [] (char*)*iter++;
	server_list.clear();

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
	cluster_node = new FollowerNode(&server_list, local_ip);
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

	WRITE_FORMAT_DEBUG("Node[%s] Try to become follower...", local_ip);
// Try to find the follower node
	ret = become_follower();
	if (CHECK_FAILURE(ret) || IS_TRY_CONNECTION_TIMEOUT(ret))
	{
		if (node_type != NONE)
		{
			WRITE_FORMAT_ERROR("Node[%s] type should be None at this moment", local_ip);
			return RET_FAILURE_INCORRECT_OPERATION;
		}
// Fail to connect to any server, be the server
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
		cluster_node = NULL;
		node_type = NONE;
	}

	return RET_SUCCESS;
}

unsigned short ClusterMgr::try_reconnection()
{
	unsigned short ret = RET_SUCCESS;

	int server_candidate_id = 0;
	if (cluster_node != NULL)
		server_candidate_id = ((PFOLLOWER_NODE)cluster_node)->get_server_candidate_id();

// Close the old connection
	ret = stop_connection();
	if (CHECK_FAILURE(ret))
		return ret;

// The server candidate ID should exist in the Follower
	if (server_candidate_id == 0)
	{
		WRITE_FORMAT_ERROR("The Follower[%s] server candidate ID is NOT correct", local_ip);
		return RET_FAILURE_INCORRECT_OPERATION;
	}

	while (server_candidate_id > 1)
	{
		for (int i = 1 ; i < TRY_TIMES ; i++)
		{
			WRITE_FORMAT_DEBUG("Node[%s] try to become a Follower...", local_ip);
			ret = become_follower();
			if (CHECK_SUCCESS(ret))
				goto OUT;
			else
			{
// Check the error code, if connection time-out, sleep for a while before trying to connect again
				if (IS_TRY_CONNECTION_TIMEOUT(ret))
				{
					WRITE_FORMAT_WARN("Sleep %d seconds before re-trying node[%s] to become a Follower", RETRY_WAIT_CONNECTION_TIME, local_ip);
					sleep(RETRY_WAIT_CONNECTION_TIME);
				}
				else
					goto OUT;
			}
			WRITE_FORMAT_DEBUG("Node[%s] try to find Leader for %d times, but still FAIL......", local_ip, TRY_TIMES);
		}

		server_candidate_id--;
	}

OUT:
	if (server_candidate_id == 1)
	{
		WRITE_FORMAT_DEBUG("Node[%s] try to become a Leader...", local_ip);
		ret = become_leader();
	}

	return ret;
}

void ClusterMgr::check_keepalive()
{
	if (cluster_node != NULL)
	{
		WRITE_DEBUG("Check Keep-Alive...");
		unsigned short ret = cluster_node->check_keepalive();
		if (node_type == FOLLOWER)
		{
			if (CHECK_FAILURE(ret))
			{
				if (!IS_KEEP_ALIVE_TIMEOUT(ret))
				{
					WRITE_ERROR("Error should NOT occur when checking keep-alive on the client side !!!");
					notify_exit(ret);
					return;
				}
				else
				{
// The leader is dead, try to find the new leader
					ret = try_reconnection();
					if (CHECK_FAILURE(ret))
					{
						notify_exit(ret);
						return;
					}
				}
			}
		}
	}
}

unsigned short ClusterMgr::initialize()
{
	unsigned short ret = RET_SUCCESS;
// Find local IP
	if (local_ip == NULL)
	{
		ret  = find_local_ip();
		if (CHECK_FAILURE(ret))
			return ret;
		WRITE_FORMAT_DEBUG("The local IP of this Node: %s", local_ip);
	}

// Define a leader/follower and establish the connection
	ret = start_connection();
	if (CHECK_FAILURE(ret))
		return ret;

// Start a keep-alive timer
	ret = start_keepalive_timer();
	if (CHECK_FAILURE(ret))
		return ret;

	return RET_SUCCESS;
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

unsigned short ClusterMgr::start()
{
// Initialize
	unsigned short ret = initialize();
// Start the thread of listening the connection requests
	if (CHECK_SUCCESS(ret))
	{
		mtx_runtime_ret = PTHREAD_MUTEX_INITIALIZER;
		cond_runtime_ret = PTHREAD_COND_INITIALIZER;
		if (pthread_create(&pid, NULL, thread_handler, this) != 0)
		{
			WRITE_FORMAT_ERROR("Fail to create a worker thread of listening the connection requests, due to: %s",strerror(errno));
			return RET_FAILURE_HANDLE_THREAD;
		}
	}

	return ret;
}

unsigned short ClusterMgr::wait_to_stop()
{
	unsigned short ret = RET_SUCCESS;
	void* status;
//	if (pid == 0)
//		goto OUT;
//
//	int kill_ret = pthread_kill(pid, 0);
//	if(kill_ret == ESRCH)
//	{
//		WRITE_WARN("The worker thread of waiting to stop did NOT exist......");
//		ret = RET_SUCCESS;
//		goto OUT;
//	}
//	else if(kill_ret == EINVAL)
//	{
//		WRITE_ERROR("The signal to the worker thread of waiting to stop is invalid");
//		ret = RET_FAILURE_HANDLE_THREAD;
//		goto OUT;
//	}

	WRITE_DEBUG("Wait for the worker thread of waiting to stop's death...");
	pthread_join(pid, &status);
	if (status == NULL)
		WRITE_DEBUG("Wait for the worker thread of waiting to stop's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of waiting to stop's death, due to: %s", (char*)status);
		ret = runtime_ret;
	}

	return ret;
}

void ClusterMgr::notify_exit(unsigned short exit_reason)
{
	WRITE_FORMAT_DEBUG("Notify the parent it's time to leave, exit reason: %s", GetErrorDescription(exit_reason));

	pthread_mutex_lock(&mtx_runtime_ret);
	runtime_ret = exit_reason;
	pthread_cond_signal(&cond_runtime_ret);
	pthread_mutex_unlock(&mtx_runtime_ret);
}

unsigned short ClusterMgr::notify(NotifyType notify_type)
{
	switch (notify_type)
	{
	case NOTIFY_CHECK_KEEPALIVE:
		check_keepalive();
		break;
	default:
		WRITE_FORMAT_ERROR("Un-supported type: %d", notify_type);
		return RET_FAILURE_IO_OPERATION;
	}
	return RET_SUCCESS;
}

void* ClusterMgr::thread_handler(void* pvoid)
{
	ClusterMgr* pthis = (ClusterMgr*)pvoid;
	assert(pthis != NULL && "pvoid should NOT be NULL");
	pthis->runtime_ret = pthis->thread_handler_internal();

	pthread_exit((CHECK_SUCCESS(pthis->runtime_ret) ? NULL : (void*)GetErrorDescription(pthis->runtime_ret)));
}

unsigned short ClusterMgr::thread_handler_internal()
{
	unsigned short ret = RET_SUCCESS;

	pthread_mutex_lock(&mtx_runtime_ret);
	pthread_cond_wait(&cond_runtime_ret, &mtx_runtime_ret);
	WRITE_DEBUG("Notify the parent it's time to leave......");
	ret = deinitialize();
	pthread_mutex_unlock(&mtx_runtime_ret);

	return ret;
}

