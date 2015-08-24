#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "msg_cluster_mgr.h"
#include "msg_cluster_leader_node.h"
#include "msg_cluster_follower_node.h"
#include "msg_cluster_keepalive_timer_task.h"


using namespace std;

const char* MsgClusterMgr::SERVER_LIST_CONF_FILENAME = "server_list.conf";
const int MsgClusterMgr::RETRY_WAIT_CONNECTION_TIME = 3; // 3 seconds
const int MsgClusterMgr::TRY_TIMES = 3;

static MsgClusterKeepaliveTimerTask msg_cluster_keepalive_timer_task;

static void timer_sigroutine(int signo)
{
	switch (signo)
	{
	case SIGALRM:
        printf("Catch a signal -- SIGALRM \n");
		msg_cluster_keepalive_timer_task.run();
		signal(SIGALRM, timer_sigroutine);
		break;
	}
}

unsigned short MsgClusterMgr::find_local_ip()
{
	unsigned short ret = RET_SUCCESS;
	char current_path[LONG_STRING_SIZE];
	getcwd(current_path, sizeof(current_path));

	char server_list_conf_filepath[EX_LONG_STRING_SIZE];
	snprintf(server_list_conf_filepath, EX_LONG_STRING_SIZE, "%s/%s/%s", current_path, CONF_FODLERNAME, SERVER_LIST_CONF_FILENAME);

	WRITE_FORMAT_DEBUG(EX_LONG_STRING_SIZE, "Check the file[%s] exist", server_list_conf_filepath);

	FILE* fp = fopen(server_list_conf_filepath, "r");
	if (fp == NULL)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "The server list configuration file[%s] does NOT exist", server_list_conf_filepath);
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
//		WRITE_FORMAT_DEBUG(STRING_SIZE, "Param content: %s", buf);
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
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "%s", *iter_show++);

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
			WRITE_FORMAT_DEBUG(STRING_SIZE, "%s IPv4 Address %s", ifa->ifa_name, addressBuffer);

// Check if the IP found in the server list
			list<char*>::iterator iter = server_list.begin();
			while (iter != server_list.end())
			{
				if (strcmp(*iter++, addressBuffer) == 0)
				{
					found = true;
					WRITE_FORMAT_DEBUG(STRING_SIZE, "Find Address %s", addressBuffer);
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
			WRITE_FORMAT_DEBUG(STRING_SIZE, "%s IPv6 Address %s", ifa->ifa_name, addressBuffer);
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

MsgClusterMgr::MsgClusterMgr() :
	local_ip(NULL),
	msg_trasnfer(NULL),
	msg_cluster_node(NULL),
	t(0),
	runtime_ret(RET_SUCCESS),
	node_type(NONE)
{
	IMPLEMENT_MSG_DUMPER()
}

MsgClusterMgr::~MsgClusterMgr()
{
	if (msg_cluster_node != NULL)
	{
		delete msg_cluster_node;
		msg_cluster_node = NULL;
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

void MsgClusterMgr::set_keepalive_timer_interval(int delay, int period)
{
	struct itimerval value, ovalue;

	value.it_value.tv_sec = delay;
	value.it_value.tv_usec = 0;
	value.it_interval.tv_sec = period;
	value.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &value, &ovalue);
}

unsigned short MsgClusterMgr::start_keepalive_timer()
{
	WRITE_DEBUG("Start the keep-alive timer");
	msg_cluster_keepalive_timer_task.initialize(this);
	signal(SIGALRM, timer_sigroutine);
	set_keepalive_timer_interval(KEEPALIVE_DELAY_TIME, KEEPALIVE_PERIOD);

	return RET_SUCCESS;
}

void MsgClusterMgr::stop_keepalive_timer()
{
// To stop the keep-alive timer
	WRITE_DEBUG("Stop the keep-alive timer");
	set_keepalive_timer_interval();
	msg_cluster_keepalive_timer_task.deinitialize();
}

unsigned short MsgClusterMgr::become_leader()
{
	msg_cluster_node = new MsgClusterLeaderNode(local_ip);
	if (msg_cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: msg_cluster_node (Leader)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	unsigned short ret = msg_cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = LEADER;
	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "This Node[%s] is a Leader !!!", local_ip);
	return RET_SUCCESS;
}

unsigned short MsgClusterMgr::become_follower()
{
	msg_cluster_node = new MsgClusterFollowerNode(&server_list, local_ip);
	if (msg_cluster_node == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: msg_cluster_node (Follower)");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	unsigned short ret = msg_cluster_node->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	node_type = FOLLOWER;
	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "This Node[%s] is a Follower !!!", local_ip);
	return ret;
}

unsigned short MsgClusterMgr::start_connection()
{
	unsigned short ret = RET_SUCCESS;

	WRITE_FORMAT_DEBUG(STRING_SIZE, "Node[%s] Try to become follower...", local_ip);
// Try to find the follower node
	ret = become_follower();
	if (CHECK_FAILURE(ret) || IS_TRY_CONNECTION_TIMEOUT(ret))
	{
		if (node_type != NONE)
		{
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Node[%s] type should be None at this moment", local_ip);
			return RET_FAILURE_INCORRECT_OPERATION;
		}
// Fail to connect to any server, be the server
		WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Node[%s] Try to become leader...", local_ip);
	// Try to find the leader node
		ret = become_leader();
	}

	return ret;
}

unsigned short MsgClusterMgr::stop_connection()
{
	if (msg_cluster_node != NULL)
	{
		unsigned short ret = msg_cluster_node->deinitialize();
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR(STRING_SIZE, "Error occur while closing the %s[%s]", (is_leader() ? "Leader" : "Follower"), local_ip);
			return ret;
		}
		msg_cluster_node = NULL;
		node_type = NONE;
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterMgr::try_reconnection()
{
	unsigned short ret = RET_SUCCESS;

	int server_candidate_id = 0;
	if (msg_cluster_node != NULL)
		server_candidate_id = ((PMSG_CLUSTER_FOLLOWER_NODE)msg_cluster_node)->get_server_candidate_id();

// Close the old connection
	ret = stop_connection();
	if (CHECK_FAILURE(ret))
		return ret;

// The server candidate ID should exist in the Follower
	if (server_candidate_id == 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "The Follower[%s] server candidate ID is NOT correct", local_ip);
		return RET_FAILURE_INCORRECT_OPERATION;
	}

	while (server_candidate_id > 1)
	{
		for (int i = 1 ; i < TRY_TIMES ; i++)
		{
			WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Node[%s] try to become a Follower...", local_ip);
			ret = become_follower();
			if (CHECK_SUCCESS(ret))
				goto OUT;
			else
			{
// Check the error code, if connection time-out, sleep for a while before trying to connect again
				if (IS_TRY_CONNECTION_TIMEOUT(ret))
				{
					WRITE_FORMAT_WARN(LONG_STRING_SIZE, "Sleep %d seconds before re-trying node[%s] to become a Follower", RETRY_WAIT_CONNECTION_TIME, local_ip);
					sleep(RETRY_WAIT_CONNECTION_TIME);
				}
				else
					goto OUT;
			}
			WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Node[%s] try to find Leader for %d times, but still FAIL......", local_ip, TRY_TIMES);
		}

		server_candidate_id--;
	}

OUT:
	if (server_candidate_id == 1)
	{
		WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Node[%s] try to become a Leader...", local_ip);
		ret = become_leader();
	}

	return ret;
}

void MsgClusterMgr::check_keepalive()
{
	if (msg_cluster_node != NULL)
	{
		WRITE_DEBUG("Check Keep-Alive...");
		unsigned short ret = msg_cluster_node->check_keepalive();
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

unsigned short MsgClusterMgr::initialize()
{
	unsigned short ret = RET_SUCCESS;
// Find local IP
	if (local_ip == NULL)
	{
		ret  = find_local_ip();
		if (CHECK_FAILURE(ret))
			return ret;
		WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "The local IP of this Node: %s", local_ip);
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

unsigned short MsgClusterMgr::deinitialize()
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

unsigned short MsgClusterMgr::start()
{
// Initialize
	unsigned short ret = initialize();
// Start the thread of listening the events
//	if (CheckSuccess(ret))
//	{
//		t = new Thread(this);
//		t.start();
//	}

	return ret;
}

unsigned short MsgClusterMgr::wait_to_stop()
{
	unsigned short ret = deinitialize();
// Wait for the death of the working thread
//	if (t != null)
//	{
//		try
//		{
//			debug("Wait for terminating the worker threads......");
//			t.join();
//		}
//		catch (InterruptedException ex)
//		{
//			error("Receive an interrupted exception while Waiting for terminating the worker threads......");
//		}
//		t = null;
//	}

	return RET_SUCCESS;
}

void MsgClusterMgr::notify_exit(unsigned short exit_reason)
{
	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Notify the parent it's time to leave, exit reason: %s", GetErrorDescription(exit_reason));
//	synchronized(runtime_ret)
//	{
//		runtime_ret.set(exit_reason);
//		runtime_ret.notify();
//	}
}

unsigned short MsgClusterMgr::notify(NotifyType notify_type)
{
	switch (notify_type)
	{
	case NOTIFY_CHECK_KEEPALIVE:
		check_keepalive();
		break;
	default:
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Un-supported type: %d", notify_type);
		return RET_FAILURE_IO_OPERATION;
	}
	return RET_SUCCESS;
}
