// #include <errno.h>
// #include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
// #include <stdexcept>
// #include <string>
#include <deque>
#include "leader_node.h"


using namespace std;

const char* LeaderNode::listen_thread_tag = "Listen Thread";
const int LeaderNode::WAIT_CONNECTION_TIMEOUT = 60; // 5 seconds

LeaderNode::LeaderNode(PINOTIFY notify, const char* ip) :
	observer(notify),
	socketfd(0),
	local_ip(NULL),
	cluster_node_id(0),
	cluster_node_cnt(0),
	notify_thread(NULL),
	listen_exit(0),
	listen_tid(0),
	listen_thread_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()
	if (ip == NULL)
		throw invalid_argument(string("ip == NULL"));
	local_ip = strdup(ip);
}

LeaderNode::~LeaderNode()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in LeaderNode::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(string(errmsg));
	}
	if (observer != NULL)
		observer = NULL;
	if (local_ip != NULL)
	{
		// delete[] local_ip;
		free(local_ip);
		local_ip = NULL;
	}

	RELEASE_MSG_DUMPER()
}

unsigned short LeaderNode::become_leader()
{
	int on = 1;
	unsigned short ret = RET_SUCCESS;
// Create socket
	int listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sd < 0)
	{
		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
// Allow socket descriptor to be reuseable
   if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) < 0)
   {
      WRITE_FORMAT_ERROR("setsockopt() fails, due to: %s", strerror(errno));
      close(listen_sd);
      return RET_FAILURE_SYSTEM_API;
   }

// Set socket to be nonblocking. 
/*
All sockets for the incoming connections will also be nonblocking
since they will inherit that state from the listening socket.   
*/
   if (ioctl(listen_sd, FIONBIO, (char*)&on) < 0)
   {
      WRITE_FORMAT_ERROR("ioctl() fails, due to: %s", strerror(errno));
      close(listen_sd);
      return RET_FAILURE_SYSTEM_API;
   }
// Bind
	int server_len;
	struct sockaddr_in server_address;
	memset(&server_address, 0x0, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(CLUSTER_PORT_NO);
	server_len = sizeof(server_address);
	if (bind(listen_sd, (struct sockaddr*)&server_address, server_len) == -1)
	{
		WRITE_FORMAT_ERROR("bind() fail, due to: %s", strerror(errno));
		close(listen_sd);
		return RET_FAILURE_SYSTEM_API;
	}
// Listen
	if (listen(listen_sd, MAX_CONNECTED_CLIENT) == -1)
	{
		WRITE_FORMAT_ERROR("listen() fail, due to: %s", strerror(errno));
		close(listen_sd);
		return RET_FAILURE_SYSTEM_API;
	}
	socketfd = listen_sd;
// Update the cluster map
	cluster_node_id = 1;
	cluster_node_cnt = 1;
	ret = cluster_map.cleanup_node();
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to cleanup node map, due to: %s", GetErrorDescription(ret));
		return ret;
	}
	ret = cluster_map.add_node(cluster_node_id, local_ip);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to add leader into node map, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	WRITE_FORMAT_INFO("Node[%s] is a Leader", local_ip);
	printf("Node[%s] is a Leader !!!\n", local_ip);

	return ret;
}

unsigned short LeaderNode::send_data(MessageType message_type, const char* data, const char* remote_ip)
{
	unsigned short ret = RET_SUCCESS;
	// assert(data != NULL && "data should NOT be NULL");

	NodeMessageAssembler node_message_assembler;
	ret = node_message_assembler.assemble(message_type, data);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to assemble the message, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	pthread_mutex_lock(&node_channel_mtx);
	if (remote_ip != NULL)
	{
		// fprintf(stderr, "remote_ip: %s\n", remote_ip);
		// dump_node_channel_map();
// Send to single node
		PNODE_CHANNEL node_channel = node_channel_map[remote_ip];
		assert(node_channel != NULL && "node_channel should NOT be NULL");
		ret = node_channel->send_msg(node_message_assembler.get_full_message());
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", remote_ip, GetErrorDescription(ret));
	}
	else
	{
// Send to all nodes
		// deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
		// while(iter != node_channel_deque.end())
		// {
		// 	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
		// 	assert(node_channel != NULL && "node_channel should NOT be NULL");
		// 	ret = node_channel->send_data(data);
		// 	if (CHECK_FAILURE(ret))
		// 	{
		// 		WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", node_channel->get_remote_ip(), GetErrorDescription(ret));
		// 		break;
		// 	}
		// 	iter++;
		// }
		map<string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
		while(iter != node_channel_map.end())
		{
			PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
			assert(node_channel != NULL && "node_channel should NOT be NULL");
			ret = node_channel->send_msg(node_message_assembler.get_full_message());
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", node_channel->get_remote_ip(), GetErrorDescription(ret));
				break;
			}
			iter++;
		}
	}
	pthread_mutex_unlock(&node_channel_mtx);
	return ret;
}

unsigned short LeaderNode::remove_follower(const string& node_ip)
{
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&node_channel_mtx);
	map<string, PNODE_CHANNEL>::iterator iter = node_channel_map.find(node_ip);
	if (iter == node_channel_map.end())
	{
		WRITE_FORMAT_ERROR("The Follower[%s] does NOT exist", node_ip.c_str());
		pthread_mutex_unlock(&node_channel_mtx);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)iter->second;
	assert(node_channel != NULL && "node_channel should NOT be NULL");
// Stop the node of the channel
	node_channel->deinitialize();
	delete node_channel;
	node_channel = NULL;
// Remove the node
	node_channel_map.erase(node_ip);
	node_keepalive_map.erase(node_ip);
	ret = cluster_map.delete_node_by_ip(node_ip);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to delete the node[%s] in the map", node_ip.c_str());
	}
	pthread_mutex_unlock(&node_channel_mtx);
	
	return ret;
}


unsigned short LeaderNode::initialize()
{
	unsigned short ret = RET_SUCCESS;
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "Leader Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
// Try to become leader
	ret = become_leader();
	if (CHECK_FAILURE(ret))
		return ret;

// Create worker thread
	if (pthread_create(&listen_tid, NULL, listen_thread_handler, this))
	{
		WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting client, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
}

unsigned short LeaderNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	// void* status;
// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&listen_exit, 1);
	sleep(1);
// Check listen thread alive
	// bool listen_thread_alive = false;
	if (listen_tid != 0)
	{
		int kill_ret = pthread_kill(listen_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of listening did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of listening is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker thread of listening is STILL alive");
			// listen_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(listen_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of listening, due to: %s", strerror(errno));
			sleep(1);
		}
	}

	WRITE_DEBUG("Wait for the worker thread of listening's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'status' variable accesses the illegal address
	// pthread_join(listen_tid, &status);
	// if (status == NULL)
	// 	sWRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	// else
	// {
	// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
	// 	return listen_thread_ret;
	// }
// Wait for listen thread's death
	pthread_join(listen_tid, NULL);
	if (CHECK_SUCCESS(listen_thread_ret))
		WRITE_DEBUG("Wait for the worker thread of listening's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of listening's death, due to: %s", GetErrorDescription(listen_thread_ret));
		ret = listen_thread_ret;
	}
	// }
// No need
// Implemented in the thread cleanup handler function
// 	// pthread_mutex_lock(&node_channel_mtx);
// 	deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
// 	while (iter != node_channel_deque.end())
// 	{
// 		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
// 		iter++;
// 		if (node_channel != NULL)
// 		{
// 			node_channel->deinitialize();
// 			delete node_channel;
// 		}
// 	}
// 	node_channel_deque.clear();
// 	node_channel_map.clear();
// // No need
// 	// pthread_mutex_unlock(&node_channel_mtx);
	// map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
	// while (iter != node_channel_map.end())
	// {
	// 	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
	// 	iter++;
	// 	if (node_channel != NULL)
	// 	{
	// 		node_channel->deinitialize();
	// 		delete node_channel;
	// 	}
	// }
	// node_channel_map.clear();
	node_keepalive_map.clear();

	if (socketfd != 0)
	{
		close(socketfd);
		socketfd = 0;
	}
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	return ret;
}

unsigned short LeaderNode::recv(MessageType message_type, const std::string& message_data)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", ip.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (LeaderNode::*RECV_FUNC_PTR)(const std::string& message_data);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		NULL,
		&LeaderNode::recv_check_keepalive,
		&LeaderNode::recv_update_cluster_map,
		&LeaderNode::recv_transmit_text,
		&LeaderNode::recv_query_system_info,
		&LeaderNode::recv_control_fake_acspt,
		&LeaderNode::recv_control_fake_usrept
	};
	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	// fprintf(stderr, "Leader[%s] recv Message from remote: type: %d, data: %s\n", local_ip, message_type, message_data.c_str());
	return (this->*(recv_func_array[message_type]))(message_data);
}

unsigned short LeaderNode::send(MessageType message_type, void* param1, void* param2, void* param3)
{
	typedef unsigned short (LeaderNode::*SEND_FUNC_PTR)(void* param1, void* param2, void* param3);
	static SEND_FUNC_PTR send_func_array[] =
	{
		NULL,
		&LeaderNode::send_check_keepalive,
		&LeaderNode::send_update_cluster_map,
		&LeaderNode::send_transmit_text,
		&LeaderNode::send_query_system_info,
		&LeaderNode::send_control_fake_acspt,
		&LeaderNode::send_control_fake_usrept
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short LeaderNode::recv_check_keepalive(const std::string& message_data)
{
// Message format:
// EventType | Payload: Client IP| EOD
	const string& follower_ip = message_data;
	// fprintf(stderr, "KeepAlive follower_ip: %s\n", follower_ip.c_str());
	pthread_mutex_lock(&node_channel_mtx);
	map<string, int>::iterator iter = node_keepalive_map.find(follower_ip);
	if (iter == node_keepalive_map.end())
	{
		WRITE_FORMAT_ERROR("The Follower[%s] does NOT exist", follower_ip.c_str());
		return RET_FAILURE_INTERNAL_ERROR;
	}
	int cnt = node_keepalive_map[follower_ip];
	if (cnt < MAX_KEEPALIVE_CNT)
		node_keepalive_map[follower_ip]++;
	// fprintf(stderr, "KeepAlive[%s] Recv to counter: %d\n", follower_ip.c_str(), node_keepalive_map[follower_ip]);
	pthread_mutex_unlock(&node_channel_mtx);
	// fprintf(stderr, "Recv Check-Keepalive: %s:%d\n", message_data.c_str(), node_keepalive_map[message_data]);
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_update_cluster_map(const std::string& message_data){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_UPDATE_CLUSUTER_MAP);}

unsigned short LeaderNode::recv_transmit_text(const std::string& message_data)
{
	printf("Recv Text: %s\n", message_data.c_str());
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_query_system_info(const std::string& message_data)
{
// Message format:
// EventType | playload: (session ID[2 digits]|system info) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	size_t notify_param_size = strlen(message_data.c_str()) + 1;
	PNOTIFY_CFG notify_cfg = new NotifySystemInfoCfg((void*)message_data.c_str(), notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_SYSTEM_INFO, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_control_fake_acspt(const std::string& message_data){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_CONTROL_FAKE_ACSPT);}

unsigned short LeaderNode::recv_control_fake_usrept(const std::string& message_data){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_CONTROL_FAKE_USREPT);}

unsigned short LeaderNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | EOD
	unsigned short ret = RET_SUCCESS;
	bool follower_dead_found = false;
// Check if nodes in cluster are dead
	pthread_mutex_lock(&node_channel_mtx);
	// dump_node_channel_map();
	// dump_node_keepalive_map();
	map<string, int>::iterator iter = node_keepalive_map.begin();
	while (iter != node_keepalive_map.end())
	{
		string node_ip = (string)iter->first;
		if ((int)iter->second == 0)
		{
			// fprintf(stderr, "KeepAlive[%s]: counter is 0!\n", node_ip.c_str());
// Remove the node
			PNODE_CHANNEL node_channel = node_channel_map[node_ip];
			WRITE_FORMAT_WARN("The Follower[%s] is dead", node_channel->get_remote_ip());
			node_channel->deinitialize();
			node_channel_map.erase(node_ip);
			node_keepalive_map.erase(iter);

			ret = cluster_map.delete_node_by_ip(node_ip);
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Fail to delete the node[%s] in the map", node_ip.c_str());
				pthread_mutex_unlock(&node_channel_mtx);
				return ret;
			}
			follower_dead_found = true;
		}
		else
		{
			node_keepalive_map[node_ip]--;
			// fprintf(stderr, "KeepAlive[%s]: counter: %d\n", node_ip.c_str(), node_keepalive_map[node_ip]);
		}
		iter++;
	}
	// fprintf(stderr, "KeepAlive, After Check...\n");
	// dump_node_channel_map();
	// dump_node_keepalive_map();
	// fprintf(stderr, "KeepAlive, After Check...END\n");

	char* cluster_map_msg = NULL;
	if (follower_dead_found)
		cluster_map_msg = strdup(cluster_map.to_string());
	pthread_mutex_unlock(&node_channel_mtx);

// Update the cluster map to Followers
	if (follower_dead_found)
	{
		ret = send_data(MSG_UPDATE_CLUSUTER_MAP, cluster_map_msg);
		free(cluster_map_msg);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fail to send the message of updating the cluster map, due to: %s", GetErrorDescription(ret));
			return ret;
		}
	}

	return send_data(MSG_CHECK_KEEPALIVE);
}

unsigned short LeaderNode::send_update_cluster_map(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | cluster map string | EOD
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&node_channel_mtx);
	// fprintf(stderr, "LeaderNode::send_update_cluster_map %s, %d\n", cluster_map.to_string(), strlen(cluster_map.to_string()));
	string cluster_map_msg(cluster_map.to_string());
	// fprintf(stderr, "Leader: %s\n", cluster_map.to_string());
	pthread_mutex_unlock(&node_channel_mtx);
// Update the cluster map to Followers
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to assemble the message[%d, %s], due to: %s", MSG_UPDATE_CLUSUTER_MAP, cluster_map_msg.c_str(), GetErrorDescription(ret));
		return ret;
	}
	return send_data(MSG_UPDATE_CLUSUTER_MAP, cluster_map_msg.c_str());
}

unsigned short LeaderNode::send_transmit_text(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: text data
// param2: remote ip. NULL for broadcast
// Message format:
// EventType | text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}

	const char* text_data = (const char*)param1;
	const char* remote_ip = (const char*)param2;

	return send_data(MSG_TRANSMIT_TEXT, text_data, remote_ip);
}

unsigned short LeaderNode::send_query_system_info(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// param2: remote ip
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	const char* remote_ip = (const char*)param2;
	// fprintf(stderr, "remote_ip: %s\n", remote_ip);
	char buf[BUF_SIZE];
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_data(MSG_QUERY_SYSTEM_INFO, buf, remote_ip);
}

unsigned short LeaderNode::send_control_fake_acspt(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: simulator ap control type
// Message format:
// EventType | simulator ap control type | EOD
	const char* fake_acspt_control_type = (const char*)param1;
	return send_data(MSG_CONTROL_FAKE_ACSPT, fake_acspt_control_type);
}

unsigned short LeaderNode::send_control_fake_usrept(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: simulator ue control type
// Message format:
// EventType | simulator ue control type | EOD
	const char* fake_usrept_control_type = (const char*)param1;
	return send_data(MSG_CONTROL_FAKE_USREPT, fake_usrept_control_type);
}

unsigned short LeaderNode::set(ParamType param_type, void* param1, void* param2)
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

unsigned short LeaderNode::get(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	case PARAM_CLUSTER_MAP:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		ClusterMap& cluster_map_param = *(ClusterMap*)param1;
            pthread_mutex_lock(&node_channel_mtx);
            ret = cluster_map_param.copy(cluster_map);
            pthread_mutex_unlock(&node_channel_mtx);
    	}
    	break;
      	case PARAM_NODE_ID:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		if (cluster_node_id == 0)
    		{
     			WRITE_ERROR("The cluster_node_id should NOT be 0");
    			return RET_FAILURE_RUNTIME;   			
    		}
    		*(int*)param1 = cluster_node_id;
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

unsigned short LeaderNode::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
      	case NOTIFY_NODE_DIE:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
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

unsigned short LeaderNode::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
      	case NOTIFY_NODE_DIE:
    	{
    		// string follower_ip((char*)notify_cfg->get_notify_param());
    		string follower_ip(((PNOTIFY_NODE_DIE_CFG)notify_cfg)->get_remote_ip());
    		WRITE_FORMAT_WARN("The follower[%s] dies, remove the node from the cluster", follower_ip.c_str());
    		ret = remove_follower(follower_ip);
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

void LeaderNode::dump_node_channel_map()const
{
	map<std::string, PNODE_CHANNEL>::const_iterator iter = node_channel_map.begin();
	while (iter != node_channel_map.end())
	{
		string node_ip = (string)(iter->first);
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
		fprintf(stderr, "%s %p\n", node_ip.c_str(), (void*)node_channel);
		iter++;
	}
}

void LeaderNode::dump_node_keepalive_map()const
{
	map<std::string, int>::const_iterator iter = node_keepalive_map.begin();
	while (iter != node_keepalive_map.end())
	{
		string node_ip = (string)(iter->first);
		int keepalive_counter = (int)(iter->second);
		fprintf(stderr, "%s %d\n", node_ip.c_str(), keepalive_counter);
		iter++;
	}
}

void* LeaderNode::listen_thread_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->listen_thread_ret))
	{
		pthread_cleanup_push(listen_thread_cleanup_handler, pthis);
		pthis->listen_thread_ret = pthis->listen_thread_handler_internal();
		pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->listen_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->listen_thread_ret)));
	pthread_exit(NULL);
}

unsigned short LeaderNode::listen_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is running", listen_thread_tag);
	unsigned short ret = RET_SUCCESS;

	struct sockaddr client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	while (listen_exit == 0)
	{
		struct timeval tv;
		fd_set sock_set;
		tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&sock_set);
		FD_SET(socketfd, &sock_set);
		int res = select(socketfd + 1, &sock_set, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR)
		{
			WRITE_FORMAT_ERROR("[%s] select() fails, due to: %s", listen_thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			usleep(100000);
			continue;
		}		
// Follower connect to Leader
		int client_socketfd = accept(socketfd, &client_addr, (socklen_t*)&client_addr_len);
		if (client_socketfd < 0)
		{
			WRITE_FORMAT_ERROR("[%s] accept() fails, due to: %s", listen_thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		// deal with both IPv4 and IPv6:
		struct sockaddr_in *client_s = (struct sockaddr_in *)&client_addr;
		// PRINT("family: %d, port: %d\n", s->sin_family, ntohs(s->sin_port));
//		port = ntohs(s->sin_port);
		char client_ip[INET_ADDRSTRLEN + 1];
		inet_ntop(AF_INET, &client_s->sin_addr, client_ip, sizeof(client_ip));
		WRITE_FORMAT_INFO("[%s] Follower[%s] request connecting to the Leader", listen_thread_tag, client_ip);
		// PRINT("Follower[%s] connects to the Leader\n", ip);
// Initialize a channel for data transfer between follower
		PNODE_CHANNEL node_channel = new NodeChannel(this);
		if (node_channel == NULL)
		{
			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: node_channel", listen_thread_tag);
			// pthread_mutex_unlock(&node_channel_mtx);
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}

		WRITE_FORMAT_INFO("[%s] Initialize the Channel between Follower[%s] and Leader", listen_thread_tag, client_ip);
		ret = node_channel->initialize(client_socketfd, local_ip, client_ip);
		if (CHECK_FAILURE(ret))
		{
			// pthread_mutex_unlock(&node_channel_mtx);
			return ret;
		}
// Add a channel of the new follower
		pthread_mutex_lock(&node_channel_mtx);
		// node_channel_deque.push_back(node_channel);
		// dump_node_channel_map();
		// dump_node_keepalive_map();
		node_channel_map[client_ip] = node_channel;
		node_keepalive_map[client_ip] = MAX_KEEPALIVE_CNT;
		// dump_node_channel_map();
		// dump_node_keepalive_map();
// Update the cluster map in Leader
		ret = cluster_map.add_node(++cluster_node_cnt, client_ip);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: node_channel", listen_thread_tag);
			pthread_mutex_unlock(&node_channel_mtx);
			return ret;
		}
		string cluster_map_msg(cluster_map.to_string());
		pthread_mutex_unlock(&node_channel_mtx);
		PRINT("[%s] The Channel between Follower[%s] and Leader is Established......\n", listen_thread_tag, client_ip);
// Update the cluster map to Followers
		// fprintf(stderr, "LeaderNode::listen_thread_handler_internal %s, %d\n", cluster_map.to_string(), strlen(cluster_map.to_string()));
		ret = send_data(MSG_UPDATE_CLUSUTER_MAP, cluster_map_msg.c_str());
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("[%s] Fail to send the message of updating the cluster map, due to: %s", listen_thread_tag, GetErrorDescription(ret));
			return ret;
		}
		WRITE_FORMAT_INFO("[%s] Follower[%s] connects to the Leader...... successfully !!!", listen_thread_tag, client_ip);
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", listen_thread_tag);
	return ret;
}

void LeaderNode::listen_thread_cleanup_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->listen_thread_cleanup_handler_internal();
}

void LeaderNode::listen_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the listen thread......", listen_thread_tag);
	map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
	while (iter != node_channel_map.end())
	{
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
		iter++;
		if (node_channel != NULL)
		{
			node_channel->deinitialize();
			delete node_channel;
			node_channel = NULL;
		}
	}
	node_channel_map.clear();
}
