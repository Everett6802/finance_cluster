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
// #include "leader_send_thread.h"
// #include "node_recv_thread.h"


using namespace std;

const char* LeaderNode::thread_tag = "Listen Thread";
const int LeaderNode::WAIT_CONNECTION_TIMEOUT = 60; // 5 seconds
// DECLARE_MSG_DUMPER_PARAM();

LeaderNode::LeaderNode(const char* ip) :
	socketfd(0),
	local_ip(NULL),
	cluster_node_id(0),
	cluster_node_cnt(0),
	exit(0),
	listen_tid(0),
	thread_ret(RET_SUCCESS)
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
	server_address.sin_port = htons(PORT_NO);
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
	// printf("Node[%s] is a leader !!!\n", local_ip);

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

	pthread_mutex_lock(&mtx_node_channel);
	if (remote_ip != NULL)
	{
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
	pthread_mutex_unlock(&mtx_node_channel);
	return ret;
}

unsigned short LeaderNode::initialize()
{
	unsigned short ret = become_leader();
	if (CHECK_FAILURE(ret))
		return ret;

	mtx_node_channel = PTHREAD_MUTEX_INITIALIZER;
	// mtx_cluster_map = PTHREAD_MUTEX_INITIALIZER;
// Create a worker thread to access data...
	if (pthread_create(&listen_tid, NULL, thread_handler, this))
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
	__sync_fetch_and_add(&exit, 1);
	sleep(1);
// Check listen thread alive
	// bool listen_thread_alive = false;
	if (listen_tid != 0)
	{
		int kill_ret = pthread_kill(listen_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of sending message did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of sending message is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker thread of sending message is STILL alive");
			// listen_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(listen_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of receving message, due to: %s", strerror(errno));
			sleep(1);
		}
	}

	WRITE_DEBUG("Wait for the worker thread of sending message's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'status' variable accesses the illegal address
	// pthread_join(listen_tid, &status);
	// if (status == NULL)
	// 	sWRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	// else
	// {
	// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
	// 	return thread_ret;
	// }
// Wait for listen thread's death
	pthread_join(listen_tid, NULL);
	if (CHECK_SUCCESS(thread_ret))
		WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", GetErrorDescription(thread_ret));
		ret = thread_ret;
	}
	// }
// No need
// 	// pthread_mutex_lock(&mtx_node_channel);
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
// 	// pthread_mutex_unlock(&mtx_node_channel);
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
	};
	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
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
		&LeaderNode::send_transmit_text
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Notify Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short LeaderNode::recv_check_keepalive(const std::string& message_data)
{
// Message format:
// EventType | Payload: Client IP| EOD
	pthread_mutex_lock(&mtx_node_channel);
	int cnt = node_keepalive_map[message_data];
	if (cnt < MAX_KEEPALIVE_CNT)
		node_keepalive_map[message_data]++;
	pthread_mutex_unlock(&mtx_node_channel);
	fprintf(stderr, "Recv Check-Keepalive: %s:%d\n", message_data.c_str(), node_keepalive_map[message_data]);
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_update_cluster_map(const std::string& message_data){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_UPDATE_CLUSUTER_MAP);}

unsigned short LeaderNode::recv_transmit_text(const std::string& message_data)
{
	printf("Recv Text: %s\n", message_data.c_str());
	return RET_SUCCESS;
}

unsigned short LeaderNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | EOD
	unsigned short ret = RET_SUCCESS;
	bool follower_dead_found = false;
// Check if nodes in cluster are dead
	pthread_mutex_lock(&mtx_node_channel);
	fprintf(stderr, "Recv20: Send Cheek Keepalive\n");
	map<string, int>::iterator iter = node_keepalive_map.begin();
	while (iter != node_keepalive_map.end())
	{
		string node_ip = (string)iter->first;
		if ((int)iter->second == 0)
		{
// Remove the node
			PNODE_CHANNEL node_channel = node_channel_map[node_ip];
			WRITE_FORMAT_WARN("The Follower[%s] is dead", node_channel->get_remote_ip());
			node_channel->deinitialize();
			node_channel_map.erase(node_ip);
			node_keepalive_map.erase(iter++);

			ret = cluster_map.delete_node_by_ip(node_ip);
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Fail to delete the node[%s] in the map", node_ip.c_str());
				pthread_mutex_unlock(&mtx_node_channel);
				return ret;
			}
			follower_dead_found = true;
		}
		else
		{
			node_keepalive_map[node_ip]--;
			iter++;
		}
	}
	char* cluster_map_msg = NULL;
	if (follower_dead_found)
		cluster_map_msg = strdup(cluster_map.to_string());
	pthread_mutex_unlock(&mtx_node_channel);

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
	pthread_mutex_lock(&mtx_node_channel);
	string cluster_map_msg(cluster_map.to_string());
	pthread_mutex_unlock(&mtx_node_channel);
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

void* LeaderNode::thread_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->thread_ret))
	{
		pthread_cleanup_push(thread_cleanup_handler, pthis);
		pthis->thread_ret = pthis->thread_handler_internal();
		pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
	pthread_exit(NULL);
}

unsigned short LeaderNode::thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is running", thread_tag);
	unsigned short ret = RET_SUCCESS;

	struct sockaddr client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	while (exit == 0)
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
			WRITE_FORMAT_ERROR("select() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			continue;
		}		
// Follower connect to Leader
		int new_sd = accept(socketfd, &client_addr, (socklen_t*)&client_addr_len);
		if (new_sd < 0)
		{
			WRITE_FORMAT_ERROR("accept() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		// deal with both IPv4 and IPv6:
		struct sockaddr_in *s = (struct sockaddr_in *)&client_addr;
		// PRINT("family: %d, port: %d\n", s->sin_family, ntohs(s->sin_port));
//		port = ntohs(s->sin_port);
		char ip[INET_ADDRSTRLEN + 1];
		inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
		WRITE_FORMAT_INFO("[%s] Follower[%s] request connecting to the Leader", thread_tag, ip);
		// PRINT("Follower[%s] connects to the Leader\n", ip);
// Initialize a new thread for data transfer between follower
		PNODE_CHANNEL node_channel = new NodeChannel();
		if (node_channel == NULL)
		{
			WRITE_ERROR("Fail to allocate memory: node_channel");
			// pthread_mutex_unlock(&mtx_node_channel);
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}

		WRITE_FORMAT_INFO("[%s] Initialize the Channel between Follower[%s] and Leader", thread_tag, ip);
		ret = node_channel->initialize(this, new_sd, ip);
		if (CHECK_FAILURE(ret))
		{
			// pthread_mutex_unlock(&mtx_node_channel);
			return ret;
		}
// Add a channel of the new follower
		pthread_mutex_lock(&mtx_node_channel);
		// node_channel_deque.push_back(node_channel);
		node_channel_map[ip] = node_channel;
		node_keepalive_map[ip] = MAX_KEEPALIVE_CNT;
// Update the cluster map in Leader
		ret = cluster_map.add_node(++cluster_node_cnt, ip);
		if (CHECK_FAILURE(ret))
		{
			WRITE_ERROR("Fail to allocate memory: node_channel");
			pthread_mutex_unlock(&mtx_node_channel);
			return ret;
		}
		string cluster_map_msg(cluster_map.to_string());
		pthread_mutex_unlock(&mtx_node_channel);
		PRINT("The Channel between Follower[%s] and Leader is Established......\n", ip);
// Update the cluster map to Followers
		ret = send_data(MSG_UPDATE_CLUSUTER_MAP, cluster_map_msg.c_str());
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fail to send the message of updating the cluster map, due to: %s", GetErrorDescription(ret));
			return ret;
		}
		WRITE_FORMAT_INFO("[%s] Follower[%s] connects to the Leader...... successfully !!!", thread_tag, ip);
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", thread_tag);
	return ret;
}

void LeaderNode::thread_cleanup_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->thread_cleanup_handler_internal();
}

void LeaderNode::thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the listen thread......", thread_tag);
	map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
	while (iter != node_channel_map.end())
	{
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
		iter++;
		if (node_channel != NULL)
		{
			node_channel->deinitialize();
			delete node_channel;
		}
	}
	node_channel_map.clear();
}