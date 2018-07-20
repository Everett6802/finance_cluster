// #include <errno.h>
// #include <assert.h>
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
// DECLARE_MSG_DUMPER_PARAM();

LeaderNode::LeaderNode(const char* ip) :
	NodeBase(ip),
	socketfd(0),
	cluster_node_cnt(0),
	exit(0),
	listen_tid(0),
	// client_recv_thread_deque(NULL),
	// client_send_thread(NULL),
	thread_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()

	// if (ip == NULL)
	// 	throw invalid_argument(string("ip == NULL"));
	// // int ip_len = strlen(ip) + 1;
	// // local_ip = new char[ip_len];
	// // if (local_ip == NULL)
	// // 	throw bad_alloc();
	// // memcpy(local_ip, ip, sizeof(char) * ip_len);
	// local_ip = strdup(ip);
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

	RELEASE_MSG_DUMPER()
}

unsigned short LeaderNode::become_leader()
{
	unsigned short ret = RET_SUCCESS;
// Create socket
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
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
	if (bind(sock_fd, (struct sockaddr*)&server_address, server_len) == -1)
	{
		WRITE_FORMAT_ERROR("bind() fail, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
// Listen
	if (listen(sock_fd, MAX_CONNECTED_CLIENT) == -1)
	{
		WRITE_FORMAT_ERROR("listen() fail, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	socketfd = sock_fd;
	cluster_node_id = 1;
	cluster_node_cnt = 1;

	WRITE_FORMAT_INFO("Node[%s] is a Leader", local_ip);
	printf("Node[%s] is a leader !!!\n", local_ip);

	return ret;
}

unsigned short LeaderNode::initialize()
{
	unsigned short ret = become_leader();
	if (CHECK_FAILURE(ret))
		return ret;

// 	client_recv_thread_deque = new deque<NodeRecvThread*>();
// 	if (client_recv_thread_deque == NULL)
// 	{
// 		WRITE_ERROR("Fail to allocate the memory: client_recv_thread_deque");
// 		return RET_FAILURE_INSUFFICIENT_MEMORY;
// 	}
// // Initialize a thread to send the message to the remote
// 	client_send_thread = new LeaderSendThread();
// 	if (client_send_thread == NULL)
// 	{
// 		WRITE_ERROR("Fail to allocate the memory: client_send_thread");
// 		return RET_FAILURE_INSUFFICIENT_MEMORY;
// 	}

// 	ret = client_send_thread->initialize(this);
// 	if (CHECK_FAILURE(ret))
// 		goto OUT;

	mtx_node_channel = PTHREAD_MUTEX_INITIALIZER;
// Create a worker thread to access data...
	if (pthread_create(&listen_tid, NULL, thread_handler, this))
	{
		WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting client, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
// OUT:
//     if (client_send_thread != NULL)
//     {
//     	delete client_send_thread;
//     	client_send_thread = NULL;
//     }
// 	if (client_recv_thread_deque != NULL)
// 	{
// 		delete client_recv_thread_deque;
// 		client_recv_thread_deque = NULL;
// 	}

    return ret;
}

unsigned short LeaderNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	void* status;
	int kill_ret;
  //   if (client_send_thread != NULL)
  //   {
  //   	client_send_thread->deinitialize();
		// if (CHECK_FAILURE(ret))
		// 	return ret;

  //   	delete client_send_thread;
  //   	client_send_thread = NULL;
  //   }
// Check listen thread alive
	bool listen_thread_alive = false;
	if (listen_tid != 0)
	{
		kill_ret = pthread_kill(listen_tid, 0);
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
			listen_thread_alive = true;
		}
	}

// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&exit, 1);
// Wait for listen thread's death
	if (listen_thread_alive)
	{
		WRITE_DEBUG("Wait for the worker thread of sending message's death...");
		pthread_join(listen_tid, &status);
		if (status == NULL)
			WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
			return thread_ret;
		}
	}
// No need
	// pthread_mutex_lock(&mtx_node_channel);
	deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
	while (iter != node_channel_deque.end())
	{
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
		iter++;
		if (node_channel != NULL)
		{
			node_channel->deinitialize();
			delete node_channel;
		}
	}
	node_channel_deque.clear();
	node_channel_map.clear();
// No need
	// pthread_mutex_unlock(&mtx_node_channel);

	if (socketfd != 0)
	{
		close(socketfd);
		socketfd = 0;
	}
	return ret;
}

unsigned short LeaderNode::check_keepalive()
{
	return send_data(CHECK_KEEPALIVE_TAG);
}

unsigned short LeaderNode::update(const std::string ip, const std::string message)
{
	WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", ip.c_str(), message.c_str(), (int)message.length());
	unsigned short ret = RET_SUCCESS;

	return ret;
}

unsigned short LeaderNode::notify(NotifyType notify_type)
{
	switch (notify_type)
	{
	case NOTIFY_DEAD_CLIENT:
	{
		// assert(client_send_thread != NULL && "client_send_thread should NOT be NULL");
		// assert(client_recv_thread_deque != NULL && "client_recv_thread_deque should NOT be NULL");

		// const std::deque<int>& dead_client_index_deque = client_send_thread->get_dead_client_index_deque();
		// pthread_mutex_lock(&mtx_node_channel);
		// int client_recv_thread_deque_size = (int)client_recv_thread_deque->size();
		// std::deque<int>::const_iterator iter = dead_client_index_deque.begin();
		// while (iter != dead_client_index_deque.end())
		// {
		// 	int index = (int)*iter++;
		// 	assert ((index >= 0 && index < client_recv_thread_deque_size) && "index is out of range");

		// 	NodeRecvThread* thread = (NodeRecvThread*)*client_recv_thread_deque->erase(client_recv_thread_deque->begin() + index);
		// 	assert (thread != NULL && "thread should NOT be NULL");
		// 	WRITE_FORMAT_DEBUG("Remove the worker thread of receiving message from %s", thread->get_ip().c_str());
		// 	unsigned short ret = thread->deinitialize();
		// 	if (CHECK_FAILURE(ret))
		// 		WRITE_FORMAT_WARN("Fail to de-initialied the worker thread of receiving message from %s", thread->get_ip().c_str());
		// 	delete thread;
		// }
		// pthread_mutex_unlock(&mtx_node_channel);
	}
	break;
	default:
	{
		WRITE_FORMAT_ERROR("Unknown Notify Type: %d", notify_type);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	break;
	}

	return RET_SUCCESS;
}

unsigned short LeaderNode::send_data(const char* data, const char* remote_ip)
{
	unsigned short ret = RET_SUCCESS;
	assert(data != NULL && "data should NOT be NULL");
	pthread_mutex_lock(&mtx_node_channel);
	if (remote_ip != NULL)
	{
// Send to single node
		PNODE_CHANNEL node_channel = node_channel_map[remote_ip];
		assert(node_channel != NULL && "node_channel should NOT be NULL");
		ret = node_channel->send_msg(data);
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", remote_ip, GetErrorDescription(ret));
	}
	else
	{
// Send to all nodes
		deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
		while(iter != node_channel_deque.end())
		{
			PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
			assert(node_channel != NULL && "node_channel should NOT be NULL");
			ret = node_channel->send_msg(data);
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

void* LeaderNode::thread_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
}

unsigned short LeaderNode::thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is running", thread_tag);
	unsigned short ret = RET_SUCCESS;

	struct sockaddr client_address;
	int client_len;
	while (!exit)
	{
		int sockfd = accept(socketfd, &client_address, (socklen_t*)&client_len);
		if (client_address.sa_family != AF_INET) // AF_INET6
		{
//			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_address;
//			port = ntohs(s->sin6_port);
//			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
			WRITE_FORMAT_ERROR("[%s] Unsupported socket type: %d", thread_tag, client_address.sa_family);
			return RET_FAILURE_INCORRECT_OPERATION;
		}

		// deal with both IPv4 and IPv6:
		struct sockaddr_in *s = (struct sockaddr_in *)&client_address;
//		port = ntohs(s->sin_port);
		char ip[INET_ADDRSTRLEN + 1];
		inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
		WRITE_FORMAT_INFO("[%s] Follower[%s] request connecting to the Leader", thread_tag, ip);
		printf("Follower[%s] connects to the Leader\n", ip);

// // Initialize a new thread to receive the message
// 		NodeRecvThread* node_recv_thread = new NodeRecvThread();
// 		if (node_recv_thread == NULL)
// 		{
// 			WRITE_FORMAT_ERROR("[%s]Fail to allocate memory: node_recv_thread", thread_tag);
// 			return RET_FAILURE_INCORRECT_OPERATION;
// 		}
// 		ret = node_recv_thread->initialize(this, sockfd, ip);
// 		if (CHECK_FAILURE(ret))
// 			break;
// 		pthread_mutex_lock(&mtx_node_channel);
// 		client_recv_thread_deque->push_back(node_recv_thread);
// 		pthread_mutex_unlock(&mtx_node_channel);

// // Add into the list of sending message
// 		ret = client_send_thread->add_client(ip, sockfd);
// 		if (CHECK_FAILURE(ret))
// 			break;

// Initialize a new thread for data transfer between follower
		PNODE_CHANNEL node_channel = new NodeChannel();
		if (node_channel == NULL)
		{
			WRITE_ERROR("Fail to allocate memory: node_channel");
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}

		ret = node_channel->initialize(this, sockfd, ip);
		if (CHECK_FAILURE(ret))
			return ret;

		pthread_mutex_lock(&mtx_node_channel);
		node_channel_deque.push_back(node_channel);
		node_channel_map[ip] = node_channel;
		pthread_mutex_unlock(&mtx_node_channel);

		WRITE_FORMAT_INFO("[%s] Follower[%s] connects to the Leader...... successfully !!!", thread_tag, ip);
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", thread_tag);
	return ret;
}
