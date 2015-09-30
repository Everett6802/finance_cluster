#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>
#include "msg_cluster_leader_node.h"
#include "msg_cluster_leader_send_thread.h"
#include "msg_cluster_node_recv_thread.h"


using namespace std;

const char* MsgClusterLeaderNode::thread_tag = "Listen Thread";

MsgClusterLeaderNode::MsgClusterLeaderNode(char* ip) :
	exit(false),
	pid(0),
	leader_socket(0),
	client_recv_thread_list(NULL),
	client_send_thread(NULL),
	thread_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()

	if (ip == NULL)
		throw invalid_argument(string("ip == NULL"));
	int ip_len = strlen(ip) + 1;
	local_ip = new char[ip_len];
	if (local_ip == NULL)
		throw bad_alloc();
	memcpy(local_ip, ip, sizeof(char) * ip_len);
}

MsgClusterLeaderNode::~MsgClusterLeaderNode()
{
	if (leader_socket != 0)
	{
		close(leader_socket);
		leader_socket = 0;
	}

	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterLeaderNode::become_leader()
{
	unsigned short ret = RET_SUCCESS;
// Create socket
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "socket() fails, due to: %s", strerror(errno));
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
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "bind() fail, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
// Listen
	if (listen(sock_fd, MAX_CONNECTED_CLIENT) == -1)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "listen() fail, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	leader_socket = sock_fd;

	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "Node[%s] is a Leader", local_ip);
	printf("Node[%s] is a leader !!!\n", local_ip);

	return ret;
}

unsigned short MsgClusterLeaderNode::initialize()
{
	unsigned short ret = become_leader();
	if (CHECK_FAILURE(ret))
		return ret;

	client_recv_thread_list = new list<MsgClusterNodeRecvThread*>();
	if (client_recv_thread_list == NULL)
	{
		WRITE_ERROR("Fail to allocate the memory: client_recv_thread_list");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
// Initialize a thread to send the message to the remote
	client_send_thread = new MsgClusterLeaderSendThread();
	if (client_send_thread == NULL)
	{
		WRITE_ERROR("Fail to allocate the memory: client_send_thread");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	ret = client_send_thread->initialize(this);
	if (CHECK_FAILURE(ret))
		goto OUT;

	mtx_thread_list = PTHREAD_MUTEX_INITIALIZER;
// Create a worker thread to access data...
	if (pthread_create(&pid, NULL, thread_handler, this))
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Fail to create a worker thread of accepting client, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
OUT:
    if (client_send_thread != NULL)
    {
    	delete client_send_thread;
    	client_send_thread = NULL;
    }
	if (client_recv_thread_list != NULL)
	{
		delete client_recv_thread_list;
		client_recv_thread_list = NULL;
	}

    return ret;
}

unsigned short MsgClusterLeaderNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
    if (client_send_thread != NULL)
    {
    	client_send_thread->deinitialize();
		if (CHECK_FAILURE(ret))
			return ret;

    	delete client_send_thread;
    	client_send_thread = NULL;
    }

	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::check_keepalive()
{
	assert(client_send_thread != NULL && "client_send_thread should NOT be NULL");
	if (client_send_thread->follower_connected())
	{
		WRITE_DEBUG("Time to notify Followers that Leader is still alive......");
		client_send_thread->check_keepalive();
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::update(const std::string ip, const std::string message)
{
	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Leader got the message from the Follower[%s], data: %s, size: %d", ip.c_str(), message.c_str(), (int)message.length());
	assert(client_send_thread != NULL && "client_send_thread should NOT be NULL");
	unsigned short ret = client_send_thread->send_msg(ip, message);

	return ret;
}

unsigned short MsgClusterLeaderNode::notify(NotifyType notify_type)
{
	return RET_SUCCESS;
}

void* MsgClusterLeaderNode::thread_handler(void* pvoid)
{
	MsgClusterLeaderNode* pthis = (MsgClusterLeaderNode*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));

}

unsigned short MsgClusterLeaderNode::thread_handler_internal()
{
	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] The worker thread of listening socket is running", thread_tag);
	unsigned short ret = RET_SUCCESS;

	struct sockaddr client_address;
	int client_len;
	while (!exit)
	{
		int sockfd = accept(leader_socket, &client_address, (socklen_t*)&client_len);
		if (client_address.sa_family != AF_INET) // AF_INET6
		{
//			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&client_address;
//			port = ntohs(s->sin6_port);
//			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "[%s] Unsupported socket type: %d", thread_tag, client_address.sa_family);
			return RET_FAILURE_INCORRECT_OPERATION;
		}

		// deal with both IPv4 and IPv6:
		struct sockaddr_in *s = (struct sockaddr_in *)&client_address;
//		port = ntohs(s->sin_port);
		char ip[INET_ADDRSTRLEN + 1];
		inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
		WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] Follower[%s] request connecting to the Leader", thread_tag, ip);
		printf("Follower[%s] connects to the Leader\n", ip);

// Initialize a new thread to receive the message
		MsgClusterNodeRecvThread* msg_cluster_node_recv_thread = new MsgClusterNodeRecvThread();
		if (msg_cluster_node_recv_thread == NULL)
		{
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "[%s]Fail to allocate memory: msg_cluster_node_recv_thread", thread_tag);
			return RET_FAILURE_INCORRECT_OPERATION;
		}
		ret = msg_cluster_node_recv_thread->initialize(this, sockfd, ip);
		if (CHECK_FAILURE(ret))
			break;
		pthread_mutex_lock(&mtx_thread_list);
		client_recv_thread_list->push_back(msg_cluster_node_recv_thread);
		pthread_mutex_unlock(&mtx_thread_list);

// Add into the list of sending message
		ret = client_send_thread->add_client(ip, sockfd);
		if (CHECK_FAILURE(ret))
			break;

		WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] Follower[%s] connects to the Leader...... successfully !!!", thread_tag, ip);
	}

	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] The worker thread of listening socket is dead", thread_tag);
	return ret;
}
