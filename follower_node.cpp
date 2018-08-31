// #include <unistd.h>
#include <fcntl.h>
// #include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "follower_node.h"
// #include "node_recv_thread.h"


using namespace std;

const int FollowerNode::WAIT_CONNECTION_TIMEOUT = 5; // 5 seconds
const int FollowerNode::TRY_TIMES = 3;
const int FollowerNode::CHECK_KEEPALIVE_TIMES = 4;
const int FollowerNode::TOTAL_KEEPALIVE_PERIOD = KEEPALIVE_PERIOD * CHECK_KEEPALIVE_TIMES;
// DECLARE_MSG_DUMPER_PARAM();

FollowerNode::FollowerNode(const char* server_ip, const char* ip) :
	// NodeBase(ip),
	socketfd(0),
	node_channel(NULL)
{
	IMPLEMENT_MSG_DUMPER()

	if (server_ip == NULL || ip == NULL)
		throw invalid_argument(string("server_ip/ip == NULL"));
	if (ip == NULL)
		throw invalid_argument(string("ip == NULL"));
	local_ip = strdup(ip);
	cluster_ip = strdup(server_ip);
}

FollowerNode::~FollowerNode()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in FollowerNode::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(string(errmsg));
	}

	RELEASE_MSG_DUMPER()
}

unsigned short FollowerNode::connect_leader()
{
	WRITE_FORMAT_DEBUG("Try to connect to %s......", cluster_ip);

// Create socket
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

// Set non-blocking
	long sock_arg;
	if((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
	{
		WRITE_FORMAT_ERROR("fcntl(F_GETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	sock_arg |= O_NONBLOCK;
	if(fcntl(sock_fd, F_SETFL, sock_arg) < 0)
	{
		WRITE_FORMAT_ERROR("fcntl(F_SETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

	sockaddr_in client_address;
	memset(&client_address, 0x0, sizeof(struct sockaddr_in));
	client_address.sin_family = AF_INET;
	client_address.sin_port = htons(PORT_NO);
	client_address.sin_addr.s_addr = inet_addr(cluster_ip);
	int res = connect(sock_fd, (struct sockaddr*)&client_address, sizeof(struct sockaddr));
	if (res < 0)
	{
		if (errno == EINPROGRESS)
		{
			WRITE_DEBUG("Connection is NOT established......");
			struct timeval tv;
			fd_set sock_set;

			tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
			tv.tv_usec = 0;

			FD_ZERO(&sock_set);
			FD_SET(sock_fd, &sock_set);
			res = select(sock_fd + 1, NULL, &sock_set, NULL, &tv);
			if (res < 0 && errno != EINTR)
			{
				WRITE_FORMAT_ERROR("select() fails, due to: %s", strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
			else if (res > 0)
			{
// Socket selected for writing
				int error;
				socklen_t error_len = sizeof(error);
				if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (void*)&error, &error_len) < 0)
				{
					WRITE_FORMAT_ERROR("getsockopt() fails, due to: %s", strerror(errno));
					return RET_FAILURE_SYSTEM_API;
				}
// Check the value returned...
				if (error)
				{
					WRITE_FORMAT_ERROR("Error in delayed connection(), due to: %s", strerror(error));
					return RET_FAILURE_SYSTEM_API;
				}
			}
			else
			{
				WRITE_DEBUG("Connection timeout");
				return RET_FAILURE_CONNECTION_TRY_TIMEOUT;
			}
		}
		else
		{
			WRITE_FORMAT_ERROR("connect() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
	}

// Set to blocking mode again...
	if ((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
	{
		WRITE_FORMAT_ERROR("fcntl(F_GETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	sock_arg &= (~O_NONBLOCK);
	if (fcntl(sock_fd, F_SETFL, sock_arg) < 0)
	{
		WRITE_FORMAT_ERROR("fcntl(F_SETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", cluster_ip);
	socketfd = sock_fd;

	return RET_SUCCESS;
}

unsigned short FollowerNode::become_follower()
{
// Try to connect to the designated server
	unsigned short ret = connect_leader();
	if (IS_TRY_CONNECTION_TIMEOUT(ret))
	{
		WRITE_FORMAT_DEBUG("Node[%s] is NOT a server", cluster_ip);
		return RET_FAILURE_CONNECTION_TRY_TIMEOUT;
	}
	else
	{
		if (CHECK_FAILURE(ret))
			return ret;
	}

	WRITE_FORMAT_INFO("Node[%s] is a Follower", local_ip);
	printf("Node[%s] is a Follower, connect to Leader[%s] !!!\n", local_ip, cluster_ip);

	return ret;
}

unsigned short LeaderNode::send_data(const char* data)
{
	unsigned short ret = RET_SUCCESS;
	assert(data != NULL && "data should NOT be NULL");
	pthread_mutex_lock(&mtx_node_channel);
// Send to leader
	assert(node_channel != NULL && "node_channel should NOT be NULL");
	ret = node_channel->send_msg(data);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fail to send data to the Leader[%s], due to: %s", cluster_ip, GetErrorDescription(ret));
	pthread_mutex_unlock(&mtx_node_channel);
	return ret;
}

// unsigned short FollowerNode::find_leader()
// {
// 	unsigned short ret = RET_SUCCESS;
// 	for (int i = 0 ; i < TRY_TIMES ; i++)
// 	{
// 		CHAR_LIST::iterator iter = server_list.begin();
// 		while (iter != server_list.end())
// 		{
// 			char* cluster_ip = (char*)*iter++;
// 			if (cluster_ip == NULL)
// 			{
// 				WRITE_ERROR("Server IP should NOT be NULL");
// 				return RET_FAILURE_INVALID_POINTER;
// 			}
// 			if (strcmp(local_ip, cluster_ip) == 0)
// 				continue;
// 			ret = become_follower(cluster_ip);
// // The node become a follower successfully
// 			if (CHECK_SUCCESS(ret))
// 				goto OUT;
// 			else
// 			{
// // Check if time-out occurs while trying to connect to the remote node
// 				if (!IS_TRY_CONNECTION_TIMEOUT(ret))
// 					goto OUT;
// 			}
// 		}
// 	}
// OUT:
// 	return ret;
// }

unsigned short FollowerNode::initialize()
{
// Try to find the leader node
	unsigned short ret = RET_SUCCESS;
	for (int i = 0 ; i < TRY_TIMES ; i++)
	{
		ret = become_follower();
// The node become a follower successfully
		if (CHECK_SUCCESS(ret))
			break;
		else
		{
// Check if time-out occurs while trying to connect to the remote node
			if (!IS_TRY_CONNECTION_TIMEOUT(ret))
				break;
		}
	}

	if (CHECK_FAILURE(ret))
	{
		if (!IS_TRY_CONNECTION_TIMEOUT(ret))
			WRITE_FORMAT_ERROR("Error occur while Node[%s]'s trying to connect to server", local_ip);
		else
			WRITE_FORMAT_WARN("Node[%s] try to search for the leader, buf time-out...", local_ip);
		return ret;
	}

// Start a timer to check keep-alive
	keepalive_cnt = MAX_KEEPALIVE_CNT;

// Create a thread of accessing the data
	node_channel = new NodeChannel();
	if (node_channel == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: node_channel");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	return node_channel->initialize(this, socketfd, local_ip);
}

unsigned short FollowerNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	if (node_channel != NULL)
	{
		ret = node_channel->deinitialize();
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fail to de-initialize the node channel worker thread[Node: %s]", local_ip);
			return ret;
		}
		delete node_channel;
		node_channel = NULL;
	}

	if (socketfd != 0)
	{
		close(socketfd);
		socketfd = 0;
	}
	if (cluster_ip != NULL)
	{
		free(cluster_ip);
		cluster_ip = NULL;
	}
	if (local_ip != NULL)
	{
		// delete[] local_ip;
		free(local_ip);
		local_ip = NULL;
	}

	return RET_SUCCESS;
}

unsigned short FollowerNode::recv(MessageType message_type, const str::string& message_data)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", ip.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (FollowerNode::*RECV_FUNC_PTR)(const str::string& message_data);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		&FollowerNode::recv_check_keepalive
	};
	if (message_type < 0 || message_type >= NOTIFY_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Notify Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(recv_func_array[message_type]))(message_data);
}

unsigned short FollowerNode::send(MessageType message_type, void* param1, void* param2, void* param3)
{
	typedef unsigned short (FollowerNode::*SEND_FUNC_PTR)(void* param1, void* param2, void* param3);
	static SEND_FUNC_PTR send_func_array[] =
	{
		&FollowerNode::send_check_keepalive
	};

	if (message_type < 0 || message_type >= NOTIFY_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Notify Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short FollowerNode::recv_check_keepalive(const str::string& message_data)
{
// Message format:
// EventType | Payload: Client IP| EOD
	pthread_mutex_lock(&mtx_node_channel);
	if (cnt < MAX_KEEPALIVE_CNT)
		keepalive_cnt++;
	pthread_mutex_unlock(&mtx_node_channel);
	return RET_SUCCESS;
}

unsigned short FollowerNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
	if (keepalive_cnt == 0)
	{
		WRITE_FORMAT_ERROR("Follower[%s] got no response from Leader[%S]", local_ip, cluster_ip);
		return RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
	}

	char msg = (char)MSG_CHECK_KEEPALIVE;
	return send_data(&msg);
}

// unsigned short FollowerNode::check_keepalive()
// {
// 	if (keepalive_cnt == 0)
// 	{
// 		WRITE_FORMAT_WARN("Leader does NOT response for %d seconds, try to connect to another leader....", TOTAL_KEEPALIVE_PERIOD);
// 		return RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
// 	}
// 	__sync_fetch_and_sub(&keepalive_cnt, 1);
// 	WRITE_FORMAT_DEBUG("Check keep-alive....... %d", keepalive_cnt);

// 	return RET_SUCCESS;
// }


// bool FollowerNode::is_keepalive_packet(const std::string message)const
// {
// 	return (message.compare(0, CHECK_KEEPALIVE_TAG_LEN, CHECK_KEEPALIVE_TAG) == 0 ? true : false);
// }
