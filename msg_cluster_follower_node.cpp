#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include "msg_cluster_follower_node.h"
#include "msg_cluster_node_recv_thread.h"


using namespace std;

const int MsgClusterFollowerNode::WAIT_CONNECTION_TIMEOUT = 5; // 5 seconds
const int MsgClusterFollowerNode::TRY_TIMES = 3;
const int MsgClusterFollowerNode::CHECK_KEEPALIVE_TIMES = 4;
const int MsgClusterFollowerNode::TOTAL_KEEPALIVE_PERIOD = KEEPALIVE_PERIOD * CHECK_KEEPALIVE_TIMES;

MsgClusterFollowerNode::MsgClusterFollowerNode(const PCHAR_LIST alist, char* ip) :
	msg_recv_thread(NULL),
	server_candidate_id(0),
	follower_socket(0)
{
	IMPLEMENT_MSG_DUMPER()

	if (alist == NULL || ip == NULL)
		throw invalid_argument(string("alist/ip == NULL"));

	CHAR_LIST::iterator iter = alist->begin();
	while (iter != alist->end())
	{
		int len = strlen(*iter) + 1;
		char* new_ip = new char[len];
		if (new_ip == NULL)
			throw bad_alloc();
		memcpy(new_ip, *iter, sizeof(char) * len);
		server_list.push_back(new_ip);
		iter++;
	}

	int ip_len = strlen(ip) + 1;
	local_ip = new char[ip_len];
	if (local_ip == NULL)
		throw bad_alloc();
	memcpy(local_ip, ip, sizeof(char) * ip_len);
}

MsgClusterFollowerNode::~MsgClusterFollowerNode()
{
	if (follower_socket != 0)
	{
		close(follower_socket);
		follower_socket = 0;
	}

	list<char*>::iterator iter = server_list.begin();
	while (iter != server_list.end())
		delete [] (char*)*iter++;
	server_list.clear();

	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterFollowerNode::initialize()
{
// Try to find the leader node
	unsigned short ret = find_leader();
	if (CHECK_FAILURE(ret))
	{
		if (!IS_TRY_CONNECTION_TIMEOUT(ret))
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Error occur while Node[%s]'s trying to connect to server", local_ip);
		else
			WRITE_FORMAT_WARN(LONG_STRING_SIZE, "Node[%s] try to search for the leader, buf time-out...", local_ip);
		return ret;
	}

// Start a timer to check keep-alive
	keepalive_counter = CHECK_KEEPALIVE_TIMES;

	return RET_SUCCESS;
}

unsigned short MsgClusterFollowerNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	if (msg_recv_thread != NULL)
	{
		ret = msg_recv_thread->deinitialize();
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Fail to de-initialize the receiving message worker thread[Node: %s]", local_ip);
			return ret;
		}
		delete msg_recv_thread;
		msg_recv_thread = NULL;
	}

	if (follower_socket != 0)
	{
		close(follower_socket);
		follower_socket = 0;
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterFollowerNode::check_keepalive()
{
	if (keepalive_counter == 0)
	{
		WRITE_FORMAT_WARN(LONG_STRING_SIZE, "Leader does NOT response for %d seconds, try to connect to another leader....", TOTAL_KEEPALIVE_PERIOD);
		return RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
	}
	__sync_fetch_and_sub(&keepalive_counter, 1);
	WRITE_FORMAT_DEBUG(STRING_SIZE, "Check keep-alive....... %d", keepalive_counter);

	return RET_SUCCESS;
}

unsigned short MsgClusterFollowerNode::connect_leader(const char* server_ip)
{
	if (server_ip == NULL)
	{
		WRITE_ERROR("Server IP should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Try to connect to %s......", server_ip);

// Create socket
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "socket() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

// Set non-blocking
	long sock_arg;
	if((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "fcntl(F_GETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	sock_arg |= O_NONBLOCK;
	if(fcntl(sock_fd, F_SETFL, sock_arg) < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "fcntl(F_SETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

	sockaddr_in client_address;
	memset(&client_address, 0x0, sizeof(struct sockaddr_in));
	client_address.sin_family = AF_INET;
	client_address.sin_port = htons(PORT_NO);
	client_address.sin_addr.s_addr = inet_addr(server_ip);
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
				WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "select() fails, due to: %s", strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
			else if (res > 0)
			{
// Socket selected for writing
				int error;
				socklen_t error_len = sizeof(error);
				if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (void*)&error, &error_len) < 0)
				{
					WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "getsockopt() fails, due to: %s", strerror(errno));
					return RET_FAILURE_SYSTEM_API;
				}
// Check the value returned...
				if (error)
				{
					WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Error in delayed connection(), due to: %s", strerror(error));
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
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "connect() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
	}

// Set to blocking mode again...
	if ((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "fcntl(F_GETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	sock_arg &= (~O_NONBLOCK);
	if (fcntl(sock_fd, F_SETFL, sock_arg) < 0)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "fcntl(F_SETFL) fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Try to connect to %s......Successfully", server_ip);
	follower_socket = sock_fd;

	return RET_SUCCESS;
}

unsigned short MsgClusterFollowerNode::become_follower(const char* server_ip)
{
// Try to connect to the designated server
	unsigned short ret = connect_leader(server_ip);
	if (IS_TRY_CONNECTION_TIMEOUT(ret))
	{
		WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Node[%s] is NOT a server", server_ip);
		return RET_FAILURE_CONNECTION_TRY_TIMEOUT;
	}
	else
	{
		if (CHECK_FAILURE(ret))
			return ret;
	}

	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "Node[%s] is a Follower", local_ip);
	printf("Node[%s] is a Follower, connect to Leader[%s] !!!\n", local_ip, server_ip);

// Create a thread to receive the remote data
	msg_recv_thread = new MsgClusterNodeRecvThread();
	if (msg_recv_thread == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: msg_recv_thread");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	return msg_recv_thread->initialize(this, follower_socket, local_ip);
}

unsigned short MsgClusterFollowerNode::find_leader()
{
	unsigned short ret = RET_SUCCESS;
	for (int i = 0 ; i < TRY_TIMES ; i++)
	{
		CHAR_LIST::iterator iter = server_list.begin();
		while (iter != server_list.end())
		{
			char* server_ip = (char*)*iter++;
			if (server_ip == NULL)
			{
				WRITE_ERROR("Server IP should NOT be NULL");
				return RET_FAILURE_INVALID_POINTER;
			}
			if (strcmp(local_ip, server_ip) == 0)
				continue;
			ret = become_follower(server_ip);
// The node become a follower successfully
			if (CHECK_SUCCESS(ret))
				goto OUT;
			else
			{
// Check if time-out occurs while trying to connect to the remote node
				if (!IS_TRY_CONNECTION_TIMEOUT(ret))
					goto OUT;
			}
		}
	}
OUT:
	return ret;
}

bool MsgClusterFollowerNode::is_keepalive_packet(const std::string message)const
{
	return (message.compare(0, CHECK_KEEPALIVE_TAG_LEN, CHECK_KEEPALIVE_TAG) == 0 ? true : false);
}

unsigned short MsgClusterFollowerNode::update(const char* ip, const std::string message)
{
	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Follower[%s] got the message from the Leader, data: %s, size: %d", ip, message.c_str(), message.length());
	if (server_candidate_id == 0)
	{
		if (message.compare(0, CHECK_SERVER_CANDIDATE_TAG_LEN, CHECK_SERVER_CANDIDATE_TAG) == 0)
		{
			size_t pos = message.find(":");
			if (pos == string::npos)
			{
				WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Incorrect config format, the message of getting server candidate ID: %s", message.c_str());
				return RET_FAILURE_INCORRECT_CONFIG;
			}

			server_candidate_id = atoi(message.substr(pos + 1).c_str());
			WRITE_FORMAT_INFO(LONG_STRING_SIZE, "Follower[%s] got server candidate id: %d", ip, server_candidate_id);
			return RET_SUCCESS;
		}
	}

	if (is_keepalive_packet(message))
	{
		WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Follower[%s] receive a Check-Alive packet......", ip);
// Reset the keep-alive timer
		__sync_lock_test_and_set(&keepalive_counter, CHECK_KEEPALIVE_TIMES);
	}
	else
	{
// TODO: Access the message
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterFollowerNode::notify(NotifyType notify_type)
{
	return RET_SUCCESS;
}

