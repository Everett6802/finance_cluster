#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>
#include "msg_cluster_leader_node.h"
#include "msg_cluster_common.h"


using namespace std;

MsgClusterLeaderNode::MsgClusterLeaderNode(char* ip) :
	client_send_thread(NULL),
	leader_socket(0)
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
	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::deinitialize()
{
	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::check_keepalive()
{
	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::update(const char* ip, const char* message)
{
	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderNode::notify(short notify_type)
{
	return RET_SUCCESS;
}
