#include "msg_cluster_leader_node.h"
#include "msg_cluster_common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>


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
