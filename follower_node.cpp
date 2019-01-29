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
	local_ip(NULL),
	cluster_ip(NULL),
	cluster_node_id(0),
	keepalive_cnt(0),
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

unsigned short FollowerNode::send_data(MessageType message_type, const char* data)
{
	unsigned short ret = RET_SUCCESS;
	// assert(msg != NULL && "msg should NOT be NULL");

	NodeMessageAssembler node_message_assembler;
	ret = node_message_assembler.assemble(message_type, data);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to assemble the message, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	pthread_mutex_lock(&mtx_node_channel);
// Send to leader
	assert(node_channel != NULL && "node_channel should NOT be NULL");
	ret = node_channel->send_msg(node_message_assembler.get_full_message());
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fail to send msg to the Leader[%s], due to: %s", cluster_ip, GetErrorDescription(ret));
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

	mtx_node_channel = PTHREAD_MUTEX_INITIALIZER;
	mtx_cluster_map = PTHREAD_MUTEX_INITIALIZER;

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

unsigned short FollowerNode::recv(MessageType message_type, const std::string& message_data)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", ip.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (FollowerNode::*RECV_FUNC_PTR)(const std::string& message_data);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		NULL,
		&FollowerNode::recv_check_keepalive,
		&FollowerNode::recv_update_cluster_map,
		&FollowerNode::recv_transmit_text
	};
	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(recv_func_array[message_type]))(message_data);
}

unsigned short FollowerNode::send(MessageType message_type, void* param1, void* param2, void* param3)
{
	typedef unsigned short (FollowerNode::*SEND_FUNC_PTR)(void* param1, void* param2, void* param3);
	static SEND_FUNC_PTR send_func_array[] =
	{
		NULL,
		&FollowerNode::send_check_keepalive,
		&FollowerNode::send_update_cluster_map,
		&FollowerNode::send_transmit_text
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Notify Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short FollowerNode::recv_check_keepalive(const std::string& message_data)
{
// Message format:
// EventType | Payload: Client IP| EOD
	pthread_mutex_lock(&mtx_node_channel);
	if (keepalive_cnt < MAX_KEEPALIVE_CNT)
		keepalive_cnt++;
	pthread_mutex_unlock(&mtx_node_channel);
	fprintf(stderr, "Recv Check-Keepalive: %d\n", keepalive_cnt);
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_update_cluster_map(const std::string& message_data)
{
// Message format:
// EventType | Payload: Cluster map string| EOD
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&mtx_cluster_map);
	ret = cluster_map.from_string(message_data.c_str());
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to update the cluster map in Follower[%s], due to: %s", local_ip, GetErrorDescription(ret));
		goto OUT;
	}
	if (cluster_node_id == 0)
	{
// New Follower get the Node ID from Leader
	    ret = cluster_map.get_last_node_id(cluster_node_id);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fails to get node ID in Follower[%s], due to: %s", local_ip, GetErrorDescription(ret));
			goto OUT;
		}

    }
OUT:
	pthread_mutex_unlock(&mtx_cluster_map);
	return ret;
}

unsigned short FollowerNode::recv_transmit_text(const std::string& message_data)
{
	printf("Recv Text: %s\n", message_data.c_str());
	return RET_SUCCESS;
}

unsigned short FollowerNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | EOD
	fprintf(stderr, "Recv30: Send Cheek Keepalive\n");
	if (keepalive_cnt == 0)
	{
// The leader die !!!
		WRITE_FORMAT_ERROR("Follower[%s] got no response from Leader[%s]", local_ip, cluster_ip);
		return RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
	}

	return send_data(MSG_CHECK_KEEPALIVE);
	// char msg = (char)MSG_CHECK_KEEPALIVE;
	// return send_data(&msg);
}

unsigned short FollowerNode::send_update_cluster_map(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_UPDATE_CLUSUTER_MAP);}

unsigned short FollowerNode::send_transmit_text(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: text data
// Message format:
// EventType | text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}

	const char* text_data = (const char*)param1;

	return send_data(MSG_TRANSMIT_TEXT, text_data);
}

unsigned short FollowerNode::set(ParamType param_type, void* param1, void* param2)
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

unsigned short FollowerNode::get(ParamType param_type, void* param1, void* param2)
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
            pthread_mutex_lock(&mtx_cluster_map);
            ret = cluster_map_param.copy(cluster_map);
            pthread_mutex_unlock(&mtx_cluster_map);
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
