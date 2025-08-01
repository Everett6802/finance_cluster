// #include <unistd.h>
#include <fcntl.h>
// #include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "follower_node.h"


using namespace std;

const int FollowerNode::WAIT_CONNECTION_TIMEOUT = 5; // 5 seconds
const int FollowerNode::TRY_CONNECTION_TIMES = 10;
const int FollowerNode::TRY_CONNECTION_SLEEP_TIMES = 15;
const int FollowerNode::CHECK_KEEPALIVE_TIMES = 4;
const int FollowerNode::TOTAL_KEEPALIVE_PERIOD = KEEPALIVE_PERIOD * CHECK_KEEPALIVE_TIMES;

FollowerNode::FollowerNode(PIMANAGER parent, const char* server_token, const char* token) :
	observer(parent),
	socketfd(0),
	// tx_socketfd(0),
	local_cluster(true),
	local_token(NULL),
	cluster_token(NULL),
	cluster_id(0),
	keepalive_cnt(0),
	connection_retry(false),
	// file_channel(NULL),
	node_channel(NULL),
	notify_thread(NULL)
{
	IMPLEMENT_MSG_DUMPER()
	IMPLEMENT_EVT_RECORDER()
	observer = parent;
	assert(observer != NULL && "observer should NOT be NULL");

	if (token != NULL)
		local_token = strdup(token);
	if (server_token != NULL)
		cluster_token = strdup(server_token);
}

FollowerNode::~FollowerNode()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in FollowerNode::~FollowerNode(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (observer != NULL)
		observer = NULL;

	RELEASE_EVT_RECORDER()
	RELEASE_MSG_DUMPER()
}

unsigned short FollowerNode::connect_leader()
{
	WRITE_FORMAT_DEBUG("Try to connect to Leader[%s]......", cluster_token);

// Create socket
	int sock_fd = 0;
	if (local_cluster)
		sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	else
		sock_fd = socket(AF_INET, SOCK_STREAM, 0);
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

// http://www.cas.mcmaster.ca/~qiao/courses/cs3mh3/tutorials/socket.html
	int res;
	if (local_cluster)
	{
		int socket_len;
		sockaddr_un client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_un));
		client_address.sun_family = AF_UNIX;
		strcpy(client_address.sun_path, CLUSTER_UDS_FILEPATH);
		// socket_len = sizeof(struct sockaddr);
    	socket_len = sizeof(client_address.sun_family) + strlen(client_address.sun_path);
		res = connect(sock_fd, (struct sockaddr*)&client_address, socket_len);
		// fprintf(stderr, "client_address.sun_path: %s, socket_len: %d\n", client_address.sun_path, socket_len);
	}
	else
	{
		sockaddr_in client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_in));
		client_address.sin_family = AF_INET;
		client_address.sin_port = htons(CLUSTER_PORT_NO);
		client_address.sin_addr.s_addr = inet_addr(cluster_token);
		res = connect(sock_fd, (struct sockaddr*)&client_address, sizeof(struct sockaddr));
	}
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
					return RET_FAILURE_CONNECTION_NO_SERVER;  // RET_FAILURE_SYSTEM_API;
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

	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", cluster_token);
	WRITE_EVT_RECORDER(OperateNodeEventCfg, EVENT_OPERATE_NODE_JOIN, FOLLOWER, cluster_token);
	socketfd = sock_fd;

	return RET_SUCCESS;
}

unsigned short FollowerNode::become_follower()
{
// Try to connect to the designated server
	unsigned short ret = connect_leader();
	// if (IS_TRY_CONNECTION_TIMEOUT_EX(ret))
	// {
	// 	WRITE_FORMAT_DEBUG("Node[%s] fails to connect to server...", cluster_token);
	// 	return ret;
	// }
	// else
	// {
	// 	if (CHECK_FAILURE(ret))
	// 		return ret;
	// }

	// WRITE_FORMAT_INFO("Node[%s] is Follower", local_token);
	// printf("Node[%s] is Follower, connect to Leader[%s] !!!\n", local_token, cluster_token);
	if (CHECK_SUCCESS(ret))
	{
		WRITE_FORMAT_INFO("Node[%s] is Follower", local_token);
		printf("Node[%s] is Follower, connect to Leader[%s] !!!\n", local_token, cluster_token);		
	}
	else
	{
		if (IS_TRY_CONNECTION_TIMEOUT_EX(ret))
			WRITE_FORMAT_DEBUG("Node[%s] fails to connect to server..., due to: %s", local_token, cluster_token, GetErrorDescription(ret));
		else
			WRITE_FORMAT_DEBUG("Node[%s] fails to connect to server[%s]", local_token, cluster_token);
	}

	return ret;
}

// unsigned short FollowerNode::connect_file_sender()
// {
// 	WRITE_FORMAT_DEBUG("Try to connect to File sender[%s]......", cluster_token);

// // Create socket
// 	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
// 	if (sock_fd < 0)
// 	{
// 		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}

// // Set non-blocking
// 	long sock_arg;
// 	if((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
// 	{
// 		WRITE_FORMAT_ERROR("fcntl(F_GETFL) fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// 	sock_arg |= O_NONBLOCK;
// 	if(fcntl(sock_fd, F_SETFL, sock_arg) < 0)
// 	{
// 		WRITE_FORMAT_ERROR("fcntl(F_SETFL) fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// // http://www.cas.mcmaster.ca/~qiao/courses/cs3mh3/tutorials/socket.html
// 	int res;
// 	if (local_cluster)
// 	{
// 		int socket_len;
// 		sockaddr_un client_address;
// 		memset(&client_address, 0x0, sizeof(struct sockaddr_un));
// 		client_address.sun_family = AF_UNIX;
// 		strcpy(client_address.sun_path, CLUSTER_UDS_FILEPATH);
// 		socket_len = sizeof(client_address.sun_family) + strlen(client_address.sun_path);
// 		// fprintf(stderr, "socket_len: %d, sun_path: %s\n", socket_len, client_address.sun_path);
// 		res = connect(sock_fd, (struct sockaddr*)&client_address, socket_len);
// 	}
// 	else
// 	{
// 		sockaddr_in client_address;
// 		memset(&client_address, 0x0, sizeof(struct sockaddr_in));
// 		client_address.sin_family = AF_INET;
// 		client_address.sin_port = htons(FILE_TRANSFER_PORT_NO);
// 		client_address.sin_addr.s_addr = inet_addr(cluster_token);
// 		res = connect(sock_fd, (struct sockaddr*)&client_address, sizeof(struct sockaddr));
// 	}
// 	if (res < 0)
// 	{
// 		if (errno == EINPROGRESS)
// 		{
// 			WRITE_DEBUG("Connection is NOT established......");
// 			struct timeval tv;
// 			fd_set sock_set;

// 			tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
// 			tv.tv_usec = 0;

// 			FD_ZERO(&sock_set);
// 			FD_SET(sock_fd, &sock_set);
// 			res = select(sock_fd + 1, NULL, &sock_set, NULL, &tv);
// 			if (res < 0 && errno != EINTR)
// 			{
// 				WRITE_FORMAT_ERROR("select() fails, due to: %s", strerror(errno));
// 				return RET_FAILURE_SYSTEM_API;
// 			}
// 			else if (res > 0)
// 			{
// // Socket selected for writing
// 				int error;
// 				socklen_t error_len = sizeof(error);
// 				if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (void*)&error, &error_len) < 0)
// 				{
// 					WRITE_FORMAT_ERROR("getsockopt() fails, due to: %s", strerror(errno));
// 					return RET_FAILURE_SYSTEM_API;
// 				}
// // Check the value returned...
// 				if (error)
// 				{
// 					WRITE_FORMAT_ERROR("Error in delayed connection(), due to: %s", strerror(error));
// 					return RET_FAILURE_SYSTEM_API;
// 				}
// 			}
// 			else
// 			{
// 				WRITE_DEBUG("Connection timeout");
// 				return RET_FAILURE_CONNECTION_TRY_TIMEOUT;
// 			}
// 		}
// 		else
// 		{
// 			WRITE_FORMAT_ERROR("connect() fails, due to: %s", strerror(errno));
// 			return RET_FAILURE_SYSTEM_API;
// 		}
// 	}

// // Set to blocking mode again...
// 	if ((sock_arg = fcntl(sock_fd, F_GETFL, NULL)) < 0)
// 	{
// 		WRITE_FORMAT_ERROR("fcntl(F_GETFL) fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// 	sock_arg &= (~O_NONBLOCK);
// 	if (fcntl(sock_fd, F_SETFL, sock_arg) < 0)
// 	{
// 		WRITE_FORMAT_ERROR("fcntl(F_SETFL) fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}

// 	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", cluster_token);
// 	tx_socketfd = sock_fd;

// 	return RET_SUCCESS;
// }

unsigned short FollowerNode::send_raw_data(MessageType message_type, const char* data, int data_size)
{
	unsigned short ret = RET_SUCCESS;
	// assert(msg != NULL && "msg should NOT be NULL");
	// fprintf(stderr, "Follower[%s] Message: type: %d, data: %s\n", local_token, message_type, data);
	NodeMessageAssembler node_message_assembler;
	ret = node_message_assembler.assemble(message_type, data, data_size);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to assemble the message, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	pthread_mutex_lock(&node_channel_mtx);
// Send to leader
	assert(node_channel != NULL && "node_channel should NOT be NULL");
	ret = node_channel->send_msg(node_message_assembler.get_message(), node_message_assembler.get_message_size());
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fail to send msg to the Leader[%s], due to: %s", cluster_token, GetErrorDescription(ret));
	pthread_mutex_unlock(&node_channel_mtx);
	// fprintf(stderr, "Follower[%s] send Message to remote: %s[type: %d]\n", local_token, (node_message_assembler.get_message() + 1), (int)(*node_message_assembler.get_message()));
	return ret;
}

unsigned short FollowerNode::send_string_data(MessageType message_type, const char* data)
{
	int data_size = 0;
	if (data != NULL)
		data_size = strlen(data) + 1;
	return send_raw_data(message_type, data, data_size);
}

unsigned short FollowerNode::initialize()
{
// Try to find the follower node
	unsigned short ret = RET_SUCCESS;
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "Follower Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

	for (int i = 0 ; i < TRY_CONNECTION_TIMES ; i++)
	{
		ret = become_follower();
// The node become a follower successfully
		if (CHECK_SUCCESS(ret))
			break;
		else
		{
// Check if time-out occurs while trying to connect to the remote node
			if (IS_TRY_CONNECTION_TIMEOUT_EX(ret) && connection_retry)
			{
				WRITE_FORMAT_DEBUG("Re-build the cluster. Node[%s] try to connect to Leader[%s], but fails... %d", local_token, cluster_token, i);
				sleep(TRY_CONNECTION_SLEEP_TIMES);
			}
			else
				break;
		}
	}

	if (CHECK_FAILURE(ret))
	{
		if (!IS_TRY_CONNECTION_TIMEOUT(ret))
			WRITE_FORMAT_ERROR("Error occur while Node[%s]'s trying to connect to Leader[%s], due to: %s", local_token, cluster_token, GetErrorDescription(ret));
		else
			WRITE_FORMAT_WARN("Node[%s] try to connect to Leader[%s], buf time-out...", local_token, cluster_token);
		return ret;
	}
// Initialize the synchronization object
	node_channel_mtx = PTHREAD_MUTEX_INITIALIZER;
	cluster_map_mtx = PTHREAD_MUTEX_INITIALIZER;

// Start a timer to check keep-alive
	keepalive_cnt = MAX_KEEPALIVE_CNT;

// Create a thread of accessing the data
	node_channel = new NodeChannel(this);
	if (node_channel == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: node_channel");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	return node_channel->initialize(socketfd, local_token, cluster_token);
}

unsigned short FollowerNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	// if (file_channel != NULL)
	// {
	// 	ret = file_channel->deinitialize();
	// 	delete file_channel;
	// 	file_channel = NULL;
	// 	if (CHECK_FAILURE(ret))
	// 		WRITE_FORMAT_WARN("Fail to de-initialize the file channel worker thread[Node: %s]", local_token);
	// }
	if (node_channel != NULL)
	{
		ret = node_channel->deinitialize();
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_WARN("Fail to de-initialize the node channel worker thread[Node: %s]", local_token);
		delete node_channel;
		node_channel = NULL;
	}
	if (socketfd != 0)
	{
		close(socketfd);
		socketfd = 0;
	}
	if (cluster_token != NULL)
	{
		free(cluster_token);
		cluster_token = NULL;
	}
	if (local_token != NULL)
	{
		// delete[] local_token;
		free(local_token);
		local_token = NULL;
	}
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv(MessageType message_type, const char* message_data, int message_size)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", token.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (FollowerNode::*RECV_FUNC_PTR)(const char* message_data, int message_size);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		NULL,
		&FollowerNode::recv_check_keepalive,
		&FollowerNode::recv_update_cluster_map,
		&FollowerNode::recv_transmit_text,
		&FollowerNode::recv_get_system_info,
		&FollowerNode::recv_get_system_monitor,
		&FollowerNode::recv_get_simulator_version,
		&FollowerNode::recv_install_simulator,
		&FollowerNode::recv_apply_fake_acspt_config,
		&FollowerNode::recv_apply_fake_usrept_config,
		&FollowerNode::recv_control_fake_acspt,
		&FollowerNode::recv_control_fake_usrept,
		&FollowerNode::recv_get_fake_acspt_state,
		&FollowerNode::recv_get_fake_acspt_detail,
		&FollowerNode::recv_request_file_transfer,
		&FollowerNode::recv_complete_file_transfer,
		&FollowerNode::recv_request_file_transfer_leader_remote_token,
		&FollowerNode::recv_request_file_transfer_follower_remote_token,
		&FollowerNode::recv_release_file_transfer_remote_token,
		&FollowerNode::recv_switch_leader,
		&FollowerNode::recv_remove_follower,
		&FollowerNode::recv_remote_sync_folder,
		&FollowerNode::recv_remote_sync_file
	};
	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(recv_func_array[message_type]))(message_data, message_size);
}

unsigned short FollowerNode::send(MessageType message_type, void* param1, void* param2, void* param3)
{
	typedef unsigned short (FollowerNode::*SEND_FUNC_PTR)(void* param1, void* param2, void* param3);
	static SEND_FUNC_PTR send_func_array[] =
	{
		NULL,
		&FollowerNode::send_check_keepalive,
		&FollowerNode::send_update_cluster_map,
		&FollowerNode::send_transmit_text,
		&FollowerNode::send_get_system_info,
		&FollowerNode::send_get_system_monitor,
		&FollowerNode::send_get_simulator_version,
		&FollowerNode::send_install_simulator,
		&FollowerNode::send_apply_fake_acspt_config,
		&FollowerNode::send_apply_fake_usrept_config,
		&FollowerNode::send_control_fake_acspt,
		&FollowerNode::send_control_fake_usrept,
		&FollowerNode::send_get_fake_acspt_state,
		&FollowerNode::send_get_fake_acspt_detail,
		&FollowerNode::send_request_file_transfer,
		&FollowerNode::send_complete_file_transfer,
		&FollowerNode::send_request_file_transfer_leader_remote_token,
		&FollowerNode::send_request_file_transfer_follower_remote_token,
		&FollowerNode::send_release_file_transfer_remote_token,
		&FollowerNode::send_switch_leader,
		&FollowerNode::send_remove_follower,
		&FollowerNode::send_remote_sync_folder,
		&FollowerNode::send_remote_sync_file
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short FollowerNode::recv_check_keepalive(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: Client IP| EOD
	pthread_mutex_lock(&node_channel_mtx);
	if (keepalive_cnt < MAX_KEEPALIVE_CNT)
		keepalive_cnt++;
	// fprintf(stderr, "KeepAlive Recv to counter: %d\n", keepalive_cnt);
	pthread_mutex_unlock(&node_channel_mtx);
	// fprintf(stderr, "Recv Check-Keepalive: %d\n", keepalive_cnt);
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_update_cluster_map(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: Cluster map string| EOD
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&cluster_map_mtx);
	// ret = cluster_map.from_string(message_data.c_str());
	ret = cluster_map.from_string(message_data);
	// fprintf(stderr, "Follower: message_data: %s, cluster_map: %s\n", message_data.c_str(), cluster_map.to_string());
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to update the cluster map in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
		goto OUT;
	}
	if (cluster_id == 0)
	{
		cluster_map.get_last_node_id(cluster_id);
		WRITE_FORMAT_DEBUG("Update Follower cluster ID: %d", cluster_id);
	}
OUT:
	pthread_mutex_unlock(&cluster_map_mtx);
	return ret;
}

unsigned short FollowerNode::recv_transmit_text(const char* message_data, int message_size)
{
// Message format:
// EventType | text string| EOD
	// printf("Recv Text: %s\n", message_data.c_str());
	printf("Recv Text: %s\n", message_data);
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_get_system_info(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int session_id = atoi(message_data.c_str());
	int session_id = atoi(message_data);
	ret = send_get_system_info((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_get_system_monitor(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int session_id = atoi(message_data.c_str());
	int session_id = atoi(message_data);
	ret = send_get_system_monitor((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_get_simulator_version(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int session_id = atoi(message_data.c_str());
	int session_id = atoi(message_data);	
	ret = send_get_simulator_version((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_install_simulator(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	// const char* simulator_package_filepath = (const char*)message_data.c_str();
	// size_t notify_param_size = strlen(simulator_package_filepath) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifySimulatorInstallCfg((void*)simulator_package_filepath, notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifySimulatorInstallCfg((void*)message_data, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_INSTALL_SIMULATOR, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_apply_fake_acspt_config(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	// const char* fake_acspt_config_line_list_str = (const char*)message_data.c_str();
	// size_t notify_param_size = strlen(fake_acspt_config_line_list_str) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptConfigApplyCfg((void*)fake_acspt_config_line_list_str, notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptConfigApplyCfg((void*)message_data, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_APPLY_FAKE_ACSPT_CONFIG, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_apply_fake_usrept_config(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	// const char* fake_usrept_config_line_list_str = (const char*)message_data.c_str();
	// size_t notify_param_size = strlen(fake_usrept_config_line_list_str) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptConfigApplyCfg((void*)fake_usrept_config_line_list_str, notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptConfigApplyCfg((void*)message_data, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_APPLY_FAKE_USREPT_CONFIG, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_control_fake_acspt(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: simulator ap control type | EOD
	unsigned short ret = RET_SUCCESS;
	// FakeAcsptControlType fake_acspt_control_type = (FakeAcsptControlType)atoi(message_data.c_str());
	// size_t notify_param_size = sizeof(FakeAcsptControlType);
	// PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, notify_param_size);
	FakeAcsptControlType fake_acspt_control_type = (FakeAcsptControlType)atoi(message_data);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_CONTROL_FAKE_ACSPT, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_control_fake_usrept(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: simulator ue control type | EOD
	unsigned short ret = RET_SUCCESS;
	// FakeUsreptControlType fake_usrept_control_type = (FakeUsreptControlType)atoi(message_data.c_str());
	// size_t notify_param_size = sizeof(FakeUsreptControlType);
	// PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptControlCfg((void*)&fake_usrept_control_type, notify_param_size);
	FakeUsreptControlType fake_usrept_control_type = (FakeUsreptControlType)atoi(message_data);
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptControlCfg((void*)&fake_usrept_control_type, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_CONTROL_FAKE_USREPT, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_get_fake_acspt_state(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int session_id = atoi(message_data.c_str());
	int session_id = atoi(message_data);
	ret = send_get_fake_acspt_state((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_get_fake_acspt_detail(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int session_id = atoi(message_data.c_str());
	int session_id = atoi(message_data);
	ret = send_get_fake_acspt_detail((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_request_file_transfer(const char* message_data, int message_size)
{
// // Message format:
// // EventType | session id | filepath | EOD
// 	assert(file_channel == NULL && "file_channel should be NULL");
// 	const char* buf = (const char*)message_data.c_str();
	// unsigned short ret = RET_SUCCESS;
// // Receiver tries to connect to Sender
// 	ret = connect_file_sender();
// 	if (CHECK_FAILURE(ret))
// 		return ret;
// // Create the channel for file tranfer
// 	file_channel = new FileChannel(this);
// 	if (file_channel == NULL)
// 	{
// 		WRITE_ERROR("Fail to allocate memory: file_channel");
// 		return RET_FAILURE_INSUFFICIENT_MEMORY;
// 	}

// 	WRITE_FORMAT_INFO("Initialize the File Channel in Receiver[%s]", local_token);
// 	ret = file_channel->initialize(tx_filepath, local_token, cluster_token, tx_socketfd);
// 	if (CHECK_FAILURE(ret))
// 		return ret;
	usleep((random() % 10) * 100000);
	// const char* nofity_param = message_data.c_str();
	// size_t notify_param_size = strlen(nofity_param);
	// PNOTIFY_CFG notify_cfg = new NotifyFileTransferConnectCfg((void*)nofity_param, notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifyFileTransferConnectCfg((void*)message_data, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Asynchronous event
    observer->notify(NOTIFY_CONNECT_FILE_TRANSFER, notify_cfg);
	SAFE_RELEASE(notify_cfg)

	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_complete_file_transfer(const char* message_data, int message_size)
{
	assert(observer != NULL && "observer should NOT be NULL");
	FileTxType file_tx_type;
	observer->get(PARAM_FILE_TX_TYPE, (void*)&file_tx_type);
	unsigned short ret = RET_SUCCESS;
	switch(file_tx_type)
	{
		case TX_SENDER:
		{
// Message format:
// EventType | playload: (session ID[2 digits]|cluster ID[2 digits]|return code[unsigned short]|remote_token) | EOD
			// size_t notify_param_size = strlen(message_data.c_str()) + 1;
			// PNOTIFY_CFG notify_cfg = new NotifyFileTransferCompleteCfg((void*)message_data.c_str(), notify_param_size);
			PNOTIFY_CFG notify_cfg = new NotifyFileTransferCompleteCfg((void*)message_data, (size_t)message_size);
			if (notify_cfg == NULL)
				throw bad_alloc();
			// fprintf(stderr, "[recv_complete_file_transfer]  remote_token: %s\n", ((PNOTIFY_FILE_TRANSFER_COMPLETE_CFG)notify_cfg)->get_remote_token());
// Asynchronous event
			observer->notify(NOTIFY_COMPLETE_FILE_TRANSFER, notify_cfg);
			SAFE_RELEASE(notify_cfg)
		}
		break;
		case TX_RECEIVER:
		{
// Message format:
// EventType | session ID | EOD
//	unsigned short ret = RET_SUCCESS;
// 	if (file_channel != NULL)
// 	{
// // ret is the recv thread return code
// 		ret = file_channel->deinitialize();
// 		delete file_channel;
// 		file_channel = NULL;
// 		if (CHECK_FAILURE(ret))
// 			return ret;
// 	}
// 	else
// 		WRITE_WARN("The file channel does NOT exist");
			// int session_id = atoi(message_data.c_str());
			int session_id = atoi(message_data);
			ret = send_complete_file_transfer((void*)&session_id, (void*)&ret);
		}
		break;
		default:
		{
			WRITE_ERROR("file_tx_type shuold NOT be TX_NONE");
			ret = RET_FAILURE_INCORRECT_OPERATION;
		}
		break;
	}
	return ret;
}

unsigned short FollowerNode::recv_request_file_transfer_leader_remote_token(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	unsigned short ret = RET_SUCCESS;
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, message_data, PAYLOAD_SESSION_ID_DIGITS);
	int session_id = atoi(session_id_buf);
	ret = send_request_file_transfer_leader_remote_token((void*)&session_id);
	return ret;
}

unsigned short FollowerNode::recv_request_file_transfer_follower_remote_token(const char* message_data, int message_size)
{
// Message format:
// EventType | session ID | file transfer token return code | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	// static const int FILE_TRANSFER_TOKEN_BUF_SIZE = sizeof(unsigned short) + 1;
	// unsigned short ret = RET_SUCCESS;
	// char session_id_buf[SESSION_ID_BUF_SIZE];
	// memset(session_id_buf, 0x0, SESSION_ID_BUF_SIZE);
	// memcpy(session_id_buf, message_data, PAYLOAD_SESSION_ID_DIGITS);
	// int session_id = atoi(session_id_buf);
	// char file_transfer_token_buf[FILE_TRANSFER_TOKEN_BUF_SIZE];
	// memset(file_transfer_token_buf, 0x0, FILE_TRANSFER_TOKEN_BUF_SIZE);
	// memcpy(file_transfer_token_buf, (message_data + PAYLOAD_SESSION_ID_DIGITS), sizeof(unsigned short));
	// unsigned short file_transfer_token_ret = atoi(file_transfer_token_buf);
	// ret = observer->set(PARAM_FILE_TRANSFER_REMOTE_TOKEN_REQUEST_RETURN, (void*)&session_id, (void*)&file_transfer_token_ret);
	// return ret;
	PNOTIFY_CFG notify_cfg = new NotifyRequestFileTransferRemoteTokenCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_REQUEST_FILE_TRANSFER_REMOTE_TOKEN, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_release_file_transfer_remote_token(const char* message_data, int message_size)
{
	// UNDEFINED_MSG_EXCEPTION("Follower", "Recv", MSG_RELEASE_FILE_TRANSFER_TOKEN);
// Message format:
// EventType | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	unsigned short ret = observer->set(PARAM_FILE_TRANSFER_TOKEN_RELEASE);
	return ret;
}

unsigned short FollowerNode::recv_switch_leader(const char* message_data, int message_size)
{
// Message format:
// EventType | leader candidate node ID | EOD
	unsigned short ret = RET_SUCCESS;
	// int leader_candidate_node_id = atoi(message_data.c_str());
	// size_t notify_param_size = sizeof(int);
	// PNOTIFY_CFG notify_cfg = new NotifySwitchLeaderCfg((void*)&leader_candidate_node_id, notify_param_size);
	int leader_candidate_node_id; //  = atoi(message_data);
	memcpy(&leader_candidate_node_id, message_data, message_size);
	// printf("[FollowerNode::recv_switch_leader] leader_candidate_node_id: %d, message_size: %d", leader_candidate_node_id, message_size);
	PNOTIFY_CFG notify_cfg = new NotifySwitchLeaderCfg((void*)&leader_candidate_node_id, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
	ret = observer->notify(NOTIFY_SWITCH_LEADER, notify_cfg);
	return ret;
}

unsigned short FollowerNode::recv_remove_follower(const char* message_data, int message_size)
{
// Message format:
// EventType | follower node ID | EOD
	unsigned short ret = RET_SUCCESS;
	int follower_node_id;
	memcpy(&follower_node_id, message_data, message_size);
	// printf("[FollowerNode::recv_remove_follower] follower_node_id: %d, message_size: %d", follower_node_id, message_size);
	PNOTIFY_CFG notify_cfg = new NotifyRemoveFollowerCfg((void*)&follower_node_id, message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
	ret = observer->notify(NOTIFY_REMOVE_FOLLOWER, notify_cfg);
	return ret;
}

unsigned short FollowerNode::recv_remote_sync_folder(const char* message_data, int message_size)
{
// Message format:
// EventType | folderpath | EOD
	return send_remote_sync_folder((void*)message_data);
}

unsigned short FollowerNode::recv_remote_sync_file(const char* message_data, int message_size)
{
// Message format:
// EventType | filepath | EOD
	return send_remote_sync_file((void*)message_data);
}

unsigned short FollowerNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | payload: local_token | EOD
	// fprintf(stderr, "Recv30: Send Cheek Keepalive\n");
	if (keepalive_cnt == 0)
	{
		// fprintf(stderr, "KeepAlive counter is 0!\n");
// The leader die !!!
		WRITE_FORMAT_ERROR("Follower[%s] got no response from Leader[%s]", local_token, cluster_token);
		return RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT;
	}

	// fprintf(stderr, "KeepAlive Sent\n");
	return send_string_data(MSG_CHECK_KEEPALIVE, local_token);
	// char msg = (char)MSG_CHECK_KEEPALIVE;
	// return send_string_data(&msg);
}

unsigned short FollowerNode::send_update_cluster_map(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_UPDATE_CLUSTER_MAP);}

unsigned short FollowerNode::send_transmit_text(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: text data
// Message format:
// EventType | payload: text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	const char* text_data = (const char*)param1;
	return send_string_data(MSG_TRANSMIT_TEXT, text_data);
}

unsigned short FollowerNode::send_get_system_info(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The sessin id
// param2: The cluster id
// Message format:
// EventType | playload: (session ID[2 digits]|system info) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
    unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of cluster id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, *(int*)param2);

// Combine the payload
	string system_info_data = string(session_id_buf) + string(cluster_id_buf);
	// string system_info;
	SystemInfoParam system_info_param;
	ret = observer->get(PARAM_SYSTEM_INFO, (void*)&system_info_param);
	// ret = get_system_info(system_info);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get system info in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
		system_info_data += system_info_param.system_info;
	// fprintf(stderr, "Follower[%s] send_get_system_info message: %s\n", local_token, system_info_data.c_str());
	// char session_id_str[3];
	// memset(session_id_str, 0x0, sizeof(char) * 3);
	// memcpy(session_id_str, system_info_data.c_str(), sizeof(char) * 2);
	// fprintf(stderr, "Follower[%s] send_get_system_info session id: %d, system info: %s\n", local_token, atoi(session_id_str), (system_info_data.c_str() + 2));
	return send_string_data(MSG_GET_SYSTEM_INFO, system_info_data.c_str());
}

unsigned short FollowerNode::send_get_system_monitor(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The sessin id
// param2: The cluster id
// Message format:
// EventType | playload: (session ID[2 digits]|system info) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
    unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of cluster id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, *(int*)param2);

// Combine the payload
	string system_monitor_data = string(session_id_buf) + string(cluster_id_buf);
	// string system_monitor;
	SystemMonitorParam system_monitor_param;
	ret = observer->get(PARAM_SYSTEM_MONITOR, (void*)&system_monitor_param);
	// ret = get_system_monitor(system_monitor);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get system monitor in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
		system_monitor_data += system_monitor_param.system_monitor_data;
	// fprintf(stderr, "Follower[%s] send_get_system_monitor message: %s\n", local_token, system_monitor_data.c_str());
	// char session_id_str[3];
	// memset(session_id_str, 0x0, sizeof(char) * 3);
	// memcpy(session_id_str, system_monitor_data.c_str(), sizeof(char) * 2);
	// fprintf(stderr, "Follower[%s] send_get_system_monitor session id: %d, system info: %s\n", local_token, atoi(session_id_str), (system_monitor_data.c_str() + 2));
	return send_string_data(MSG_GET_SYSTEM_MONITOR, system_monitor_data.c_str());
}

unsigned short FollowerNode::send_get_simulator_version(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The session id
// param2: The cluster id
// Message format:
// EventType | playload: (session ID[2 digits]|cluster ID[2 digits]|simulator version) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
    unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of cluster id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, *(int*)param2);

// Combine the payload
	string simulator_version_data = string(session_id_buf) + string(cluster_id_buf);
// Get the data
	PSIMULATOR_VERSION_PARAM simulator_version_param = new SimulatorVersionParam(DEF_VERY_SHORT_STRING_SIZE);
	if (simulator_version_param  == NULL)
		throw bad_alloc();
    ret = observer->get(PARAM_SIMULATOR_VERSION, (void*)simulator_version_param);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get simulaltor version in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
	{
		string simulator_version(simulator_version_param->simulator_version);
		simulator_version_data += simulator_version;
	}
	if (simulator_version_param != NULL)
	{
		delete simulator_version_param;
		simulator_version_param = NULL;
	}

	return send_string_data(MSG_GET_SIMULATOR_VERSION, simulator_version_data.c_str());
}

unsigned short FollowerNode::send_install_simulator(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_INSTALL_SIMULATOR);}

unsigned short FollowerNode::send_apply_fake_acspt_config(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_APPLY_FAKE_ACSPT_CONFIG);}

unsigned short FollowerNode::send_apply_fake_usrept_config(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_APPLY_FAKE_USREPT_CONFIG);}

unsigned short FollowerNode::send_control_fake_acspt(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_CONTROL_FAKE_ACSPT);}

unsigned short FollowerNode::send_control_fake_usrept(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_CONTROL_FAKE_USREPT);}

unsigned short FollowerNode::send_get_fake_acspt_state(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The session id
// param2: The cluster id
// Message format:
// EventType | playload: (session ID[2 digits]|cluster ID[2 digits]|fake acspt state) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
    unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of cluster id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, *(int*)param2);

// Combine the payload
	string fake_acspt_state_data = string(session_id_buf) + string(cluster_id_buf);
// Get the data
	PFAKE_ACSPT_STATE_PARAM fake_acspt_state_param = new FakeAcsptStateParam();
	if (fake_acspt_state_param  == NULL)
		throw bad_alloc();
    ret = observer->get(PARAM_FAKE_ACSPT_STATE, (void*)fake_acspt_state_param);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get fake acspt state in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
	{
		string fake_acspt_state(fake_acspt_state_param->fake_acspt_state);
		fake_acspt_state_data += fake_acspt_state;
	}
	if (fake_acspt_state_param != NULL)
	{
		delete fake_acspt_state_param;
		fake_acspt_state_param = NULL;
	}

	return send_string_data(MSG_GET_FAKE_ACSPT_STATE, fake_acspt_state_data.c_str());
}

unsigned short FollowerNode::send_get_fake_acspt_detail(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The session id
// param2: The cluster id
// Message format:
// EventType | playload: (session ID[2 digits]|cluster ID[2 digits]|fake acspt detail) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
    unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of cluster id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, *(int*)param2);

// Combine the payload
	string fake_acspt_detail_data = string(session_id_buf) + string(cluster_id_buf);
// Get the data
	PFAKE_ACSPT_DETAIL_PARAM fake_acspt_detail_param = new FakeAcsptDetailParam();
	if (fake_acspt_detail_param  == NULL)
		throw bad_alloc();
    ret = observer->get(PARAM_FAKE_ACSPT_DETAIL, (void*)fake_acspt_detail_param);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get fake acspt detail in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
	{
		string fake_acspt_detail(fake_acspt_detail_param->fake_acspt_detail);
		fake_acspt_detail_data += fake_acspt_detail;
	}
	if (fake_acspt_detail_param != NULL)
	{
		delete fake_acspt_detail_param;
		fake_acspt_detail_param = NULL;
	}

	return send_string_data(MSG_GET_FAKE_ACSPT_DETAIL, fake_acspt_detail_data.c_str());
}

unsigned short FollowerNode::send_request_file_transfer(void* param1, void* param2, void* param3)
{
	// UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_REQUEST_FILE_TRANSFER);
// Parameters:
// param1: session id/filepath
// Message format:
// EventType | session id | filepath | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	PFILE_TRANSFER_PARAM file_transfer_param = (PFILE_TRANSFER_PARAM)param1; 
   assert(file_transfer_param != NULL && "file_transfer_param should NOT be NULL");
	if (file_transfer_param->session_id == -1)
	{
		WRITE_ERROR("file_transfer_param->session_id should NOT be -1");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	if (file_transfer_param->sender_token == NULL)
	{
		WRITE_ERROR("file_transfer_param->sender_token should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	if (file_transfer_param->filepath == NULL)
	{
		WRITE_ERROR("file_transfer_param->filepath should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	int sender_token_len = strlen(file_transfer_param->sender_token);
	int filepath_len = strlen(file_transfer_param->filepath);
	int buf_size = PAYLOAD_SESSION_ID_DIGITS + sender_token_len + 1 + filepath_len + 1;
	char* buf = new char[buf_size];
	if (buf == NULL)
		throw bad_alloc();
	// fprintf(stderr, "session_id: %d, filepath: %s\n", file_transfer_param->session_id, file_transfer_param->filepath);
	memset(buf, 0x0, sizeof(char) * buf_size);
	// fprintf(stderr, "session_id in buf: %d\n", atoi(buf));
	memcpy((buf + PAYLOAD_SESSION_ID_DIGITS), file_transfer_param->sender_token, sizeof(char) * sender_token_len);
	// fprintf(stderr, "sender_token in buf: %s\n", &buf[PAYLOAD_SESSION_ID_DIGITS]);
	memcpy((buf + PAYLOAD_SESSION_ID_DIGITS + sender_token_len + 1), file_transfer_param->filepath, sizeof(char) * filepath_len);
	// fprintf(stderr, "filepath in buf: %s\n", &buf[PAYLOAD_SESSION_ID_DIGITS + sender_token_len + 1]);
	// fprintf(stderr, "buf: %s, buf_size: %d\n", buf, buf_size);

	WRITE_DEBUG("Notify the receiver to establish the connection for file transfer");
	unsigned short ret = send_raw_data(MSG_REQUEST_FILE_TRANSFER, buf, buf_size);
	if (buf != NULL)
	{
		delete[] buf;
		buf = NULL;
	}
	return ret;
}

unsigned short FollowerNode::send_complete_file_transfer(void* param1, void* param2, void* param3)
{
	assert(observer != NULL && "observer should NOT be NULL");
	FileTxType file_tx_type;
	observer->get(PARAM_FILE_TX_TYPE, (void*)&file_tx_type);
	unsigned short ret = RET_SUCCESS;
	switch(file_tx_type)
	{
		case TX_SENDER:
		{
// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
			if (param1 == NULL || param2 == NULL)
			{
				WRITE_ERROR("param1/param2 should NOT be NULL");
				return RET_FAILURE_INVALID_ARGUMENT;
			}
			static const int BUF_SIZE = sizeof(int) + 1;
			int session_id = *(int*)param1;
			char buf[BUF_SIZE];
			memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
			snprintf(buf, BUF_SIZE, "%d", session_id);
			// const char* remote_token = (const char*)param2;
			// fprintf(stderr, "[send_complete_file_transfer]  remote_token: %s\n", remote_token);
			ret = send_string_data(MSG_COMPLETE_FILE_TRANSFER, buf);
		}
		break;
		case TX_RECEIVER:
		{
// Parameters:
// param1: The sessin id
// param2: The return code
// Message format:
// EventType | playload: (session ID[2 digits]|cluster ID[2 digits]|return code[unsigned short]|remote_token) | EOD
			if (param1 == NULL)
			{
				WRITE_ERROR("param1 should NOT be NULL");
				return RET_FAILURE_INVALID_ARGUMENT;		
			}
			// static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
			// static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
			// static const int RETURN_CODE_BUF_SIZE = sizeof(unsigned short) + 1;
			int buf_size = PAYLOAD_SESSION_ID_DIGITS + PAYLOAD_CLUSTER_ID_DIGITS + sizeof(unsigned short) + strlen(local_token) + 1;
			char* buf = new char[buf_size];
			if (buf == NULL)
				throw bad_alloc();
			memset(buf, 0x0, sizeof(char) * buf_size);
			char* buf_ptr = buf;
			memcpy(buf_ptr, param1, PAYLOAD_SESSION_ID_DIGITS);
			buf_ptr += PAYLOAD_SESSION_ID_DIGITS;
			memcpy(buf_ptr, &cluster_id, PAYLOAD_CLUSTER_ID_DIGITS);
			buf_ptr += PAYLOAD_CLUSTER_ID_DIGITS;
			memcpy(buf_ptr, param2, sizeof(unsigned short));
			buf_ptr += sizeof(unsigned short);
			memcpy(buf_ptr, local_token, strlen(local_token));
// Synchronous event
// Notify to complete the file receiving...
			ret = observer->notify(NOTIFY_COMPLETE_FILE_TRANSFER);
// Notify the remote sender that the recevier has closed the resource
			ret = send_raw_data(MSG_COMPLETE_FILE_TRANSFER, buf, buf_size);
		}
		break;
		default:
		{
			WRITE_ERROR("file_tx_type shuold NOT be TX_NONE");
			ret = RET_FAILURE_INCORRECT_OPERATION;
		}
		break;
	}
	return ret;
}

unsigned short FollowerNode::send_request_file_transfer_leader_remote_token(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session id | file transfer token return code | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	if (param1 == NULL/* || param2 == NULL*/)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	static const int BUF_SIZE = sizeof(int) + sizeof(unsigned short);
	unsigned short ret = RET_SUCCESS;
	int session_id = *(int*)param1;
	unsigned short ret_file_transfer = observer->set(PARAM_FILE_TRANSFER_TOKEN_REQUEST);
	char buf[BUF_SIZE];
	memset(buf, 0x0, BUF_SIZE);
	char* buf_ptr = buf;
	memcpy(buf_ptr, &session_id, PAYLOAD_SESSION_ID_DIGITS);
	buf_ptr += PAYLOAD_SESSION_ID_DIGITS;
	memcpy(buf_ptr, &ret_file_transfer, sizeof(unsigned short));
	ret = send_raw_data(MSG_REQUEST_FILE_TRANSFER_LEADER_REMOTE_TOKEN, buf, BUF_SIZE);
	return ret;
}

unsigned short FollowerNode::send_request_file_transfer_follower_remote_token(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session id | local token | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	unsigned short ret = RET_SUCCESS;
	int buf_size = PAYLOAD_SESSION_ID_DIGITS + strlen(local_token) + 1;
	char* buf = new char[buf_size];
	if (buf == NULL)
		throw bad_alloc();
	memset(buf, 0x0, sizeof(char) * buf_size);
	char* buf_ptr = buf;
	memcpy(buf_ptr, param1, PAYLOAD_SESSION_ID_DIGITS);
	buf_ptr += PAYLOAD_SESSION_ID_DIGITS;
	memcpy(buf_ptr, local_token, strlen(local_token));
	ret = send_raw_data(MSG_REQUEST_FILE_TRANSFER_FOLLOWER_REMOTE_TOKEN, buf, buf_size);
	return ret;
}

unsigned short FollowerNode::send_release_file_transfer_remote_token(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | EOD
	unsigned short ret = send_raw_data(MSG_RELEASE_FILE_TRANSFER_REMOTE_TOKEN);
	return ret;
}

unsigned short FollowerNode::send_switch_leader(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_SWITCH_LEADER);}

unsigned short FollowerNode::send_remove_follower(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_REMOVE_FOLLOWER);}

unsigned short FollowerNode::send_remote_sync_folder(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: folderpath
// Message format:
// EventType | return value | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	unsigned short ret = RET_SUCCESS;
	const char* folderpath = (const char*)param1;
	unsigned short remote_sync_file_ret = RET_SUCCESS;
	if (check_file_exist(folderpath))
	{
		ClusterFileTransferParam cluster_file_transfer_param;
		cluster_file_transfer_param.control_token = gen_random_string();
		list<string> full_filepath_in_folder_list;
		get_filepath_in_folder_recursive(full_filepath_in_folder_list, string(folderpath));
		list<string>::iterator iter = full_filepath_in_folder_list.begin();
		while (iter != full_filepath_in_folder_list.end())
		{
			string full_filepath = (string)(*iter);
			// printf("* %s\n", full_filepath.c_str());
			WRITE_FORMAT_DEBUG("Synchronize the file[%s] to Leader", full_filepath.c_str());
// Start to transfer the file
			cluster_file_transfer_param.session_id = -1;
			ret = observer->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)full_filepath.c_str());
			usleep(150000);
			// printf("[PARAM_FILE_TRANSFER], ret description: %s\n", GetErrorDescription(ret));
			if (CHECK_FAILURE(ret))
				return ret;
			iter++;
		}
		// observer->set(PARAM_REMOTE_SYNC_FLAG_OFF);
	}
	else
	{
		WRITE_FORMAT_ERROR("The folder[%s] does NOT exist and fails to sync to Leader", folderpath);
		remote_sync_file_ret = RET_FAILURE_NOT_FOUND;
	}
	static const int BUF_SIZE = sizeof(unsigned short) + 1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, BUF_SIZE);
	snprintf(buf, BUF_SIZE, "%hu", remote_sync_file_ret);
	// memcpy(buf, &ret, sizeof(unsigned short));
	ret = send_raw_data(MSG_REMOTE_SYNC_FOLDER, buf, BUF_SIZE);
	return ret;
}

unsigned short FollowerNode::send_remote_sync_file(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: filepath
// Message format:
// EventType | return value | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	unsigned short ret = RET_SUCCESS;
	const char* filepath = (const char*)param1;
	unsigned short remote_sync_file_ret = RET_SUCCESS;
	if (check_file_exist(filepath))
	{
// Start to transfer the file
		ClusterFileTransferParam cluster_file_transfer_param;
		cluster_file_transfer_param.control_token = gen_random_string();
		cluster_file_transfer_param.session_id = -1;
		WRITE_FORMAT_DEBUG("Synchronize the file[%s] to Leader", filepath);
		ret = observer->set(PARAM_FILE_TRANSFER, (void*)&cluster_file_transfer_param, (void*)filepath);
		// printf("[PARAM_FILE_TRANSFER], ret description: %s\n", GetErrorDescription(ret));
		usleep(100000);
		// printf("[PARAM_FILE_TRANSFER], ret description: %s\n", GetErrorDescription(ret));
		// observer->set(PARAM_REMOTE_SYNC_FLAG_OFF);
	}
	else
	{
		WRITE_FORMAT_ERROR("The file[%s] does NOT exist and fails to sync to Leader", filepath);
		remote_sync_file_ret = RET_FAILURE_NOT_FOUND;
	}
	static const int BUF_SIZE = sizeof(unsigned short) + 1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, BUF_SIZE);
	snprintf(buf, BUF_SIZE, "%hu", remote_sync_file_ret);
	// memcpy(buf, &ret, sizeof(unsigned short));
	ret = send_raw_data(MSG_REMOTE_SYNC_FILE, buf, BUF_SIZE);
	return ret;
}

unsigned short FollowerNode::set(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	case PARAM_CONNECTION_RETRY:
    	{
    		connection_retry = *(bool*)param1;
    	}
    	break;
    	case PARAM_LOCAL_CLUSTER:
    	{
    		local_cluster = *(bool*)param1;
    	}
    	break;
// 	    case PARAM_FILE_TRANSFER:
//     	{
//     		if (param1 == NULL)
//     		{
//     			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
//     			return RET_FAILURE_INVALID_ARGUMENT;
//     		}
// // Notify the leader to connect to the sender and become a receiver
// 			ret = send_request_file_transfer(param1);
// 			if (CHECK_FAILURE(ret))
// 				return ret;	
//     	}
//     	break;
    	case PARA_FOLLOWERM_REMOVAL:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
			int alive_node_id = *(int*)param1;
			string alive_node_token;
			pthread_mutex_lock(&cluster_map_mtx);
// re-build the cluster map
			ret = cluster_map.get_node_token(alive_node_id, alive_node_token);
			if (CHECK_FAILURE(ret))
				goto OUT;
			cluster_map.cleanup_node();
			ret = cluster_map.add_node(cluster_id, cluster_token);
			if (CHECK_FAILURE(ret))
				goto OUT;
			ret = cluster_map.add_node(alive_node_id, alive_node_token);
			if (CHECK_FAILURE(ret))
				goto OUT;
			// ret = cluster_map.cleanup_node_except_one(node_id);
OUT:
			pthread_mutex_unlock(&cluster_map_mtx);
			if (CHECK_FAILURE(ret))
				return ret;	
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
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
            pthread_mutex_lock(&cluster_map_mtx);
            ret = cluster_map_param.copy(cluster_map);
            pthread_mutex_unlock(&cluster_map_mtx);
    	}
    	break;
		// case PARAM_CLUSTER_IS_SINGLE:
		// {
    	// 	if (param1 == NULL)
    	// 	{
    	// 		WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    	// 		return RET_FAILURE_INVALID_ARGUMENT;
    	// 	}
        //     pthread_mutex_lock(&cluster_map_mtx);
        //     *(bool*)param1 = cluster_map.is_single();
        //     pthread_mutex_unlock(&cluster_map_mtx);
		// }
		// break;
    	case PARAM_NODE_ID:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		if (cluster_id == 0)
    		{
     			WRITE_ERROR("The cluster_id should NOT be 0");
    			return RET_FAILURE_RUNTIME;   			
    		}
    		*(int*)param1 = cluster_id;
    	}
    	break;
    	case PARAM_CONNECTION_RETRY:
    	{
    		 *(bool*)param1 = connection_retry;
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short FollowerNode::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
      	case NOTIFY_NODE_DIE:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    		assert(observer != NULL && "observer should NOT be NULL");
    		ret = observer->notify(notify_type, notify_cfg);
    	}
    	break;
// Asynchronous event:
     //  	case NOTIFY_ABORT_FILE_TRANSFER:
    	// {
    	// 	PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    	// 	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    	// 	assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    	// 	ret = notify_thread->add_event(notify_cfg);
    	// }
    	// break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d, %s", notify_type, GetNotifyDescription(notify_type));
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short FollowerNode::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
   //  	case NOTIFY_ABORT_FILE_TRANSFER:
   //  	{
   //  		WRITE_DEBUG("File transfer ABORT !!!");
   //  		assert(file_channel != NULL && "file_channel should NOT be NULL");
			// ret = file_channel->deinitialize();
			// delete file_channel;
			// file_channel = NULL;
			// if (CHECK_FAILURE(ret))
			// 	return ret;
   //  	}
   //  	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d, %s", notify_type, GetNotifyDescription(notify_type));
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}