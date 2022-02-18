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
	tx_socketfd(0),
	local_cluster(true),
	local_token(NULL),
	cluster_token(NULL),
	cluster_id(0),
	keepalive_cnt(0),
	connection_retry(false),
	node_channel(NULL),
	notify_thread(NULL),
	file_channel(NULL)
{
	IMPLEMENT_MSG_DUMPER()

	local_token = strdup(token);
	cluster_token = strdup(server_token);
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
	if (observer != NULL)
		observer = NULL;

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

	int res;
	if (local_cluster)
	{
		sockaddr_un client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_un));
		client_address.sun_family = AF_UNIX;
		strcpy(client_address.sun_path, CLUSTER_UDS_FILEPATH);
		res = connect(sock_fd, (struct sockaddr*)&client_address, sizeof(struct sockaddr));
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

	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", cluster_token);
	socketfd = sock_fd;

	return RET_SUCCESS;
}

unsigned short FollowerNode::become_follower()
{
// Try to connect to the designated server
	unsigned short ret = connect_leader();
	if (IS_TRY_CONNECTION_TIMEOUT(ret))
	{
		WRITE_FORMAT_DEBUG("Node[%s] is NOT a server", cluster_token);
		return RET_FAILURE_CONNECTION_TRY_TIMEOUT;
	}
	else
	{
		if (CHECK_FAILURE(ret))
			return ret;
	}

	WRITE_FORMAT_INFO("Node[%s] is a Follower", local_token);
	printf("Node[%s] is a Follower, connect to Leader[%s] !!!\n", local_token, cluster_token);

	return ret;
}


unsigned short FollowerNode::connect_file_sender()
{
	WRITE_FORMAT_DEBUG("Try to connect to File sender[%s]......", cluster_token);

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

	int res;
	if (local_cluster)
	{
		sockaddr_un client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_un));
		client_address.sun_family = AF_UNIX;
		strcpy(client_address.sun_path, CLUSTER_UDS_FILEPATH);
		res = connect(sock_fd, (struct sockaddr*)&client_address, sizeof(struct sockaddr));
	}
	else
	{
		sockaddr_in client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_in));
		client_address.sin_family = AF_INET;
		client_address.sin_port = htons(FILE_TRANSFER_PORT_NO);
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

	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", cluster_token);
	tx_socketfd = sock_fd;

	return RET_SUCCESS;
}

unsigned short FollowerNode::send_data(MessageType message_type, const char* data)
{
	unsigned short ret = RET_SUCCESS;
	// assert(msg != NULL && "msg should NOT be NULL");
	// fprintf(stderr, "Follower[%s] Message: type: %d, data: %s\n", local_token, message_type, data);
	NodeMessageAssembler node_message_assembler;
	ret = node_message_assembler.assemble(message_type, data);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to assemble the message, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	pthread_mutex_lock(&node_channel_mtx);
// Send to leader
	assert(node_channel != NULL && "node_channel should NOT be NULL");
	ret = node_channel->send_msg(node_message_assembler.get_full_message());
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fail to send msg to the Leader[%s], due to: %s", cluster_token, GetErrorDescription(ret));
	pthread_mutex_unlock(&node_channel_mtx);
	// fprintf(stderr, "Follower[%s] send Message to remote: %s[type: %d]\n", local_token, (node_message_assembler.get_full_message() + 1), (int)(*node_message_assembler.get_full_message()));
	return ret;
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
			if (IS_TRY_CONNECTION_TIMEOUT(ret) && connection_retry)
			{
				WRITE_FORMAT_DEBUG("Re-build the cluster. Node[%s] try to connect to Leader[%s], but no response... %d", local_token, cluster_token, i);
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

	if (file_channel != NULL)
	{
		ret = file_channel->deinitialize();
		delete file_channel;
		file_channel = NULL;
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_WARN("Fail to de-initialize the file channel worker thread[Node: %s]", local_token);
	}

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

unsigned short FollowerNode::recv(MessageType message_type, const std::string& message_data)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", token.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (FollowerNode::*RECV_FUNC_PTR)(const std::string& message_data);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		NULL,
		&FollowerNode::recv_check_keepalive,
		&FollowerNode::recv_update_cluster_map,
		&FollowerNode::recv_transmit_text,
		&FollowerNode::recv_get_system_info,
		&FollowerNode::recv_get_simulator_version,
		&FollowerNode::recv_install_simulator,
		&FollowerNode::recv_apply_fake_acspt_config,
		&FollowerNode::recv_apply_fake_usrept_config,
		&FollowerNode::recv_control_fake_acspt,
		&FollowerNode::recv_control_fake_usrept,
		&FollowerNode::recv_get_fake_acspt_state,
		&FollowerNode::recv_request_file_transfer,
		&FollowerNode::recv_complete_file_transfer
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
		&FollowerNode::send_transmit_text,
		&FollowerNode::send_get_system_info,
		&FollowerNode::send_get_simulator_version,
		&FollowerNode::send_install_simulator,
		&FollowerNode::send_apply_fake_acspt_config,
		&FollowerNode::send_apply_fake_usrept_config,
		&FollowerNode::send_control_fake_acspt,
		&FollowerNode::send_control_fake_usrept,
		&FollowerNode::send_get_fake_acspt_state,
		&FollowerNode::send_request_file_transfer,
		&FollowerNode::send_complete_file_transfer
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short FollowerNode::recv_check_keepalive(const std::string& message_data)
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

unsigned short FollowerNode::recv_update_cluster_map(const std::string& message_data)
{
// Message format:
// EventType | Payload: Cluster map string| EOD
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&cluster_map_mtx);
	// fprintf(stderr, "Follower: %s\n", message_data.c_str());
	// fprintf(stderr, "FollowerNode::recv_update_cluster_map %s, %d\n", message_data.c_str(), strlen(message_data.c_str()));
	ret = cluster_map.from_string(message_data.c_str());
	// fprintf(stderr, "!Follower: %s\n", cluster_map.to_string());
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to update the cluster map in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
		goto OUT;
	}
	if (cluster_id == 0)
	{
// New Follower get the Node ID from Leader
	    ret = cluster_map.get_last_node_id(cluster_id);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fails to get node ID in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
			goto OUT;
		}
    }
OUT:
	pthread_mutex_unlock(&cluster_map_mtx);
	return ret;
}

unsigned short FollowerNode::recv_transmit_text(const std::string& message_data)
{
// Message format:
// EventType | text string| EOD
	printf("Recv Text: %s\n", message_data.c_str());
	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_get_system_info(const std::string& message_data)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	int session_id = atoi(message_data.c_str());
	ret = send_get_system_info((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_get_simulator_version(const std::string& message_data)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	int session_id = atoi(message_data.c_str());
	ret = send_get_simulator_version((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_install_simulator(const std::string& message_data)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	const char* simulator_package_filepath = (const char*)message_data.c_str();
	size_t notify_param_size = strlen(simulator_package_filepath) + 1;
	PNOTIFY_CFG notify_cfg = new NotifySimulatorInstallCfg((void*)simulator_package_filepath, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_INSTALL_SIMULATOR, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_apply_fake_acspt_config(const std::string& message_data)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	const char* fake_acspt_config_line_list_str = (const char*)message_data.c_str();
	size_t notify_param_size = strlen(fake_acspt_config_line_list_str) + 1;
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptConfigApplyCfg((void*)fake_acspt_config_line_list_str, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_APPLY_FAKE_ACSPT_CONFIG, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_apply_fake_usrept_config(const std::string& message_data)
{
// Message format:
// EventType | Payload: simulator package filepath | EOD
	unsigned short ret = RET_SUCCESS;
	const char* fake_usrept_config_line_list_str = (const char*)message_data.c_str();
	size_t notify_param_size = strlen(fake_usrept_config_line_list_str) + 1;
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptConfigApplyCfg((void*)fake_usrept_config_line_list_str, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_APPLY_FAKE_USREPT_CONFIG, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_control_fake_acspt(const std::string& message_data)
{
// Message format:
// EventType | Payload: simulator ap control type | EOD
	unsigned short ret = RET_SUCCESS;
	FakeAcsptControlType fake_acspt_control_type = (FakeAcsptControlType)atoi(message_data.c_str());
	size_t notify_param_size = sizeof(FakeAcsptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_CONTROL_FAKE_ACSPT, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_control_fake_usrept(const std::string& message_data)
{
// Message format:
// EventType | Payload: simulator ue control type | EOD
	unsigned short ret = RET_SUCCESS;
	FakeUsreptControlType fake_usrept_control_type = (FakeUsreptControlType)atoi(message_data.c_str());
	size_t notify_param_size = sizeof(FakeUsreptControlType);
	PNOTIFY_CFG notify_cfg = new NotifyFakeUsreptControlCfg((void*)&fake_usrept_control_type, notify_param_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
    assert(observer != NULL && "observer should NOT be NULL");
// Synchronous event
    observer->notify(NOTIFY_CONTROL_FAKE_USREPT, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return ret;
}

unsigned short FollowerNode::recv_get_fake_acspt_state(const std::string& message_data)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	int session_id = atoi(message_data.c_str());
	ret = send_get_fake_acspt_state((void*)&session_id, (void*)&cluster_id);
	return ret;
}

unsigned short FollowerNode::recv_request_file_transfer(const std::string& message_data)
{
// Message format:
// EventType | filepath | EOD
	assert(file_channel == NULL && "file_channel should be NULL");
	const char* tx_filepath = (const char*)message_data.c_str();
	unsigned short ret = RET_SUCCESS;
	usleep((random() % 10) * 100000);
// Receiver tries to connect to Sender
	ret = connect_file_sender();
	if (CHECK_FAILURE(ret))
		return ret;
// Create the channel for file tranfer
	file_channel = new FileChannel(this);
	if (file_channel == NULL)
	{
		WRITE_ERROR("Fail to allocate memory: file_channel");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}

	WRITE_FORMAT_INFO("Initialize the File Channel in Receiver[%s]", local_token);
	ret = file_channel->initialize(tx_filepath, local_token, cluster_token, tx_socketfd);
	if (CHECK_FAILURE(ret))
		return ret;

	return RET_SUCCESS;
}

unsigned short FollowerNode::recv_complete_file_transfer(const std::string& message_data)
{
// Message format:
// EventType | session ID | EOD
	unsigned short ret = RET_SUCCESS;
	if (file_channel != NULL)
	{
// ret is the recv thread return code
		ret = file_channel->deinitialize();
		delete file_channel;
		file_channel = NULL;
		if (CHECK_FAILURE(ret))
			return ret;
	}
	else
		WRITE_WARN("The file channel does NOT exist");

	int session_id = atoi(message_data.c_str());
	ret = send_complete_file_transfer((void*)&session_id, (void*)&ret);
	return ret;
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
	return send_data(MSG_CHECK_KEEPALIVE, local_token);
	// char msg = (char)MSG_CHECK_KEEPALIVE;
	// return send_data(&msg);
}

unsigned short FollowerNode::send_update_cluster_map(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_UPDATE_CLUSUTER_MAP);}

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
	return send_data(MSG_TRANSMIT_TEXT, text_data);
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
	string system_info;
	ret = get_system_info(system_info);
	if (CHECK_FAILURE(ret))
		WRITE_FORMAT_ERROR("Fails to get system info in Follower[%s], due to: %s", local_token, GetErrorDescription(ret));
	else
		system_info_data += system_info;
	// fprintf(stderr, "Follower[%s] send_get_system_info message: %s\n", local_token, system_info_data.c_str());
	// char session_id_str[3];
	// memset(session_id_str, 0x0, sizeof(char) * 3);
	// memcpy(session_id_str, system_info_data.c_str(), sizeof(char) * 2);
	// fprintf(stderr, "Follower[%s] send_get_system_info session id: %d, system info: %s\n", local_token, atoi(session_id_str), (system_info_data.c_str() + 2));
	return send_data(MSG_GET_SYSTEM_INFO, system_info_data.c_str());
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

	return send_data(MSG_GET_SIMULATOR_VERSION, simulator_version_data.c_str());
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

	return send_data(MSG_GET_FAKE_ACSPT_STATE, fake_acspt_state_data.c_str());
}

unsigned short FollowerNode::send_request_file_transfer(void* param1, void* param2, void* param3){UNDEFINED_MSG_EXCEPTION("Follower", "Send", MSG_REQUEST_FILE_TRANSFER);}

unsigned short FollowerNode::send_complete_file_transfer(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: The sessin id
// param2: The return code
// Message format:
// EventType | playload: (session ID[2 digits]) | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
	static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
	static const int RETURN_CODE_BUF_SIZE = sizeof(unsigned short) + 1;
    // unsigned short ret = RET_SUCCESS;
// Serialize: convert the type of session id from integer to string  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// Serialize: convert the type of session id from integer to string  
	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, cluster_id);
// Serialize: convert the type of return code from integer to string  
	char return_code_buf[RETURN_CODE_BUF_SIZE];
	memset(return_code_buf, 0x0, sizeof(return_code_buf) / sizeof(return_code_buf[0]));
	snprintf(return_code_buf, RETURN_CODE_BUF_SIZE, "%hu", *(int*)param2);

	string file_transfer_data = string(session_id_buf) + string(cluster_id_buf) + string(return_code_buf);
	return send_data(MSG_COMPLETE_FILE_TRANSFER, file_transfer_data.c_str());
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
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown param type: %d", param_type);
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
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
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
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
      	case NOTIFY_ABORT_FILE_TRANSFER:
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
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
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
    	case NOTIFY_ABORT_FILE_TRANSFER:
    	{
    		WRITE_DEBUG("File transfer ABORT !!!");
    		assert(file_channel != NULL && "file_channel should NOT be NULL");
			ret = file_channel->deinitialize();
			delete file_channel;
			file_channel = NULL;
			if (CHECK_FAILURE(ret))
				return ret;
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		fprintf(stderr, "%s in %s:%d", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}