#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "file_receiver.h"


using namespace std;

const int FileReceiver::WAIT_CONNECTION_TIMEOUT = 60; // 5 seconds

FileReceiver::FileReceiver(PIMANAGER parent, const char* server_token, const char* token) :
	observer(parent),
	tx_socketfd(0),
	local_token(NULL),
	sender_token(NULL),
	notify_thread(NULL),
	file_channel(NULL)
{
	IMPLEMENT_MSG_DUMPER()
	observer = parent;
	assert(observer != NULL && "observer should NOT be NULL");

	if (token != NULL)
		local_token = strdup(token);
	if (server_token != NULL)
		sender_token = strdup(server_token);
}

FileReceiver::~FileReceiver()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in FileReceiver::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (observer != NULL)
		observer = NULL;

	RELEASE_MSG_DUMPER()
}

unsigned short FileReceiver::connect_file_sender()
{
	WRITE_FORMAT_DEBUG("Try to connect to File sender[%s]......", sender_token);

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
// http://www.cas.mcmaster.ca/~qiao/courses/cs3mh3/tutorials/socket.html
	int res;
	if (local_cluster)
	{
		int socket_len;
		sockaddr_un client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_un));
		client_address.sun_family = AF_UNIX;
		strcpy(client_address.sun_path, CLUSTER_UDS_FILEPATH);
		socket_len = sizeof(client_address.sun_family) + strlen(client_address.sun_path);
		// fprintf(stderr, "socket_len: %d, sun_path: %s\n", socket_len, client_address.sun_path);
		res = connect(sock_fd, (struct sockaddr*)&client_address, socket_len);
	}
	else
	{
		sockaddr_in client_address;
		memset(&client_address, 0x0, sizeof(struct sockaddr_in));
		client_address.sin_family = AF_INET;
		client_address.sin_port = htons(FILE_TRANSFER_PORT_NO);
		client_address.sin_addr.s_addr = inet_addr(sender_token);
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

	WRITE_FORMAT_DEBUG("Try to connect to %s......Successfully", sender_token);
	tx_socketfd = sock_fd;

	return RET_SUCCESS;
}

unsigned short FileReceiver::request_file_transfer(const char* tx_filepath)
{
// Message format:
// EventType | filepath | EOD
	assert(file_channel == NULL && "file_channel should be NULL");
	// const char* tx_filepath = (const char*)message_data.c_str();
	unsigned short ret = RET_SUCCESS;
	// usleep((random() % 10) * 100000);
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
	ret = file_channel->initialize(tx_filepath, local_token, sender_token, tx_socketfd);
	if (CHECK_FAILURE(ret))
		return ret;

	return RET_SUCCESS;
}

unsigned short FileReceiver::complete_file_transfer()
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

	// int session_id = atoi(message_data.c_str());
	// ret = send_complete_file_transfer((void*)&session_id, (void*)&ret);
	return ret;
}

// unsigned short FileReceiver::initialize(const char* filepath, const char* channel_token, const char* channel_remote_token, int channel_socket, bool sender, bool session_id)
unsigned short FileReceiver::initialize()
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

	return RET_SUCCESS;
}

unsigned short FileReceiver::deinitialize()
{
	WRITE_DEBUG("Release resource in FileReceiver......");
	unsigned short ret = RET_SUCCESS;
	if (file_channel != NULL)
	{
		ret = file_channel->deinitialize();
		delete file_channel;
		file_channel = NULL;
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_WARN("Fail to de-initialize the file channel worker thread[Node: %s]", local_token);
	}
	if (sender_token != NULL)
	{
		free(sender_token);
		sender_token = NULL;
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
	return ret;
}

unsigned short FileReceiver::set(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	case PARAM_LOCAL_CLUSTER:
    	{
    		local_cluster = *(bool*)param1;
    	}
    	break;
//     	case PARAM_FILE_TRANSFER:
//     	{
//     		if (param1 == NULL)
//     		{
//     			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
//     			return RET_FAILURE_INVALID_ARGUMENT;
//     		}
//     		PFILE_TRANSFER_PARAM file_transfer_param = (PFILE_TRANSFER_PARAM)param1; 
//     		assert(file_transfer_param != NULL && "file_transfer_param should NOT be NULL");
// 			tx_session_id = file_transfer_param->session_id;
// 			if (tx_session_id == -1)
// 			{
// 				WRITE_ERROR("tx_session_id should NOT be -1");
// 				return RET_FAILURE_SYSTEM_API;
// 			}			
// 			tx_filepath = strdup(file_transfer_param->filepath);
// 			if (tx_filepath == NULL)
// 			{
// 				WRITE_FORMAT_ERROR("strdup() fails, due to: %s", strerror(errno));		
// 				return RET_FAILURE_SYSTEM_API;
// 			}
// // Start a thread for listening the connection request of file tranfer from the folower
//     		ret = request_file_transfer();
// 			if (CHECK_FAILURE(ret))
// 				return ret;
//     	}
//     	break;
    	case PARAM_FILE_TRANSFER_DONE:
    	{
    		ret = complete_file_transfer();
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

unsigned short FileReceiver::get(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
    	case PARAM_SENDER_TOKEN:
    	{
    		*(char**)param1 = strdup(sender_token);
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

unsigned short FileReceiver::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
    	case NOTIFY_CONNECT_FILE_TRANSFER:
    	{
    		PNOTIFY_FILE_TRANSFER_CONNECT_CFG notify_file_transfer_connect_cfg = (PNOTIFY_FILE_TRANSFER_CONNECT_CFG)notify_param;
    		const char* filepath = notify_file_transfer_connect_cfg->get_filepath();
    		ret = request_file_transfer(filepath);
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
    	// case NOTIFY_RECV_FILE_DONE:
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
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short FileReceiver::async_handle(NotifyCfg* notify_cfg)
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
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}
