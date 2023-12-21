#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include "file_sender.h"


using namespace std;

const char* FileSender::tx_listen_thread_tag = "File Transfer Listen Thread";
const int FileSender::WAIT_CONNECTION_TIMEOUT = 60; // 5 seconds


FileSender::FileSender(PIMANAGER parent, const char* token) :
	observer(parent),
	tx_socketfd(0),
	local_cluster(true),
	local_token(NULL),
	notify_thread(NULL),
	tx_listen_exit(0),
	tx_listen_tid(0),
	tx_listen_thread_ret(RET_SUCCESS),
	tx_session_id(-1),
	tx_filepath(NULL)
{
	IMPLEMENT_MSG_DUMPER()
	observer = parent;
	assert(observer != NULL && "observer should NOT be NULL");
	if (token != NULL)
		local_token = strdup(token);
}

FileSender::~FileSender()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in FileSender::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(errmsg);
	}
	if (observer != NULL)
		observer = NULL;
	if (local_token != NULL)
	{
		// delete[] local_token;
		free(local_token);
		local_token = NULL;
	}
	RELEASE_MSG_DUMPER()
}

unsigned short FileSender::remove_file_channel(const string& node_token)
{
	WRITE_FORMAT_DEBUG("Try to remove the file channel[%s]", node_token.c_str());
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&file_channel_mtx);
	map<string, PFILE_CHANNEL>::iterator iter = file_channel_map.find(node_token);
	if (iter == file_channel_map.end())
	{
		WRITE_FORMAT_ERROR("The file channel to Follower[%s] does NOT exist", node_token.c_str());
		pthread_mutex_unlock(&file_channel_mtx);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	else
		WRITE_FORMAT_DEBUG("The file channel to %s FOUND. Release the resource...", node_token.c_str());
	PFILE_CHANNEL file_channel = (PFILE_CHANNEL)iter->second;
	assert(file_channel != NULL && "file_channel should NOT be NULL");
// Stop the node of the channel
	ret = file_channel->deinitialize();
	delete file_channel;
	file_channel = NULL;
// Remove the node
	file_channel_map.erase(node_token);
	pthread_mutex_unlock(&file_channel_mtx);
	
	return ret;
}

unsigned short FileSender::become_file_sender()
{
	int on = 1;
	unsigned short ret = RET_SUCCESS;
// Create socket
	int listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sd < 0)
	{
		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
// Allow socket descriptor to be reuseable
// Bind failed: Address already in use: 
// I faced the same issue when I closed the server program with client program still running. This put the socket into TIME_WAIT stat
/*
What exactly does SO_REUSEADDR do?
This socket option tells the kernel that even if 
this port is busy (in the TIME_WAIT state), go ahead and 
reuse it anyway. If it is busy, but with another state, 
you will still get an address already in use error. 
It is useful if your server has been shut down, and then 
restarted right away while sockets are still active on its port. 

*** How do I remove a CLOSE_WAIT socket connection ***
CLOSE_WAIT means your program is still running, and hasn't 
closed the socket (and the kernel is waiting for it to do so). 
Add -p to netstat to get the pid, and then kill it more 
forcefully (with SIGKILL if needed). 
That should get rid of your CLOSE_WAIT sockets. 
You can also use ps to find the pid.

SO_REUSEADDR is for servers and TIME_WAIT sockets, so doesn't apply here.
*/
   if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) < 0)
   {
      WRITE_FORMAT_ERROR("setsockopt() fails, due to: %s", strerror(errno));
      close(listen_sd);
      return RET_FAILURE_SYSTEM_API;
   }

// Set socket to be nonblocking. 
/*
All sockets for the incoming connections will also be nonblocking
since they will inherit that state from the listening socket.   
*/
   if (ioctl(listen_sd, FIONBIO, (char*)&on) < 0)
   {
      WRITE_FORMAT_ERROR("ioctl() fails, due to: %s", strerror(errno));
      close(listen_sd);
      return RET_FAILURE_SYSTEM_API;
   }
// Bind
	int socket_len;
	struct sockaddr_in server_address;
	memset(&server_address, 0x0, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(FILE_TRANSFER_PORT_NO);
	socket_len = sizeof(server_address);
	if (bind(listen_sd, (struct sockaddr*)&server_address, socket_len) == -1)
	{
		WRITE_FORMAT_ERROR("bind() fail, due to: %s", strerror(errno));
		close(listen_sd);
		return RET_FAILURE_SYSTEM_API;
	}
// Listen
	if (listen(listen_sd, MAX_CONNECTED_CLIENT) == -1)
	{
		WRITE_FORMAT_ERROR("listen() fail, due to: %s", strerror(errno));
		close(listen_sd);
		return RET_FAILURE_SYSTEM_API;
	}
	tx_socketfd = listen_sd;

	WRITE_FORMAT_INFO("Node[%s] is a File Sender", local_token);

	return ret;
}

unsigned short FileSender::start_file_transfer()
{
// Restrict only one file transfer process at one time in the cluster
	unsigned short ret = RET_SUCCESS;
	if (tx_listen_tid == 0)
	{
		pthread_mutex_lock(&tx_mtx);
		if (tx_listen_tid == 0)
		{
			ret = become_file_sender();
			if (CHECK_FAILURE(ret))
				goto OUT;

// Create worker thread
			if (pthread_create(&tx_listen_tid, NULL, tx_listen_thread_handler, this))
			{
				WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting file trasnfer client, due to: %s",strerror(errno));
				ret = RET_FAILURE_HANDLE_THREAD;
				goto OUT;
			}
		}
		else
		{
			WRITE_FORMAT_ERROR("Another file transfer is in process[2], tx_listen_tid: %d", tx_listen_tid);
			ret = RET_WARN_FILE_TRANSFER_IN_PROCESS;
			goto OUT;
		}
OUT:
		pthread_mutex_unlock(&tx_mtx);
	}
	else
	{
		WRITE_FORMAT_ERROR("Another file transfer is in process[1], tx_listen_tid: %d", tx_listen_tid);
		ret = RET_WARN_FILE_TRANSFER_IN_PROCESS;
	}

	return ret;
}

unsigned short FileSender::stop_file_transfer()
{
// Restrict only one file transfer process at one time in the cluster
	unsigned short ret = RET_SUCCESS;
	if (tx_listen_tid != 0)
	{
		pthread_mutex_lock(&tx_mtx);
// Notify the worker thread it's time to exit
		__sync_fetch_and_add(&tx_listen_exit, 1);
		usleep(100000);
// Check tx listen thread alive
		// bool listen_thread_alive = false;
		if (tx_listen_tid != 0)
		{
			int kill_ret = pthread_kill(tx_listen_tid, 0);
			if(kill_ret == ESRCH)
			{
				WRITE_WARN("The worker thread of file tx listening did NOT exist......");
				ret = RET_SUCCESS;
			}
			else if(kill_ret == EINVAL)
			{
				WRITE_ERROR("The signal to the worker thread of file tx listening is invalid");
				ret = RET_FAILURE_HANDLE_THREAD;
			}
			else
			{
				WRITE_DEBUG("The signal to the worker thread of file tx listening is STILL alive");
// Kill the thread
			    if (pthread_cancel(tx_listen_tid) != 0)
			        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of file tx listening, due to: %s", strerror(errno));
				usleep(100000);
			}
		}

		WRITE_DEBUG("Wait for the worker thread of file tx listening's death...");

// Wait for file tx listen thread's death
		pthread_join(tx_listen_tid, NULL);
		tx_listen_tid = 0;
		tx_listen_exit = 0;
		if (CHECK_SUCCESS(tx_listen_thread_ret))
		{
			WRITE_FORMAT_DEBUG("Wait for the worker thread[tx_listen_tid: %d] of file tx listening's death Successfully !!!", tx_listen_tid);
		}
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread[tx_listen_tid: %d] of file tx listening's death, due to: %s", tx_listen_tid, GetErrorDescription(tx_listen_thread_ret));
			ret = tx_listen_thread_ret;
		}

		pthread_mutex_unlock(&tx_mtx);
	}
	else
	{
		WRITE_INFO("No file transfer is in process");
	}

	return ret;
}

// unsigned short FileSender::initialize(const char* filepath, const char* channel_token, const char* channel_remote_token, int channel_socket, bool sender, bool session_id)
unsigned short FileSender::initialize()
{
	unsigned short ret = RET_SUCCESS;
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "Leader Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;

// Initialize the synchronization object
	tx_mtx = PTHREAD_MUTEX_INITIALIZER;
	file_channel_mtx = PTHREAD_MUTEX_INITIALIZER;

	return RET_SUCCESS;
}

unsigned short FileSender::deinitialize()
{
	WRITE_DEBUG("Release resource in FileSender......");
	unsigned short ret = RET_SUCCESS;
	ret = stop_file_transfer();
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to stop file transfer, due to: %s", GetErrorDescription(ret));
	}
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	return ret;
}


unsigned short FileSender::set(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
       	case PARAM_LOCAL_CLUSTER:
    	{
    		local_cluster = *(bool*)param1;
    	}
    	break;
    	case PARAM_FILE_TRANSFER:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		PFILE_TRANSFER_PARAM file_transfer_param = (PFILE_TRANSFER_PARAM)param1; 
    		assert(file_transfer_param != NULL && "file_transfer_param should NOT be NULL");
			tx_session_id = file_transfer_param->session_id;
			if (tx_session_id == -1)
			{
				WRITE_ERROR("tx_session_id should NOT be -1");
				return RET_FAILURE_SYSTEM_API;
			}			
			tx_filepath = strdup(file_transfer_param->filepath);
			if (tx_filepath == NULL)
			{
				WRITE_FORMAT_ERROR("strdup() fails, due to: %s", strerror(errno));		
				return RET_FAILURE_SYSTEM_API;
			}
// Start a thread for listening the connection request of file tranfer from the folower
    		ret = start_file_transfer();
			if (CHECK_FAILURE(ret))
				return ret;
// // Notify the folower to connect to the sender and become a receiver
// 			ret = send_request_file_transfer();
// 			if (CHECK_FAILURE(ret))
// 				return ret;	
    	}
    	break;
    	case PARAM_FILE_TRANSFER_DONE:
    	{
    		ret = stop_file_transfer();
    	}
    	break;
    	case PARAM_REMOVE_FILE_CHANNEL:
    	{
    		string follower_token((char*)param1);
    		WRITE_FORMAT_WARN("Send file to the follwer[%s] completely, remove the file channel to the follower", follower_token.c_str());
			ret = remove_file_channel(follower_token);
    		if (CHECK_FAILURE(ret))
    			WRITE_FORMAT_ERROR("Fails to remove file channel to follower[%s], due to: %s", follower_token.c_str(), GetErrorDescription(ret));
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

unsigned short FileSender::get(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
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

unsigned short FileSender::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
    	case NOTIFY_SEND_FILE_DONE:
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
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short FileSender::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
      	case NOTIFY_SEND_FILE_DONE:
    	{
    		assert(observer != NULL && "observer should NOT be NULL");
    		observer->notify(NOTIFY_SEND_FILE_DONE, (void*)notify_cfg);
    		// string follower_token((char*)notify_cfg->get_notify_param());
   //  		PNOTIFY_SEND_FILE_DONE_CFG notify_send_file_done_cfg = (PNOTIFY_SEND_FILE_DONE_CFG)notify_cfg;
   //  		string follower_token(notify_send_file_done_cfg->get_remote_token());
   //  		WRITE_FORMAT_WARN("Send file to the follwer[%s] completely, remove the file channel to the follower", follower_token.c_str());
			// ret = remove_file_channel(follower_token);
   //  		if (CHECK_FAILURE(ret))
   //  			WRITE_FORMAT_ERROR("Fails to remove file channel to follower[%s], due to: %s", follower_token.c_str(), GetErrorDescription(ret));
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

void* FileSender::tx_listen_thread_handler(void* pvoid)
{
	FileSender* pthis = (FileSender*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->tx_listen_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->tx_listen_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->tx_listen_thread_ret))
	{
		pthread_cleanup_push(tx_listen_thread_cleanup_handler, pthis);
		pthis->tx_listen_thread_ret = pthis->tx_listen_thread_handler_internal();
		pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->listen_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->listen_thread_ret)));
	pthread_exit(NULL);
}

unsigned short FileSender::tx_listen_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of file transfer listening socket is running", tx_listen_thread_tag);
	unsigned short ret = RET_SUCCESS;

	struct sockaddr client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	while (tx_listen_exit == 0)
	{
		struct timeval tv;
		fd_set sock_set;
		tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&sock_set);
		FD_SET(tx_socketfd, &sock_set);
		int res = select(tx_socketfd + 1, &sock_set, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR)
		{
			WRITE_FORMAT_ERROR("[%s] select() fails, due to: %s",tx_listen_thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			usleep(100000);
			continue;
		}		
// Follower connect to Leader
		int client_socketfd = accept(tx_socketfd, &client_addr, (socklen_t*)&client_addr_len);
		if (client_socketfd < 0)
		{
			WRITE_FORMAT_ERROR("[%s] accept() fails, due to: %s", tx_listen_thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		// deal with both IPv4 and IPv6:
		struct sockaddr_in *client_s = (struct sockaddr_in *)&client_addr;
		// PRINT("family: %d, port: %d\n", s->sin_family, ntohs(s->sin_port));
//		port = ntohs(s->sin_port);
		char client_token[INET_ADDRSTRLEN + 1];
		inet_ntop(AF_INET, &client_s->sin_addr, client_token, sizeof(client_token));
		WRITE_FORMAT_INFO("[%s] Receiver[%s] request connecting to the Sender", tx_listen_thread_tag, client_token);
		// PRINT("Follower[%s] connects to the Leader\n", token);
// Initialize a channel for file transfer between follower
		PFILE_CHANNEL file_channel = new FileChannel(this);
		if (file_channel == NULL)
		{
			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: file_channel", tx_listen_thread_tag);
			// pthread_mutex_unlock(&node_channel_mtx);
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}
		WRITE_FORMAT_INFO("[%s] Initialize the File Channel between Receiver[%s] and Sender", tx_listen_thread_tag, client_token);
		ret = file_channel->initialize(tx_filepath, local_token, client_token, client_socketfd, true, tx_session_id);
		if (CHECK_FAILURE(ret))
			return ret;
		sleep(3);
// Start to transfer the file
		WRITE_FORMAT_DEBUG("[%s] Notify Receiver[%s] to start to transfer data...", tx_listen_thread_tag, client_token);
		ret = file_channel->request_transfer();
		if (CHECK_FAILURE(ret))
			return ret;

// Add a channel for file transfer
		pthread_mutex_lock(&file_channel_mtx);
		file_channel_map[client_token] = file_channel;
		pthread_mutex_unlock(&file_channel_mtx);
		PRINT("[%s] The File Channel between Receiver[%s] and Sender is Established......\n", tx_listen_thread_tag, client_token);
		WRITE_FORMAT_INFO("[%s] Receiver File Channel[%s] connects to the Sender...... successfully !!!", tx_listen_thread_tag, client_token);
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of file trasnfer listening socket is dead", tx_listen_thread_tag);
	return ret;
}

void FileSender::tx_listen_thread_cleanup_handler(void* pvoid)
{
	FileSender* pthis = (FileSender*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->tx_listen_thread_cleanup_handler_internal();
}

void FileSender::tx_listen_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the tx listen thread......", tx_listen_thread_tag);
	pthread_mutex_lock(&file_channel_mtx);
	map<std::string, PFILE_CHANNEL>::iterator iter = file_channel_map.begin();
	while (iter != file_channel_map.end())
	{
		PFILE_CHANNEL file_channel = (PFILE_CHANNEL)(iter->second);
		iter++;
		if (file_channel != NULL)
		{
			file_channel->deinitialize();
			delete file_channel;
			file_channel = NULL;
		}
	}
	file_channel_map.clear();
	pthread_mutex_unlock(&file_channel_mtx);
	if (tx_socketfd != 0)
	{
		close(tx_socketfd);
		tx_socketfd = 0;
	}
}
