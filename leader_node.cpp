// #include <errno.h>
// #include <assert.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
// #include <stdexcept>
// #include <string>
#include <deque>
#include "leader_node.h"


using namespace std;

const char* LeaderNode::listen_thread_tag = "Listen Thread";
// const char* LeaderNode::tx_listen_thread_tag = "File Transfer Listen Thread";
const int LeaderNode::WAIT_CONNECTION_TIMEOUT = 60; // 5 seconds

LeaderNode::LeaderNode(PIMANAGER parent, const char* token) :
	observer(parent),
	socketfd(0),
	// tx_socketfd(0),
	local_cluster(true),
	local_token(NULL),
	cluster_id(0),
	cluster_node_cnt(0),
	notify_thread(NULL),
	action_freeze(0),
	listen_exit(0),
	listen_tid(0),
	listen_thread_ret(RET_SUCCESS)
	// tx_listen_exit(0),
	// tx_listen_tid(0),
	// tx_listen_thread_ret(RET_SUCCESS),
	// tx_session_id(-1),
	// tx_filepath(NULL)
{
	IMPLEMENT_MSG_DUMPER()
	IMPLEMENT_EVT_RECORDER()
	assert(observer != NULL && "observer should NOT be NULL");
	if (token != NULL)
		local_token = strdup(token);
}

LeaderNode::~LeaderNode()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in LeaderNode::~LeaderNode(), due to :%s", GetErrorDescription(ret));
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

	RELEASE_EVT_RECORDER()
	RELEASE_MSG_DUMPER()
}

unsigned short LeaderNode::become_leader()
{
	int on = 1;
	unsigned short ret = RET_SUCCESS;
// Create socket
	int listen_sd = 0;
	if (local_cluster)
		listen_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	else
		listen_sd = socket(AF_INET, SOCK_STREAM, 0);
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
	if (!local_cluster)
	{
	   if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) < 0)
	   {
	      WRITE_FORMAT_ERROR("setsockopt() fails, due to: %s", strerror(errno));
	      close(listen_sd);
	      return RET_FAILURE_SYSTEM_API;
	   }		
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
	if (local_cluster)
	{
		int socket_len;
		struct sockaddr_un server_address;
		memset(&server_address, 0x0, sizeof(struct sockaddr_un));
		server_address.sun_family = AF_UNIX;
		strcpy(server_address.sun_path, CLUSTER_UDS_FILEPATH);
		if (access(server_address.sun_path, F_OK) == 0)
		{
			WRITE_FORMAT_ERROR("The old socket file[%s] still exists. Remove it !!!", server_address.sun_path);
			unlink(server_address.sun_path);	
			if (access(server_address.sun_path, F_OK) == 0)
			{
				WRITE_FORMAT_ERROR("Fails to remove the old socket file[%s]", server_address.sun_path);
				return RET_FAILURE_SYSTEM_API;
			}
		}
		// socket_len = sizeof(server_address);
    	socket_len = sizeof(server_address.sun_family) + strlen(server_address.sun_path);
		if (bind(listen_sd, (struct sockaddr*)&server_address, socket_len) == -1)
		{
			WRITE_FORMAT_ERROR("bind() fail(UDS), due to: %s", strerror(errno));
			close(listen_sd);
			return RET_FAILURE_SYSTEM_API;
		}
	}
	else
	{
		int socket_len;
		struct sockaddr_in server_address;
		memset(&server_address, 0x0, sizeof(struct sockaddr_in));
		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
		server_address.sin_port = htons(CLUSTER_PORT_NO);
		socket_len = sizeof(server_address);
		if (bind(listen_sd, (struct sockaddr*)&server_address, socket_len) == -1)
		{
			WRITE_FORMAT_ERROR("bind() fail(TCP), due to: %s", strerror(errno));
			close(listen_sd);
			return RET_FAILURE_SYSTEM_API;
		}		
	}
// Listen
	if (listen(listen_sd, MAX_CONNECTED_CLIENT) == -1)
	{
		WRITE_FORMAT_ERROR("listen() fail, due to: %s", strerror(errno));
		close(listen_sd);
		return RET_FAILURE_SYSTEM_API;
	}
	socketfd = listen_sd;
// Update the cluster map
	cluster_id = 1;
	cluster_node_cnt = 1;
	ret = cluster_map.cleanup_node();
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to cleanup node map, due to: %s", GetErrorDescription(ret));
		return ret;
	}
	ret = cluster_map.add_node(cluster_id, local_token);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to add leader into node map, due to: %s", GetErrorDescription(ret));
		return ret;
	}
	WRITE_FORMAT_INFO("Node[%s] is a Leader", local_token);
	printf("Node[%s] is a Leader !!!\n", local_token);

	return ret;
}

unsigned short LeaderNode::send_raw_data(MessageType message_type, const char* data, int data_size, const char* remote_token)
{
	unsigned short ret = RET_SUCCESS;
	// assert(data != NULL && "data should NOT be NULL");
	// fprintf(stderr, "[send_raw_data]  message_type: %d\n", message_type);

	NodeMessageAssembler node_message_assembler;
	ret = node_message_assembler.assemble(message_type, data, data_size);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fails to assemble the message, due to: %s", GetErrorDescription(ret));
		return ret;
	}

	pthread_mutex_lock(&node_channel_mtx);
	if (remote_token != NULL)
	{
		// fprintf(stderr, "[send_raw_data]  remote_token: %s\n", remote_token);
		// dump_node_channel_map();
// Send to single node
		string remote_token_str = string(remote_token);
		PNODE_CHANNEL node_channel = node_channel_map[remote_token_str];
		// map<string, PNODE_CHANNEL>::iterator iter = node_channel_map.find(remote_token);
		// if (iter == node_channel_map.end())
		// {
		// 	WRITE_FORMAT_ERROR("The Follower[%s] does NOT exist", remote_token.c_str());
		// 	return RET_FAILURE_INVALID_ARGUMENT;
		// }
		// PNODE_CHANNEL node_channel = (PNODE_CHANNEL)iter->second;

		// fprintf(stderr, "[send_raw_data]  node_channel: %p\n", (void*)node_channel);
		assert(node_channel != NULL && "node_channel should NOT be NULL");
		ret = node_channel->send_msg(node_message_assembler.get_message(), node_message_assembler.get_message_size());
		if (CHECK_FAILURE(ret))
			WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", remote_token, GetErrorDescription(ret));
	}
	else
	{
// Send to all nodes
		// deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
		// while(iter != node_channel_deque.end())
		// {
		// 	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
		// 	assert(node_channel != NULL && "node_channel should NOT be NULL");
		// 	ret = node_channel->send_string_data(data);
		// 	if (CHECK_FAILURE(ret))
		// 	{
		// 		WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", node_channel->get_remote_token(), GetErrorDescription(ret));
		// 		break;
		// 	}
		// 	iter++;
		// }
		map<string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
		while(iter != node_channel_map.end())
		{
			PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
			assert(node_channel != NULL && "node_channel should NOT be NULL");
			ret = node_channel->send_msg(node_message_assembler.get_message(), node_message_assembler.get_message_size());
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Fail to send data to the Follower[%s], due to: %s", node_channel->get_remote_token(), GetErrorDescription(ret));
				break;
			}
			iter++;
		}
	}
	pthread_mutex_unlock(&node_channel_mtx);
	return ret;
}

unsigned short LeaderNode::send_string_data(MessageType message_type, const char* data, const char* remote_token)
{
	int data_size = 0;
	if (data != NULL)
		data_size = strlen(data) + 1;
	return send_raw_data(message_type, data, data_size, remote_token);
}

unsigned short LeaderNode::remove_follower(const string& node_token)
{
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&node_channel_mtx);
	map<string, PNODE_CHANNEL>::iterator iter = node_channel_map.find(node_token);
	if (iter == node_channel_map.end())
	{
		WRITE_FORMAT_ERROR("The Follower[%s] does NOT exist", node_token.c_str());
		pthread_mutex_unlock(&node_channel_mtx);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)iter->second;
	assert(node_channel != NULL && "node_channel should NOT be NULL");
// Stop the node of the channel
	node_channel->deinitialize();
	delete node_channel;
	node_channel = NULL;
// Remove the node
	node_channel_map.erase(node_token);
	node_keepalive_map.erase(node_token);
	ret = cluster_map.delete_node_by_token(node_token);
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to delete the node[%s] in the map", node_token.c_str());
	}
	pthread_mutex_unlock(&node_channel_mtx);
	
	return ret;
}

// unsigned short LeaderNode::remove_file_channel(const string& node_token)
// {
// 	WRITE_FORMAT_DEBUG("Try to remove the file channel[%s]", node_token.c_str());
// 	unsigned short ret = RET_SUCCESS;
// 	pthread_mutex_lock(&file_channel_mtx);
// 	map<string, PFILE_CHANNEL>::iterator iter = file_channel_map.find(node_token);
// 	if (iter == file_channel_map.end())
// 	{
// 		WRITE_FORMAT_ERROR("The file channel to Follower[%s] does NOT exist", node_token.c_str());
// 		pthread_mutex_unlock(&file_channel_mtx);
// 		return RET_FAILURE_INVALID_ARGUMENT;
// 	}
// 	else
// 		WRITE_FORMAT_DEBUG("The file channel to %s FOUND. Release the resource...", node_token.c_str());
// 	PFILE_CHANNEL file_channel = (PFILE_CHANNEL)iter->second;
// 	assert(file_channel != NULL && "file_channel should NOT be NULL");
// // Stop the node of the channel
// 	ret = file_channel->deinitialize();
// 	delete file_channel;
// 	file_channel = NULL;
// // Remove the node
// 	file_channel_map.erase(node_token);
// 	pthread_mutex_unlock(&file_channel_mtx);
	
// 	return ret;
// }

// unsigned short LeaderNode::become_file_sender()
// {
// 	int on = 1;
// 	unsigned short ret = RET_SUCCESS;
// // Create socket
// 	int listen_sd = socket(AF_INET, SOCK_STREAM, 0);
// 	if (listen_sd < 0)
// 	{
// 		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// // Allow socket descriptor to be reuseable
// // Bind failed: Address already in use: 
// // I faced the same issue when I closed the server program with client program still running. This put the socket into TIME_WAIT stat
// /*
// What exactly does SO_REUSEADDR do?
// This socket option tells the kernel that even if 
// this port is busy (in the TIME_WAIT state), go ahead and 
// reuse it anyway. If it is busy, but with another state, 
// you will still get an address already in use error. 
// It is useful if your server has been shut down, and then 
// restarted right away while sockets are still active on its port. 

// *** How do I remove a CLOSE_WAIT socket connection ***
// CLOSE_WAIT means your program is still running, and hasn't 
// closed the socket (and the kernel is waiting for it to do so). 
// Add -p to netstat to get the pid, and then kill it more 
// forcefully (with SIGKILL if needed). 
// That should get rid of your CLOSE_WAIT sockets. 
// You can also use ps to find the pid.

// SO_REUSEADDR is for servers and TIME_WAIT sockets, so doesn't apply here.
// */
//    if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on)) < 0)
//    {
//       WRITE_FORMAT_ERROR("setsockopt() fails, due to: %s", strerror(errno));
//       close(listen_sd);
//       return RET_FAILURE_SYSTEM_API;
//    }

// // Set socket to be nonblocking. 
// /*
// All sockets for the incoming connections will also be nonblocking
// since they will inherit that state from the listening socket.   
// */
//    if (ioctl(listen_sd, FIONBIO, (char*)&on) < 0)
//    {
//       WRITE_FORMAT_ERROR("ioctl() fails, due to: %s", strerror(errno));
//       close(listen_sd);
//       return RET_FAILURE_SYSTEM_API;
//    }
// // Bind
// 	int socket_len;
// 	struct sockaddr_in server_address;
// 	memset(&server_address, 0x0, sizeof(struct sockaddr_in));
// 	server_address.sin_family = AF_INET;
// 	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
// 	server_address.sin_port = htons(FILE_TRANSFER_PORT_NO);
// 	socket_len = sizeof(server_address);
// 	if (bind(listen_sd, (struct sockaddr*)&server_address, socket_len) == -1)
// 	{
// 		WRITE_FORMAT_ERROR("bind() fail, due to: %s", strerror(errno));
// 		close(listen_sd);
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// // Listen
// 	if (listen(listen_sd, MAX_CONNECTED_CLIENT) == -1)
// 	{
// 		WRITE_FORMAT_ERROR("listen() fail, due to: %s", strerror(errno));
// 		close(listen_sd);
// 		return RET_FAILURE_SYSTEM_API;
// 	}
// 	tx_socketfd = listen_sd;

// 	WRITE_FORMAT_INFO("Node[%s] is a File Sender", local_token);

// 	return ret;
// }

// unsigned short LeaderNode::start_file_transfer()
// {
// // Restrict only one file transfer process at one time in the cluster
// 	unsigned short ret = RET_SUCCESS;
// 	if (tx_listen_tid == 0)
// 	{
// 		pthread_mutex_lock(&tx_mtx);
// 		if (tx_listen_tid == 0)
// 		{
// 			ret = become_file_sender();
// 			if (CHECK_FAILURE(ret))
// 				goto OUT;

// // Create worker thread
// 			if (pthread_create(&tx_listen_tid, NULL, tx_listen_thread_handler, this))
// 			{
// 				WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting file trasnfer client, due to: %s",strerror(errno));
// 				ret = RET_FAILURE_HANDLE_THREAD;
// 				goto OUT;
// 			}
// 		}
// 		else
// 		{
// 			WRITE_FORMAT_ERROR("Another file transfer is in process[2], tx_listen_tid: %d", tx_listen_tid);
// 			ret = RET_WARN_FILE_TRANSFER_IN_PROCESS;
// 			goto OUT;
// 		}
// OUT:
// 		pthread_mutex_unlock(&tx_mtx);
// 	}
// 	else
// 	{
// 		WRITE_FORMAT_ERROR("Another file transfer is in process[1], tx_listen_tid: %d", tx_listen_tid);
// 		ret = RET_WARN_FILE_TRANSFER_IN_PROCESS;
// 	}

// 	return ret;
// }

// unsigned short LeaderNode::stop_file_transfer()
// {
// // Restrict only one file transfer process at one time in the cluster
// 	unsigned short ret = RET_SUCCESS;
// 	if (tx_listen_tid != 0)
// 	{
// 		pthread_mutex_lock(&tx_mtx);
// // Notify the worker thread it's time to exit
// 		__sync_fetch_and_add(&tx_listen_exit, 1);
// 		usleep(100000);
// // Check tx listen thread alive
// 		// bool listen_thread_alive = false;
// 		if (tx_listen_tid != 0)
// 		{
// 			int kill_ret = pthread_kill(tx_listen_tid, 0);
// 			if(kill_ret == ESRCH)
// 			{
// 				WRITE_WARN("The worker thread of tx listening did NOT exist......");
// 				ret = RET_SUCCESS;
// 			}
// 			else if(kill_ret == EINVAL)
// 			{
// 				WRITE_ERROR("The signal to the worker thread of tx listening is invalid");
// 				ret = RET_FAILURE_HANDLE_THREAD;
// 			}
// 			else
// 			{
// 				WRITE_DEBUG("The signal to the worker thread of tx listening is STILL alive");
// // Kill the thread
// 			    if (pthread_cancel(tx_listen_tid) != 0)
// 			        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of tx listening, due to: %s", strerror(errno));
// 				usleep(100000);
// 			}
// 		}

// 		WRITE_DEBUG("Wait for the worker thread of tx listening's death...");

// // Wait for tx listen thread's death
// 		pthread_join(tx_listen_tid, NULL);
// 		tx_listen_tid = 0;
// 		tx_listen_exit = 0;
// 		if (CHECK_SUCCESS(tx_listen_thread_ret))
// 		{
// 			WRITE_FORMAT_DEBUG("Wait for the worker thread[tx_listen_tid: %d] of tx listening's death Successfully !!!", tx_listen_tid);
// 		}
// 		else
// 		{
// 			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread[tx_listen_tid: %d] of tx listening's death, due to: %s", tx_listen_tid, GetErrorDescription(tx_listen_thread_ret));
// 			ret = tx_listen_thread_ret;
// 		}

// 		pthread_mutex_unlock(&tx_mtx);
// 	}
// 	else
// 	{
// 		WRITE_INFO("No file transfer is in process");
// 	}

// 	return ret;
// }

unsigned short LeaderNode::find_new_follower_pid(int& new_follower_pid)const
{
	unsigned short ret = RET_SUCCESS;
	list<int> active_process_id_list;
	ret = get_process_id_list(PROCESS_NAME, active_process_id_list);
#if 0
	int process_count;
	get_process_count(PROCESS_NAME, process_count);
	fprintf(stderr, "===== Active Process ID =====\n");
	fprintf(stderr, "Count: %d\n", process_count);
	list<int>::const_iterator iter_check = active_process_id_list.begin();
	while (iter_check != active_process_id_list.end())
	{
		fprintf(stderr, "Pid: %d\n", (int)*iter_check);
		iter_check++;
	}
	fprintf(stderr, "ClusterMap: %s\n", cluster_map.to_string());
#endif
	if (CHECK_FAILURE(ret))
		return ret;
	list<int>::const_iterator iter = active_process_id_list.begin();
	bool found;
	char local_token_tmp[LOCAL_CLUSTER_SHM_BUFSIZE];
	while (iter != active_process_id_list.end())
	{
		int pid = (int)*iter;
		memset(local_token_tmp, 0x0, sizeof(char) * LOCAL_CLUSTER_SHM_BUFSIZE);
		snprintf(local_token_tmp, LOCAL_CLUSTER_SHM_BUFSIZE, LOCAL_CLUSTER_TOKEN_SHM_FORMOAT, pid);
		string node_token_str(local_token_tmp);
		cluster_map.check_exist_by_node_token(node_token_str.c_str(), found);
		if (!found)
		{
			new_follower_pid = pid;
			return RET_SUCCESS;
		}
		iter++;
	} 
	WRITE_ERROR("The PID of the new follower is NOT found");	
	return RET_FAILURE_NOT_FOUND;
}

unsigned short LeaderNode::initialize()
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
	// tx_mtx = PTHREAD_MUTEX_INITIALIZER;
	node_channel_mtx = PTHREAD_MUTEX_INITIALIZER;
	// file_channel_mtx = PTHREAD_MUTEX_INITIALIZER;

// Try to become leader
	ret = become_leader();
	if (CHECK_FAILURE(ret))
		return ret;

	char shm_filename[DEF_SHORT_STRING_SIZE];
	snprintf(shm_filename, DEF_SHORT_STRING_SIZE, "%s-%s", LOCAL_CLUSTER_SHM_FILENAME, get_username());
	char shm_filepath[DEF_STRING_SIZE];
	snprintf(shm_filepath, DEF_STRING_SIZE, "/dev/shm/%s", shm_filename);
	if (access(shm_filepath, F_OK) == 0)
	{
		WRITE_FORMAT_WARN("LeaderNode::initialize(%s)=> The old SHM file[%s] still exists. Remove it !!!", local_token, shm_filepath);
// Remove the old token if required
		// printf("shm_unlink: %s\n", LOCAL_CLUSTER_SHM_FILENAME);
		if (shm_unlink(shm_filename) != 0)
		{
			WRITE_FORMAT_ERROR("shm_unlink() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
	}

// The /dev/shm/finance_cluster_cluster_token file is created
	// printf("shm_open: %s, create !!!\n", LOCAL_CLUSTER_SHM_FILENAME);
  	int shm_fd = shm_open(shm_filename, O_CREAT | O_EXCL | O_RDWR, 0600);
  	if (shm_fd < 0) 
  	{

    	WRITE_FORMAT_ERROR("shm_open() fails, due to: %s", strerror(errno));
    	return RET_FAILURE_SYSTEM_API;
  	}
	if (access(shm_filepath, F_OK) != 0)
	{
		WRITE_FORMAT_ERROR("The new SHM file[%s] is NOT created", shm_filepath);
    	return RET_FAILURE_SYSTEM_API;
	}
  	ftruncate(shm_fd, LOCAL_CLUSTER_SHM_BUFSIZE);

  	char *cluster_token_data = (char *)mmap(0, LOCAL_CLUSTER_SHM_BUFSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  	WRITE_FORMAT_DEBUG("cluster token, mapped address: %p, data: %s", &cluster_token_data, cluster_token_data);
  	memset(cluster_token_data, 0x0, sizeof(char) * LOCAL_CLUSTER_SHM_BUFSIZE);
  	strncpy(cluster_token_data, local_token, strlen(local_token));
  	munmap(cluster_token_data, LOCAL_CLUSTER_SHM_BUFSIZE);
  	close(shm_fd);

// Create worker thread
	if (pthread_create(&listen_tid, NULL, listen_thread_handler, this))
	{
		WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting client, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
}

unsigned short LeaderNode::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	// void* status;
	// ret = stop_file_transfer();
	// if (CHECK_FAILURE(ret))
	// {
	// 	WRITE_FORMAT_ERROR("Fails to stop file transfer, due to: %s", GetErrorDescription(ret));
	// }

// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&listen_exit, 1);
	// sleep(1);
	usleep(100000);
// Check listen thread alive
	// bool listen_thread_alive = false;
	if (listen_tid != 0)
	{
		int kill_ret = pthread_kill(listen_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of listening did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of listening is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker thread of listening is STILL alive");
			// listen_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(listen_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of listening, due to: %s", strerror(errno));
			// sleep(1);
			usleep(100000);
		}
		WRITE_DEBUG("Wait for the worker thread of listening's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'status' variable accesses the illegal address
	// pthread_join(listen_tid, &status);
	// if (status == NULL)
	// 	sWRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	// else
	// {
	// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
	// 	return listen_thread_ret;
	// }
// Wait for listen thread's death
		pthread_join(listen_tid, NULL);
		if (CHECK_SUCCESS(listen_thread_ret))
			WRITE_DEBUG("Wait for the worker thread of listening's death Successfully !!!");
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of listening's death, due to: %s", GetErrorDescription(listen_thread_ret));
			ret = listen_thread_ret;
		}
		listen_tid = 0;
	}

// No need to check return value
	// if (shm_unlink(LOCAL_CLUSTER_SHM_FILENAME) < 0)
 //  	{
 //    	WRITE_FORMAT_ERROR("shm_unlink() fails, due to: %s", strerror(errno));
 //    	// return RET_FAILURE_SYSTEM_API;
 //  	}
	char shm_filename[DEF_SHORT_STRING_SIZE];
	snprintf(shm_filename, DEF_SHORT_STRING_SIZE, "%s-%s", LOCAL_CLUSTER_SHM_FILENAME, get_username());
	char shm_filepath[DEF_STRING_SIZE];
	snprintf(shm_filepath, DEF_STRING_SIZE, "/dev/shm/%s", shm_filename);
	if (access(shm_filepath, F_OK) == 0)
	{
		int process_count;
		get_process_count(PROCESS_NAME, process_count);
// If this is the last process, then remove it
		if (process_count <= 1)
		{
			WRITE_FORMAT_WARN("LeaderNode::deinitialize(%s)=> The old SHM file[%s] still exists. Remove it !!!", local_token, shm_filepath);
// Remove the old token if required
			// printf("shm_unlink: %s\n", LOCAL_CLUSTER_SHM_FILENAME);
			if (shm_unlink(shm_filename) != 0)
			{
				WRITE_FORMAT_ERROR("shm_unlink() fails, due to: %s", strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
		}
	}
	// }
// No need
// Implemented in the thread cleanup handler function
// 	// pthread_mutex_lock(&node_channel_mtx);
// 	deque<PNODE_CHANNEL>::iterator iter = node_channel_deque.begin();
// 	while (iter != node_channel_deque.end())
// 	{
// 		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)*iter;
// 		iter++;
// 		if (node_channel != NULL)
// 		{
// 			node_channel->deinitialize();
// 			delete node_channel;
// 		}
// 	}
// 	node_channel_deque.clear();
// 	node_channel_map.clear();
// // No need
// 	// pthread_mutex_unlock(&node_channel_mtx);
	// map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
	// while (iter != node_channel_map.end())
	// {
	// 	PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
	// 	iter++;
	// 	if (node_channel != NULL)
	// 	{
	// 		node_channel->deinitialize();
	// 		delete node_channel;
	// 	}
	// }
	// node_channel_map.clear();
	node_keepalive_map.clear();

	if (socketfd != 0)
	{
		close(socketfd);
		socketfd = 0;
	}
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	return ret;
}

unsigned short LeaderNode::recv(MessageType message_type, const char* message_data, int message_size)
{
	// WRITE_FORMAT_DEBUG("Leader got the message from the Follower[%s], data: %s, size: %d", token.c_str(), message.c_str(), (int)message.length());
	typedef unsigned short (LeaderNode::*RECV_FUNC_PTR)(const char* message_data, int message_size);
	static RECV_FUNC_PTR recv_func_array[] =
	{
		NULL,
		&LeaderNode::recv_check_keepalive,
		&LeaderNode::recv_update_cluster_map,
		&LeaderNode::recv_transmit_text,
		&LeaderNode::recv_get_system_info,
		&LeaderNode::recv_get_system_monitor,
		&LeaderNode::recv_get_simulator_version,
		&LeaderNode::recv_install_simulator,
		&LeaderNode::recv_apply_fake_acspt_config,
		&LeaderNode::recv_apply_fake_usrept_config,
		&LeaderNode::recv_control_fake_acspt,
		&LeaderNode::recv_control_fake_usrept,
		&LeaderNode::recv_get_fake_acspt_state,
		&LeaderNode::recv_get_fake_acspt_detail,
		&LeaderNode::recv_request_file_transfer,
		&LeaderNode::recv_complete_file_transfer,
		&LeaderNode::recv_switch_leader,
		&LeaderNode::recv_remove_follower,
		&LeaderNode::recv_remote_sync_file
	};
	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	// fprintf(stderr, "Leader[%s] recv Message from remote: type: %d, data: %s\n", local_token, message_type, message_data.c_str());
	return (this->*(recv_func_array[message_type]))(message_data, message_size);
}

unsigned short LeaderNode::send(MessageType message_type, void* param1, void* param2, void* param3)
{
	typedef unsigned short (LeaderNode::*SEND_FUNC_PTR)(void* param1, void* param2, void* param3);
	static SEND_FUNC_PTR send_func_array[] =
	{
		NULL,
		&LeaderNode::send_check_keepalive,
		&LeaderNode::send_update_cluster_map,
		&LeaderNode::send_transmit_text,
		&LeaderNode::send_get_system_info,
		&LeaderNode::send_get_system_monitor,
		&LeaderNode::send_get_simulator_version,
		&LeaderNode::send_install_simulator,
		&LeaderNode::send_apply_fake_acspt_config,
		&LeaderNode::send_apply_fake_usrept_config,
		&LeaderNode::send_control_fake_acspt,
		&LeaderNode::send_control_fake_usrept,
		&LeaderNode::send_get_fake_acspt_state,
		&LeaderNode::send_get_fake_acspt_detail,
		&LeaderNode::send_request_file_transfer,
		&LeaderNode::send_complete_file_transfer,
		&LeaderNode::send_switch_leader,
		&LeaderNode::send_remove_follower,
		&LeaderNode::send_remote_sync_file
	};

	if (message_type < 1 || message_type >= MSG_SIZE)
	{
		WRITE_FORMAT_ERROR("Unknown Message Type: %d", message_type);
		return RET_FAILURE_INVALID_ARGUMENT;		
	}
	return (this->*(send_func_array[message_type]))(param1, param2, param3);
}

unsigned short LeaderNode::recv_check_keepalive(const char* message_data, int message_size)
{
// Message format:
// EventType | Payload: Client IP| EOD
	// const string& follower_token = message_data;
	const string& follower_token = string(message_data);
	// fprintf(stderr, "KeepAlive follower_token: %s\n", follower_token.c_str());
	pthread_mutex_lock(&node_channel_mtx);
	map<string, int>::iterator iter = node_keepalive_map.find(follower_token);
	if (iter == node_keepalive_map.end())
	{
		WRITE_FORMAT_ERROR("The Follower[%s] does NOT exist", follower_token.c_str());
		pthread_mutex_unlock(&node_channel_mtx);
		return RET_FAILURE_INTERNAL_ERROR;
	}
	int cnt = node_keepalive_map[follower_token];
	if (cnt < MAX_KEEPALIVE_CNT)
		node_keepalive_map[follower_token]++;
	// fprintf(stderr, "KeepAlive[%s] Recv to counter: %d\n", follower_token.c_str(), node_keepalive_map[follower_token]);
	pthread_mutex_unlock(&node_channel_mtx);
	// fprintf(stderr, "Recv Check-Keepalive: %s:%d\n", message_data.c_str(), node_keepalive_map[message_data]);
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_update_cluster_map(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_UPDATE_CLUSTER_MAP);}

unsigned short LeaderNode::recv_transmit_text(const char* message_data, int message_size)
{
	// printf("Recv Text: %s\n", message_data.c_str());
	printf("Recv Text: %s\n", message_data);
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_get_system_info(const char* message_data, int message_size)
{
// Message format:
// EventType | playload: (session ID[2 digits]|system info) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// size_t notify_param_size = strlen(message_data.c_str()) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifySystemInfoCfg((void*)message_data.c_str(), notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifySystemInfoCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_GET_SYSTEM_INFO, notify_cfg);
	// printf("recv_get_system_info()\n");
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_get_system_monitor(const char* message_data, int message_size)
{
// Message format:
// EventType | playload: (session ID[2 digits]|system info) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// size_t notify_param_size = strlen(message_data.c_str()) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifySystemMonitorCfg((void*)message_data.c_str(), notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifySystemMonitorCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_GET_SYSTEM_MONITOR, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_get_simulator_version(const char* message_data, int message_size)
{
// Message format:
// EventType | playload: (session ID[2 digits]|simulator_version) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// size_t notify_param_size = strlen(message_data.c_str()) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifySimulatorVersionCfg((void*)message_data.c_str(), notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifySimulatorVersionCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_GET_SIMULATOR_VERSION, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_install_simulator(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_INSTALL_SIMULATOR);}

unsigned short LeaderNode::recv_apply_fake_acspt_config(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_APPLY_FAKE_ACSPT_CONFIG);}

unsigned short LeaderNode::recv_apply_fake_usrept_config(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_APPLY_FAKE_USREPT_CONFIG);}

unsigned short LeaderNode::recv_control_fake_acspt(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_CONTROL_FAKE_ACSPT);}

unsigned short LeaderNode::recv_control_fake_usrept(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_CONTROL_FAKE_USREPT);}

unsigned short LeaderNode::recv_get_fake_acspt_state(const char* message_data, int message_size)
{
// Message format:
// EventType | playload: (session ID[2 digits]|fake acspt state) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// size_t notify_param_size = strlen(message_data.c_str()) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptStateCfg((void*)message_data.c_str(), notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptStateCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_GET_FAKE_ACSPT_STATE, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_get_fake_acspt_detail(const char* message_data, int message_size)
{
// Message format:
// EventType | playload: (session ID[2 digits]|fake acspt detail) | EOD
	assert(observer != NULL && "observer should NOT be NULL");
	// size_t notify_param_size = strlen(message_data.c_str()) + 1;
	// PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptDetailCfg((void*)message_data.c_str(), notify_param_size);
	PNOTIFY_CFG notify_cfg = new NotifyFakeAcsptDetailCfg((void*)message_data, (size_t)message_size);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	observer->notify(NOTIFY_GET_FAKE_ACSPT_DETAIL, notify_cfg);
	SAFE_RELEASE(notify_cfg)
	return RET_SUCCESS;
}

unsigned short LeaderNode::recv_request_file_transfer(const char* message_data, int message_size)
{
	// UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_REQUEST_FILE_TRANSFER);
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

unsigned short LeaderNode::recv_complete_file_transfer(const char* message_data, int message_size)
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

unsigned short LeaderNode::recv_switch_leader(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_SWITCH_LEADER);}

unsigned short LeaderNode::recv_remove_follower(const char* message_data, int message_size){UNDEFINED_MSG_EXCEPTION("Leader", "Recv", MSG_REMOVE_FOLLOWER);}

unsigned short LeaderNode::recv_remote_sync_file(const char* message_data, int message_size)
{
// Message format:
// EventType | return value | EOD
	unsigned short ret = RET_SUCCESS;
	unsigned short remote_sync_file_ret = (unsigned short)atoi(message_data);
	WRITE_FORMAT_DEBUG("Receive the return value of remote sync file: %d", remote_sync_file_ret);
	ret = observer->set(PARAM_REMOTE_SYNC_FILE_RETURN_VALUE, (void*)&remote_sync_file_ret);
	return ret;
}

unsigned short LeaderNode::send_check_keepalive(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | EOD
	unsigned short ret = RET_SUCCESS;
	bool follower_dead_found = false;
// Check if nodes in cluster are dead
	pthread_mutex_lock(&node_channel_mtx);
	// dump_node_channel_map();
	// dump_node_keepalive_map();
	map<string, int>::iterator iter = node_keepalive_map.begin();
	while (iter != node_keepalive_map.end())
	{
		string node_token = (string)iter->first;
		if ((int)iter->second == 0)
		{
			// fprintf(stderr, "KeepAlive[%s]: counter is 0!\n", node_token.c_str());
// Remove the node
			PNODE_CHANNEL node_channel = node_channel_map[node_token];
			WRITE_FORMAT_WARN("The Follower[%s] is dead", node_channel->get_remote_token());
			node_channel->deinitialize();
			node_channel_map.erase(node_token);
			node_keepalive_map.erase(iter);

			ret = cluster_map.delete_node_by_token(node_token);
			if (CHECK_FAILURE(ret))
			{
				WRITE_FORMAT_ERROR("Fail to delete the node[%s] in the map", node_token.c_str());
				pthread_mutex_unlock(&node_channel_mtx);
				return ret;
			}
			follower_dead_found = true;
		}
		else
		{
			node_keepalive_map[node_token]--;
			// fprintf(stderr, "KeepAlive[%s]: counter: %d\n", node_token.c_str(), node_keepalive_map[node_token]);
		}
		iter++;
	}
	// fprintf(stderr, "KeepAlive, After Check...\n");
	// dump_node_channel_map();
	// dump_node_keepalive_map();
	// fprintf(stderr, "KeepAlive, After Check...END\n");

	char* cluster_map_msg = NULL;
	if (follower_dead_found)
		cluster_map_msg = strdup(cluster_map.to_string());
	pthread_mutex_unlock(&node_channel_mtx);

// Update the cluster map to Followers
	if (follower_dead_found)
	{
		ret = send_string_data(MSG_UPDATE_CLUSTER_MAP, cluster_map_msg);
		free(cluster_map_msg);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("Fail to send the message of updating the cluster map, due to: %s", GetErrorDescription(ret));
			return ret;
		}
	}

	return send_string_data(MSG_CHECK_KEEPALIVE);
}

unsigned short LeaderNode::send_update_cluster_map(void* param1, void* param2, void* param3)
{
// Message format:
// EventType | cluster map string | EOD
	unsigned short ret = RET_SUCCESS;
	pthread_mutex_lock(&node_channel_mtx);
	fprintf(stderr, "LeaderNode::send_update_cluster_map %s, %ld\n", cluster_map.to_string(), strlen(cluster_map.to_string()));
	string cluster_map_msg(cluster_map.to_string());
	// fprintf(stderr, "Leader: %s\n", cluster_map.to_string());
	pthread_mutex_unlock(&node_channel_mtx);
// Update the cluster map to Followers
	if (CHECK_FAILURE(ret))
	{
		WRITE_FORMAT_ERROR("Fail to assemble the message[%d, %s], due to: %s", MSG_UPDATE_CLUSTER_MAP, cluster_map_msg.c_str(), GetErrorDescription(ret));
		return ret;
	}
	return send_string_data(MSG_UPDATE_CLUSTER_MAP, cluster_map_msg.c_str());
}

unsigned short LeaderNode::send_transmit_text(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: text data
// param2: remote token. NULL for broadcast
// Message format:
// EventType | text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	const char* text_data = (const char*)param1;
	const char* remote_token = (const char*)param2;

	return send_string_data(MSG_TRANSMIT_TEXT, text_data, remote_token);
}

unsigned short LeaderNode::send_get_system_info(void* param1, void* param2, void* param3)
{
// // Parameters:
// // param1: session id
// // param2: remote token
// // Message format:
// // EventType | session ID | EOD
// 	static const int BUF_SIZE = sizeof(int) + 1;
// 	int session_id = *(int*)param1;
// 	const char* remote_token = (const char*)param2;
// 	// fprintf(stderr, "remote_token: %s\n", remote_token);
// 	char buf[BUF_SIZE];
// 	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
// 	snprintf(buf, BUF_SIZE, "%d", session_id);
// 	return send_string_data(MSG_GET_SYSTEM_INFO, buf, remote_token);

// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_string_data(MSG_GET_SYSTEM_INFO, buf);
}

unsigned short LeaderNode::send_get_system_monitor(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_string_data(MSG_GET_SYSTEM_MONITOR, buf);
}

unsigned short LeaderNode::send_get_simulator_version(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_string_data(MSG_GET_SIMULATOR_VERSION, buf);
}

unsigned short LeaderNode::send_install_simulator(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: simulator packge filepath
// Message format:
// EventType | simulator_packge_filepath | EOD
	static const int BUF_SIZE = 256;
	const char* simulator_packge_filepath = (const char*)param1;
	char buf[BUF_SIZE + 1];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%s", simulator_packge_filepath);
	return send_string_data(MSG_INSTALL_SIMULATOR, buf);
}

unsigned short LeaderNode::send_apply_fake_acspt_config(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: fake acspt new config line list string
// Message format:
// EventType | fake_acspt_config_line_list_str | EOD
	// static const int BUF_SIZE = 256;
	const char* fake_acspt_config_line_list_str = (const char*)param1;
	// char buf[BUF_SIZE + 1];
	// memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	// snprintf(buf, BUF_SIZE, "%s", fake_acspt_config_filepath);
	return send_string_data(MSG_APPLY_FAKE_ACSPT_CONFIG, fake_acspt_config_line_list_str);
}

unsigned short LeaderNode::send_apply_fake_usrept_config(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: fake usrept new config line list string
// Message format:
// EventType | fake_acspt_config_line_list_str | EOD
	// static const int BUF_SIZE = 256;
	const char* fake_usrept_config_line_list_str = (const char*)param1;
	// char buf[BUF_SIZE + 1];
	// memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	// snprintf(buf, BUF_SIZE, "%s", fake_usrept_config_filepath);
	return send_string_data(MSG_APPLY_FAKE_USREPT_CONFIG, fake_usrept_config_line_list_str);
}

unsigned short LeaderNode::send_control_fake_acspt(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: fake access point control type
// Message format:
// EventType | fake access point control type | EOD
	// const char* fake_acspt_control_type = (const char*)param1;
	static const int BUF_SIZE = sizeof(int) + 1;
	FakeAcsptControlType fake_acspt_control_type = (FakeAcsptControlType)*(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", fake_acspt_control_type);
	return send_string_data(MSG_CONTROL_FAKE_ACSPT, buf);
}

unsigned short LeaderNode::send_control_fake_usrept(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: fake user endpoint control type
// Message format:
// EventType | fake user endpoint control type | EOD
	// const char* fake_usrept_control_type = (const char*)param1;
	static const int BUF_SIZE = sizeof(int) + 1;
	FakeUsreptControlType fake_usrept_control_type = (FakeUsreptControlType)*(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", fake_usrept_control_type);
	return send_string_data(MSG_CONTROL_FAKE_USREPT, buf);
}

unsigned short LeaderNode::send_get_fake_acspt_state(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_string_data(MSG_GET_FAKE_ACSPT_STATE, buf);
}

unsigned short LeaderNode::send_get_fake_acspt_detail(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: session id
// Message format:
// EventType | session ID | EOD
	static const int BUF_SIZE = sizeof(int) + 1;
	int session_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, BUF_SIZE, "%d", session_id);
	return send_string_data(MSG_GET_FAKE_ACSPT_DETAIL, buf);
}

unsigned short LeaderNode::send_request_file_transfer(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: a pointer to an FILE_TRANSFER_PARAM object
// Message format:
// EventType | session id | sender_token | filepath | EOD
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
	memcpy(buf, &file_transfer_param->session_id, sizeof(char) * PAYLOAD_SESSION_ID_DIGITS);
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

unsigned short LeaderNode::send_complete_file_transfer(void* param1, void* param2, void* param3)
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
// param2: remote token. NULL for broadcast
// Message format:
// EventType | session ID | EOD
			if (param1 == NULL || param2 == NULL)
			{
				WRITE_ERROR("param1/param2 should NOT be NULL");
				return RET_FAILURE_INVALID_ARGUMENT;
			}
			static const int BUF_SIZE = sizeof(int) + 1;
			int session_id = *(int*)param1;
			const char* remote_token = (const char*)param2;
			char buf[BUF_SIZE];
			memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
			snprintf(buf, BUF_SIZE, "%d", session_id);
			// fprintf(stderr, "[send_complete_file_transfer]  remote_token: %s\n", remote_token);
			ret = send_string_data(MSG_COMPLETE_FILE_TRANSFER, buf, remote_token);
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
			static const int SESSION_ID_BUF_SIZE = PAYLOAD_SESSION_ID_DIGITS + 1;
			static const int CLUSTER_ID_BUF_SIZE = PAYLOAD_CLUSTER_ID_DIGITS + 1;
			static const int RETURN_CODE_BUF_SIZE = sizeof(unsigned short) + 1;
//     // unsigned short ret = RET_SUCCESS;
// // Serialize: convert the type of session id from integer to string  
// 	char session_id_buf[SESSION_ID_BUF_SIZE];
// 	memset(session_id_buf, 0x0, sizeof(session_id_buf) / sizeof(session_id_buf[0]));
// 	snprintf(session_id_buf, SESSION_ID_BUF_SIZE, PAYLOAD_SESSION_ID_STRING_FORMAT, *(int*)param1);
// // Serialize: convert the type of cluster id from integer to string  
// 	char cluster_id_buf[CLUSTER_ID_BUF_SIZE];
// 	memset(cluster_id_buf, 0x0, sizeof(cluster_id_buf) / sizeof(cluster_id_buf[0]));
// 	snprintf(cluster_id_buf, CLUSTER_ID_BUF_SIZE, PAYLOAD_CLUSTER_ID_STRING_FORMAT, cluster_id);
// // Serialize: convert the type of return code from integer to string  
// 	char return_code_buf[RETURN_CODE_BUF_SIZE];
// 	memset(return_code_buf, 0x0, sizeof(return_code_buf) / sizeof(return_code_buf[0]));
// 	snprintf(return_code_buf, RETURN_CODE_BUF_SIZE, "%hu", *(int*)param2);

// 	string file_transfer_data = string(session_id_buf) + string(cluster_id_buf) + string(return_code_buf) + string(local_token);
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

			char* sender_token = NULL;
			observer->get(PARAM_SENDER_TOKEN, (void*)&sender_token);
			WRITE_FORMAT_DEBUG("The sender token in Leader: %s", sender_token);
// Synchronous event
// Notify to complete the file receiving...
			ret = observer->notify(NOTIFY_COMPLETE_FILE_TRANSFER);
// Notify the remote sender that the recevier has closed the resource
			ret = send_raw_data(MSG_COMPLETE_FILE_TRANSFER, buf, buf_size, sender_token);
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

unsigned short LeaderNode::send_switch_leader(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: leader candidate node id
// Message format:
// EventType | text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	static const int BUF_SIZE = sizeof(int); // + 1;
	int leader_candidate_node_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, BUF_SIZE);
	// snprintf(buf, BUF_SIZE, "%d", leader_candidate_node_id);
	memcpy(buf, &leader_candidate_node_id, BUF_SIZE);
	// printf("[LeaderNode::send_switch_leader]  leader_candidate_node_id: %d\n", leader_candidate_node_id);
	// return send_string_data(MSG_SWITCH_LEADER, buf);
	return send_raw_data(MSG_SWITCH_LEADER, buf, BUF_SIZE);
}

unsigned short LeaderNode::send_remove_follower(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: leader candidate node id
// Message format:
// EventType | text | EOD
	if (param1 == NULL)
	{
		WRITE_ERROR("param1 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	static const int BUF_SIZE = sizeof(int); // + 1;
	int follower_node_id = *(int*)param1;
	char buf[BUF_SIZE];
	memset(buf, 0x0, BUF_SIZE);
	// snprintf(buf, BUF_SIZE, "%d", leader_candidate_node_id);
	memcpy(buf, &follower_node_id, BUF_SIZE);
	// printf("[LeaderNode::send_switch_leader]  leader_candidate_node_id: %d\n", leader_candidate_node_id);
	// return send_string_data(MSG_SWITCH_LEADER, buf);
	return send_raw_data(MSG_REMOVE_FOLLOWER, buf, BUF_SIZE);
}

unsigned short LeaderNode::send_remote_sync_file(void* param1, void* param2, void* param3)
{
// Parameters:
// param1: follower node id
// param2: file path in follower
// Message format:
// EventType | text | EOD
	if (param1 == NULL || param2 == NULL)
	{
		WRITE_ERROR("param1/param2 should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	unsigned short ret = RET_SUCCESS;
	int follower_node_id = *(int*)param1;
	const char* remote_filepath = (char*)param2;
	string follower_node_token;
	pthread_mutex_lock(&node_channel_mtx);
	ret = cluster_map.get_node_token(follower_node_id, follower_node_token);
	pthread_mutex_unlock(&node_channel_mtx);
	if (ret == RET_FAILURE_NOT_FOUND)
	{
		WRITE_FORMAT_ERROR("Fail to find the node token from node id[%d]", follower_node_id);
		return ret;
	}

	// int buf_size = sizeof(int) + strlen((char*)remote_filepath) + 1;
	// char* buf = new char[buf_size];
	// if (buf == NULL)
	// 	throw bad_alloc();
	// memset(buf, 0x0, sizeof(char) * buf_size);
	// char* buf_ptr = buf;
	// memcpy(buf_ptr, param1, sizeof(int));
	// buf_ptr += sizeof(int);
	// memcpy(buf_ptr, (char*)param2, strlen((char*)remote_filepath));
	return send_raw_data(MSG_REMOTE_SYNC_FILE, remote_filepath, strlen((char*)remote_filepath) + 1, follower_node_token.c_str());
}

unsigned short LeaderNode::set(ParamType param_type, void* param1, void* param2)
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
    		// PFILE_TRANSFER_PARAM file_transfer_param = (PFILE_TRANSFER_PARAM)param1; 
    		// assert(file_transfer_param != NULL && "file_transfer_param should NOT be NULL");
			// tx_session_id = file_transfer_param->session_id;
			// if (tx_session_id == -1)
			// {
			// 	WRITE_ERROR("tx_session_id should NOT be -1");
			// 	return RET_FAILURE_SYSTEM_API;
			// }			
			// tx_filepath = strdup(file_transfer_param->filepath);
			// if (tx_filepath == NULL)
			// {
			// 	WRITE_FORMAT_ERROR("strdup() fails, due to: %s", strerror(errno));		
			// 	return RET_FAILURE_SYSTEM_API;
			// }
// // Start a thread for listening the connection request of file tranfer from the folower
//     		ret = start_file_transfer();
// 			if (CHECK_FAILURE(ret))
// 				return ret;
// Notify the folower to connect to the sender and become a receiver
			ret = send_request_file_transfer(param1);
			if (CHECK_FAILURE(ret))
				return ret;	
    	}
    	break;
//     	case PARAM_FILE_TRANSFER_DONE:
//     	{
//     		// ret = stop_file_transfer();
//     	}
//     	break;
// //     	case PARAM_NODE_FILE_TRANSFER_DONE:
// //     	{
// //     		if (param1 == NULL)
// //     		{
// //     			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
// //     			return RET_FAILURE_INVALID_ARGUMENT;
// //     		}
// //     		PNODE_FILE_TRANSFER_DONE_PARAM node_file_transfer_done_param = (PNODE_FILE_TRANSFER_DONE_PARAM)param1; 
// //     		WRITE_FORMAT_INFO("The file transferring to follower[%s] complete", node_file_transfer_done_param->node_token);
// // // Delete a file transfer channel
// //     		string follower_token(node_file_transfer_done_param->node_token);
// // 			ret = remove_file_channel(follower_token);
// //     		if (CHECK_FAILURE(ret))
// //     			WRITE_FORMAT_ERROR("Fails to remove file channel to follower[%s], due to: %s", node_file_transfer_done_param->node_token, GetErrorDescription(ret));
// //     	}
// //     	break;
    	case PARAM_ACTION_FREEZE:
    	{
    		if (action_freeze == 0)
    		{
    			WRITE_DEBUG("Freeze the action in Leader...");
				__sync_fetch_and_add(&action_freeze, 1);
				map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
				while (iter != node_channel_map.end())
				{
					PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
					iter++;
					if (node_channel != NULL)
						node_channel->freeze_action();
				}
			}
    	}
    	break;
      	case PARAM_REMOVE_FOLLOWER:
    	{
    		char* follower_token = (char*)param1;
    		WRITE_FORMAT_WARN("Remove the follower[%s] from the cluster", follower_token);
    		ret = remove_follower(follower_token);
    		if (CHECK_FAILURE(ret))
    			WRITE_FORMAT_ERROR("Fails to remove follower[%s], due to: %s", follower_token, GetErrorDescription(ret));
			PRINT("The Channel between Follower[%s] and Leader is Removed......\n", follower_token);
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

unsigned short LeaderNode::get(ParamType param_type, void* param1, void* param2)
{
    unsigned short ret = RET_SUCCESS;
    switch(param_type)
    {
		case PARAM_NODE_TOKEN_LOOKUP:
		{
    		if (param1 == NULL || param2 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1/param2 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
			int node_id = *(int*)param1;
			string node_token;
            pthread_mutex_lock(&node_channel_mtx);
            ret = cluster_map.get_node_token(node_id, node_token);
            pthread_mutex_unlock(&node_channel_mtx);
			if (CHECK_FAILURE(ret))
				return ret;
			char *node_token_tmp = strdup(node_token.c_str());
    		*((char**)param2) = node_token_tmp;
		}
		break;
    	case PARAM_CLUSTER_MAP:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		ClusterMap& cluster_map_param = *(ClusterMap*)param1;
            pthread_mutex_lock(&node_channel_mtx);
            ret = cluster_map_param.copy(cluster_map);
            pthread_mutex_unlock(&node_channel_mtx);
    	}
    	break;
		case PARAM_CLUSTER_IS_SINGLE:
		{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
			pthread_mutex_lock(&node_channel_mtx);
            *(bool*)param1 = cluster_map.is_single();
			pthread_mutex_unlock(&node_channel_mtx);
		}
		break;
    	case PARAM_CLUSTER_NODE_AMOUNT:
    	{
    		if (param1 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		int& cluster_node_amount_param = *(int*)param1;

         cluster_node_amount_param = cluster_map.size();
         pthread_mutex_unlock(&node_channel_mtx);
    	}
    	break;
    	case PARAM_CLUSTER_TOKEN2ID:
    	{
    		if (param1 == NULL || param2 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1/param2 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		string& cluster_node_token_param = *(string*)param1;
    		int& cluster_node_id_param = *(int*)param2;
         pthread_mutex_lock(&node_channel_mtx);
         ret = cluster_map.get_node_id(cluster_node_token_param, cluster_node_id_param);
         pthread_mutex_unlock(&node_channel_mtx);
    	}
    	break;
    	case PARAM_CLUSTER_ID2TOKEN:
    	{
    		if (param1 == NULL || param2 == NULL)
    		{
    			WRITE_FORMAT_ERROR("The param1/param2 of the param_type[%d] should NOT be NULL", param_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		int& cluster_node_id_param = *(int*)param1;
    		string& cluster_node_token_param = *(string*)param2;
         pthread_mutex_lock(&node_channel_mtx);
         ret = cluster_map.get_node_token(cluster_node_id_param, cluster_node_token_param);
         pthread_mutex_unlock(&node_channel_mtx);
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

unsigned short LeaderNode::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
      	case NOTIFY_NODE_DIE:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		ret = notify_thread->add_event(notify_cfg);
    	}
    	break;
    	// case NOTIFY_SEND_FILE_DONE:
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

unsigned short LeaderNode::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
      case NOTIFY_NODE_DIE:
    	{
    		// string follower_token((char*)notify_cfg->get_notify_param());
    		string follower_token(((PNOTIFY_NODE_DIE_CFG)notify_cfg)->get_remote_token());
    		WRITE_FORMAT_WARN("The follower[%s] dies, remove the node from the cluster", follower_token.c_str());
    		ret = remove_follower(follower_token);
    		if (CHECK_FAILURE(ret))
    			WRITE_FORMAT_ERROR("Fails to remove follower[%s], due to: %s", follower_token.c_str(), GetErrorDescription(ret));
			WRITE_EVT_RECORDER(OperateNodeEventCfg, EVENT_OPERATE_NODE_LEAVE, LEADER, follower_token.c_str());
			PRINT("The Channel between Follower[%s] and Leader is Removed......\n", follower_token.c_str());
    	}
    	break;
   //    case NOTIFY_SEND_FILE_DONE:
   //  	{
   //  		// string follower_token((char*)notify_cfg->get_notify_param());
   //  		string follower_token(((PNOTIFY_SEND_FILE_DONE_CFG)notify_cfg)->get_remote_token());
   //  		WRITE_FORMAT_WARN("Send file to the follwer[%s] completely, remove the file channel to the follower", follower_token.c_str());
			// ret = remove_file_channel(follower_token);
   //  		if (CHECK_FAILURE(ret))
   //  			WRITE_FORMAT_ERROR("Fails to remove file channel to follower[%s], due to: %s", follower_token.c_str(), GetErrorDescription(ret));
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

void LeaderNode::dump_node_channel_map()const
{
	map<std::string, PNODE_CHANNEL>::const_iterator iter = node_channel_map.begin();
	while (iter != node_channel_map.end())
	{
		string node_token = (string)(iter->first);
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
		// fprintf(stderr, "%s %p\n", node_token.c_str(), (void*)node_channel);
		iter++;
	}
}

void LeaderNode::dump_node_keepalive_map()const
{
	map<std::string, int>::const_iterator iter = node_keepalive_map.begin();
	while (iter != node_keepalive_map.end())
	{
		string node_token = (string)(iter->first);
		int keepalive_counter = (int)(iter->second);
		fprintf(stderr, "%s %d\n", node_token.c_str(), keepalive_counter);
		iter++;
	}
}

void* LeaderNode::listen_thread_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->listen_thread_ret))
	{
		pthread_cleanup_push(listen_thread_cleanup_handler, pthis);
		pthis->listen_thread_ret = pthis->listen_thread_handler_internal();
		pthread_cleanup_pop(1);
	}

// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->listen_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->listen_thread_ret)));
	pthread_exit(NULL);
}

unsigned short LeaderNode::listen_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is running", listen_thread_tag);
	unsigned short ret = RET_SUCCESS;

	char *client_token = NULL;
	while (listen_exit == 0)
	{
		struct timeval tv;
		fd_set sock_set;
		tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&sock_set);
		FD_SET(socketfd, &sock_set);
		int res = select(socketfd + 1, &sock_set, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR)
		{
			WRITE_FORMAT_ERROR("[%s] select() fails, due to: %s", listen_thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			usleep(100000);
			continue;
		}	
// http://www.cas.mcmaster.ca/~qiao/courses/cs3mh3/tutorials/socket.html
		int client_socketfd = 0;
// Follower connects to Leader
		if (local_cluster)
		{
			struct sockaddr_un client_addr;
			// struct stat client_statbuf;
			socklen_t client_addr_len = sizeof(client_addr);
			// fprintf(stderr, "client_addr_len: %d\n", client_addr_len);
			client_socketfd = accept(socketfd, (struct sockaddr*)&client_addr, (socklen_t*)&client_addr_len);
			if (client_socketfd < 0)
			{
				WRITE_FORMAT_ERROR("[%s] accept() fails, due to: %s", listen_thread_tag, strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
// https://www.itread01.com/content/1549028184.html
// I don't know why 'sun_path' is empty
			// fprintf(stderr, "sun_family: %d, sun_path: %s\n", client_addr.sun_family, client_addr.sun_path);
			// client_addr.sun_path[client_addr_len - offsetof(struct sockaddr_un, sun_path) len of pathname ] = '\0'; /* null terminate */
			// client_token = strdup(client_addr.sun_path);
			int new_follower_pid;
			ret = find_new_follower_pid(new_follower_pid);
			if (CHECK_FAILURE(ret))
				return ret;
			char local_token_tmp[LOCAL_CLUSTER_SHM_BUFSIZE];
			snprintf(local_token_tmp, LOCAL_CLUSTER_SHM_BUFSIZE, LOCAL_CLUSTER_TOKEN_SHM_FORMOAT, new_follower_pid);
			client_token = strdup(local_token_tmp);
			WRITE_FORMAT_INFO("[%s] Follower[%s] request connecting to the Leader", listen_thread_tag, client_token);
			// PRINT("Follower[%s] connects to the Leader\n", client_token);
		}
		else
		{
			struct sockaddr_in client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			client_socketfd = accept(socketfd, (struct sockaddr*)&client_addr, (socklen_t*)&client_addr_len);
			if (client_socketfd < 0)
			{
				WRITE_FORMAT_ERROR("[%s] accept() fails, due to: %s", listen_thread_tag, strerror(errno));
				return RET_FAILURE_SYSTEM_API;
			}
// deal with both IPv4 and IPv6:
			// struct sockaddr_in *client_s = (struct sockaddr_in *)&client_addr;
			// PRINT("family: %d, port: %d\n", s->sin_family, ntohs(s->sin_port));
	//		port = ntohs(s->sin_port);
			client_token = (char*)malloc(INET_ADDRSTRLEN + 1);
			if (client_token == NULL)
				throw bad_alloc();
			inet_ntop(AF_INET, &client_addr.sin_addr, client_token, INET_ADDRSTRLEN + 1);
			WRITE_FORMAT_INFO("[%s] Follower[%s] request connecting to the Leader", listen_thread_tag, client_token);
			// PRINT("Follower[%s] connects to the Leader\n", client_token);
		}
// Initialize a channel for data transfer between follower
		PNODE_CHANNEL node_channel = new NodeChannel(this);
		if (node_channel == NULL)
		{
			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: node_channel", listen_thread_tag);
			// pthread_mutex_unlock(&node_channel_mtx);
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}

		WRITE_FORMAT_INFO("[%s] Initialize the Channel between Follower[%s] and Leader", listen_thread_tag, client_token);
		ret = node_channel->initialize(client_socketfd, local_token, client_token);
		if (CHECK_FAILURE(ret))
		{
			// pthread_mutex_unlock(&node_channel_mtx);
			// return ret;
			goto OUT;
		}
// Add a channel of the new follower
		pthread_mutex_lock(&node_channel_mtx);
		// node_channel_deque.push_back(node_channel);
		// dump_node_channel_map();
		// dump_node_keepalive_map();
		node_channel_map[client_token] = node_channel;
		node_keepalive_map[client_token] = MAX_KEEPALIVE_CNT;
		// dump_node_channel_map();
		// dump_node_keepalive_map();
// Update the cluster map in Leader
		ret = cluster_map.add_node(++cluster_node_cnt, client_token);
		if (CHECK_FAILURE(ret))
		{
			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: node_channel", listen_thread_tag);
			pthread_mutex_unlock(&node_channel_mtx);
			// return ret;
			goto OUT;
		}
		string cluster_map_msg(cluster_map.to_string());
		// fprintf(stderr, "New Cluster Map: %s\n", cluster_map_msg.c_str());
		pthread_mutex_unlock(&node_channel_mtx);
		PRINT("The Channel between Follower[%s] and Leader is Established......\n", client_token);
		WRITE_EVT_RECORDER(OperateNodeEventCfg, EVENT_OPERATE_NODE_JOIN, LEADER, client_token);
// Update the cluster map to Followers
		// fprintf(stderr, "LeaderNode::listen_thread_handler_internal %s, %d\n", cluster_map.to_string(), strlen(cluster_map.to_string()));
		ret = send_string_data(MSG_UPDATE_CLUSTER_MAP, cluster_map_msg.c_str());
		if (CHECK_FAILURE(ret))
		{
			// return ret;
			goto OUT;
		}
		WRITE_FORMAT_INFO("[%s] Follower[%s] connects to the Leader...... successfully !!!", listen_thread_tag, client_token);
	}
OUT:
	if (client_token != NULL)
	{
		free(client_token);
		client_token = NULL;
	}
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", listen_thread_tag);
	return ret;
}

void LeaderNode::listen_thread_cleanup_handler(void* pvoid)
{
	LeaderNode* pthis = (LeaderNode*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->listen_thread_cleanup_handler_internal();
}

void LeaderNode::listen_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the listen thread......", listen_thread_tag);
	map<std::string, PNODE_CHANNEL>::iterator iter = node_channel_map.begin();
	while (iter != node_channel_map.end())
	{
		PNODE_CHANNEL node_channel = (PNODE_CHANNEL)(iter->second);
		iter++;
		if (node_channel != NULL)
		{
			node_channel->deinitialize();
			delete node_channel;
			node_channel = NULL;
		}
	}
	node_channel_map.clear();
}

// void* LeaderNode::tx_listen_thread_handler(void* pvoid)
// {
// 	LeaderNode* pthis = (LeaderNode*)pvoid;
// 	if (pthis == NULL)
// 		throw std::invalid_argument("pvoid should NOT be NULL");

// // https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
//     if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
//     {
//     	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
//     	pthis->tx_listen_thread_ret = RET_FAILURE_SYSTEM_API;
//     }

// // PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
//     // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
//     // thread receive cancel message.
//     if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
//     {
//     	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
//     	pthis->tx_listen_thread_ret = RET_FAILURE_SYSTEM_API;
// 	}

// 	if (CHECK_SUCCESS(pthis->tx_listen_thread_ret))
// 	{
// 		pthread_cleanup_push(tx_listen_thread_cleanup_handler, pthis);
// 		pthis->tx_listen_thread_ret = pthis->tx_listen_thread_handler_internal();
// 		pthread_cleanup_pop(1);
// 	}

// // No need to send data to pthread_join
// 	// pthread_exit((CHECK_SUCCESS(pthis->listen_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->listen_thread_ret)));
// 	pthread_exit(NULL);
// }

// unsigned short LeaderNode::tx_listen_thread_handler_internal()
// {
// 	WRITE_FORMAT_INFO("[%s] The worker thread of file transfer listening socket is running", tx_listen_thread_tag);
// 	unsigned short ret = RET_SUCCESS;

// 	struct sockaddr client_addr;
// 	socklen_t client_addr_len = sizeof(client_addr);
// 	while (tx_listen_exit == 0)
// 	{
// 		struct timeval tv;
// 		fd_set sock_set;
// 		tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
// 		tv.tv_usec = 0;
// 		FD_ZERO(&sock_set);
// 		FD_SET(tx_socketfd, &sock_set);
// 		int res = select(tx_socketfd + 1, &sock_set, NULL, NULL, &tv);
// 		if (res < 0 && errno != EINTR)
// 		{
// 			WRITE_FORMAT_ERROR("[%s] select() fails, due to: %s",tx_listen_thread_tag, strerror(errno));
// 			return RET_FAILURE_SYSTEM_API;
// 		}
// 		else if (res == 0)
// 		{
// 			// WRITE_DEBUG("Accept timeout");
// 			usleep(100000);
// 			continue;
// 		}		
// // Follower connect to Leader
// 		int client_socketfd = accept(tx_socketfd, &client_addr, (socklen_t*)&client_addr_len);
// 		if (client_socketfd < 0)
// 		{
// 			WRITE_FORMAT_ERROR("[%s] accept() fails, due to: %s", tx_listen_thread_tag, strerror(errno));
// 			return RET_FAILURE_SYSTEM_API;
// 		}
// 		// deal with both IPv4 and IPv6:
// 		struct sockaddr_in *client_s = (struct sockaddr_in *)&client_addr;
// 		// PRINT("family: %d, port: %d\n", s->sin_family, ntohs(s->sin_port));
// //		port = ntohs(s->sin_port);
// 		char client_token[INET_ADDRSTRLEN + 1];
// 		inet_ntop(AF_INET, &client_s->sin_addr, client_token, sizeof(client_token));
// 		WRITE_FORMAT_INFO("[%s] Receiver[%s] request connecting to the Sender", tx_listen_thread_tag, client_token);
// 		// PRINT("Follower[%s] connects to the Leader\n", token);
// // Initialize a channel for file transfer between follower
// 		PFILE_CHANNEL file_channel = new FileChannel(this);
// 		if (file_channel == NULL)
// 		{
// 			WRITE_FORMAT_ERROR("[%s] Fail to allocate memory: file_channel", tx_listen_thread_tag);
// 			// pthread_mutex_unlock(&node_channel_mtx);
// 			return RET_FAILURE_INSUFFICIENT_MEMORY;
// 		}
// 		WRITE_FORMAT_INFO("[%s] Initialize the File Channel between Receiver[%s] and Sender", tx_listen_thread_tag, client_token);
// 		ret = file_channel->initialize(tx_filepath, local_token, client_token, client_socketfd, true, tx_session_id);
// 		if (CHECK_FAILURE(ret))
// 			return ret;
// 		sleep(3);
// // Start to transfer the file
// 		WRITE_FORMAT_DEBUG("[%s] Notify Receiver[%s] to start to transfer data...", tx_listen_thread_tag, client_token);
// 		ret = file_channel->request_transfer();
// 		if (CHECK_FAILURE(ret))
// 			return ret;

// // Add a channel for file transfer
// 		pthread_mutex_lock(&file_channel_mtx);
// 		file_channel_map[client_token] = file_channel;
// 		pthread_mutex_unlock(&file_channel_mtx);
// 		PRINT("[%s] The File Channel between Receiver[%s] and Sender is Established......\n", tx_listen_thread_tag, client_token);
// 		WRITE_FORMAT_INFO("[%s] Follower File Channel[%s] connects to the Leader...... successfully !!!", tx_listen_thread_tag, client_token);
// 	}

// 	WRITE_FORMAT_INFO("[%s] The worker thread of file trasnfer listening socket is dead", tx_listen_thread_tag);
// 	return ret;
// }

// void LeaderNode::tx_listen_thread_cleanup_handler(void* pvoid)
// {
// 	LeaderNode* pthis = (LeaderNode*)pvoid;
// 	if (pthis == NULL)
// 		throw std::invalid_argument("pvoid should NOT be NULL");
// 	pthis->tx_listen_thread_cleanup_handler_internal();
// }

// void LeaderNode::tx_listen_thread_cleanup_handler_internal()
// {
// 	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the tx listen thread......", tx_listen_thread_tag);
// 	pthread_mutex_lock(&file_channel_mtx);
// 	map<std::string, PFILE_CHANNEL>::iterator iter = file_channel_map.begin();
// 	while (iter != file_channel_map.end())
// 	{
// 		PFILE_CHANNEL file_channel = (PFILE_CHANNEL)(iter->second);
// 		iter++;
// 		if (file_channel != NULL)
// 		{
// 			file_channel->deinitialize();
// 			delete file_channel;
// 			file_channel = NULL;
// 		}
// 	}
// 	file_channel_map.clear();
// 	pthread_mutex_unlock(&file_channel_mtx);
// 	if (tx_socketfd != 0)
// 	{
// 		close(tx_socketfd);
// 		tx_socketfd = 0;
// 	}
// }
