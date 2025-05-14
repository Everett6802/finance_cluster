#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <string>
#include <stdexcept>
#include "file_channel.h"


using namespace std;

const char* FileChannel::thread_tag = "File Channel Thread";
const int FileChannel::WAIT_DATA_TIMEOUT = 60 * 1000;
const long FileChannel::MAX_BUF_SIZE = 1024 * 100;

FileChannel::FileChannel(PIFILE_TX file_tx) :
	exit(0),
//	node_token(NULL),
	is_sender(false),
	send_tid(0),
	recv_tid(0),
	tx_filepath(NULL),
	tx_socket(0),
	tx_session_id(-1),
	tx_fp(NULL),   	
	tx_buf(NULL),
	send_thread_ret(RET_SUCCESS),
	recv_thread_ret(RET_SUCCESS),
	send_msg_trigger(false)
{
	IMPLEMENT_MSG_DUMPER()
	IMPLEMENT_EVT_RECORDER()
	observer = file_tx;
	assert(observer != NULL && "observer should NOT be NULL");
}

FileChannel::~FileChannel()
{
	RELEASE_EVT_RECORDER()
	RELEASE_MSG_DUMPER()
}

unsigned short FileChannel::initialize(const char* filepath, const char* channel_token, const char* channel_remote_token, int channel_socket, bool sender, bool session_id)
{
	if (filepath == NULL)
	{
		WRITE_ERROR("filepath should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}	
	if (channel_token == NULL)
	{
		WRITE_ERROR("channel_token should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	if (channel_remote_token == NULL)
	{
		WRITE_ERROR("channel_remote_token should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	is_sender = sender;

	tx_filepath = strdup(filepath);
	node_token = string(channel_token);
	remote_token = string(channel_remote_token);
	tx_socket = channel_socket;
	tx_session_id = session_id;

	mtx_buffer = PTHREAD_MUTEX_INITIALIZER;
	cond_buffer = PTHREAD_COND_INITIALIZER;

// Create a worker thread to access data...
    // if (pthread_create(&send_tid, NULL, send_thread_handler, this) != 0)
    // {
    // 	WRITE_FORMAT_ERROR("Fail to create a worker thread of sending message, due to: %s",strerror(errno));
    // 	return RET_FAILURE_HANDLE_THREAD;
    // }

	bool file_exist = check_file_exist(tx_filepath);
	if (is_sender)
	{
		if (!file_exist)
		{
			WRITE_FORMAT_WARN("The file[%s] does NOT exist", filepath);
			return RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND;
		}
	}
	else
	{
	    if (file_exist)
	    {
	    	int ret = remove(filepath);
	    	if (ret != 0)
	    	{
	    		WRITE_FORMAT_ERROR("remove() fails, due to: %s", strerror(errno));
				return RET_FAILURE_SYSTEM_API;
	    	}
	    }
	    else
	    {
		    char folderpath[256];  // Adjust the size as needed
		    strcpy(folderpath, filepath);
		    char *last_slash = strrchr(folderpath, '/');
		    if (last_slash == NULL) 
		    {
			    WRITE_FORMAT_ERROR("Incorrect filepath: %s", filepath);
			    return RET_FAILURE_INCORRECT_PATH;
		    }
		    *last_slash = '\0';
		    unsigned short ret = create_folder_recursive(folderpath);
		    if (CHECK_FAILURE(ret))
		    	return ret;
	    }
		if (pthread_create(&recv_tid, NULL, recv_thread_handler, this) != 0)
		{
		    WRITE_FORMAT_ERROR("Fail to create a worker thread of receiving message, due to: %s",strerror(errno));
		    return RET_FAILURE_HANDLE_THREAD;
		}
	}

	return RET_SUCCESS;
}

unsigned short FileChannel::deinitialize()
{
	WRITE_DEBUG("Release resource in FileChannel......");
	unsigned short ret = RET_SUCCESS;
	// int kill_ret;
	int old_exit = __sync_fetch_and_add(&exit, 1);
	// sleep(1);
	if (old_exit == 0)
		usleep(100000);

	// bool thread_alive = false;
	// bool send_thread_alive = false;
	if (is_sender)
	{
// Check send thread alive
		if (send_tid != 0)
		{
			int kill_ret = pthread_kill(send_tid, 0);
			if(kill_ret == ESRCH)
			{
				WRITE_WARN("The worker thread of sending file did NOT exist......");
				ret = RET_SUCCESS;
				// goto OUT;
			}
			else if(kill_ret == EINVAL)
			{
				WRITE_ERROR("The signal to the worker thread of sending file is invalid");
				ret = RET_FAILURE_HANDLE_THREAD;
				// goto OUT;
			}
			else
			{
				WRITE_DEBUG("The signal to the worker thread of sending file is STILL alive");
// Kill the thread
			    if (pthread_cancel(send_tid) != 0)
			        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of sending file, due to: %s", strerror(errno));
				usleep(100000);
// Wait for send thread's death
				WRITE_DEBUG("Wait for the worker thread of sending file's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'send_status' variable accesses the illegal address
				// void* send_status;
				// pthread_join(send_tid, &send_status);
				// if (send_status == NULL)
				// 	WRITE_DEBUG("Wait for the worker thread of sending file's death Successfully !!!");
				// else
				// {
				// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending file's death, due to: %s", (char*)send_status);
				// 	ret = send_thread_ret;
				// }
				pthread_join(send_tid, NULL);
				if (CHECK_SUCCESS(send_thread_ret))
					WRITE_DEBUG("Wait for the worker thread of sending file's death Successfully !!!");
				else
				{
					WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending file's death, due to: %s", GetErrorDescription(send_thread_ret));
					ret = send_thread_ret;
				}
			}
			send_tid = 0;
		}
	}
	else
	{
// Check recv thread alive
	// bool recv_thread_alive = false;
		if (recv_tid != 0)
		{
			int kill_ret = pthread_kill(recv_tid, 0);
			if(kill_ret == ESRCH)
			{
				WRITE_WARN("The worker thread of receiving file did NOT exist......");
				ret = RET_SUCCESS;
				// goto OUT;
			}
			else if(kill_ret == EINVAL)
			{
				WRITE_ERROR("The signal to the worker thread of receiving file is invalid");
				ret = RET_FAILURE_HANDLE_THREAD;
				// goto OUT;
			}		
			else
			{
				WRITE_DEBUG("The signal to the worker thread of receiving file is STILL alive");
			    if (pthread_cancel(recv_tid) != 0)
			        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of receving file, due to: %s", strerror(errno));
				usleep(100000);
// Wait for recv thread's death
				WRITE_DEBUG("Wait for the worker thread of receiving file's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'recv_status' variable accesses the illegal address
				// void* recv_status;
				// pthread_join(recv_tid, &recv_status);
				// if (recv_status == NULL)
				// 	WRITE_DEBUG("Wait for the worker thread of receiving file's death Successfully !!!");
				// else
				// {
				// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving file's death, due to: %s", (char*)recv_status);
				// 	ret = recv_thread_ret;
				// }
				pthread_join(recv_tid, NULL);
				if (CHECK_SUCCESS(recv_thread_ret))
					WRITE_DEBUG("Wait for the worker thread of receiving file's death Successfully !!!");
				else
				{
					WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving file's death, due to: %s", GetErrorDescription(recv_thread_ret));
					ret = recv_thread_ret;
				}
			}
			recv_tid = 0;
		}
	}

	if (tx_buf != NULL)
	{
		delete[] tx_buf;
		tx_buf = NULL;
	}
	if (tx_fp != NULL)
	{
		fclose(tx_fp);
		tx_fp = NULL;
	}
	if (tx_filepath != NULL)
	{
		free(tx_filepath);
		tx_filepath = NULL;
	}
	if (tx_socket != 0)
	{
		close(tx_socket);
		tx_socket = 0;
	}
	if (observer != NULL)
		observer = NULL;
	return ret;
}

void FileChannel::notify_exit()
{
	__sync_fetch_and_add(&exit, 1);
// Notify the send thread to exit
	pthread_mutex_lock(&mtx_buffer);
	if (!send_msg_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		send_msg_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);
}

const char* FileChannel::get_token()const
{
	return node_token.c_str();
}

const char* FileChannel::get_remote_token()const
{
	return remote_token.c_str();
}

unsigned short FileChannel::request_transfer()
{
    if (!is_sender)
    {
    	WRITE_FORMAT_ERROR("Incorrect operation: Node[%s] is NOT a sender", node_token.c_str());
    	return RET_FAILURE_INCORRECT_OPERATION;
    }
// Create a worker thread to access data...
    if (pthread_create(&send_tid, NULL, send_thread_handler, this) != 0)
    {
    	WRITE_FORMAT_ERROR("Fail to create a worker thread of sending message, due to: %s", strerror(errno));
    	return RET_FAILURE_HANDLE_THREAD;
    }

	return RET_SUCCESS;
}

// unsigned short FileChannel::complete_transfer()
// {
//     if (is_sender)
//     {
//     	WRITE_FORMAT_ERROR("Incorrect operation: Node[%s] is NOT a receiver", node_token);
//     	return RET_FAILURE_INCORRECT_OPERATION;
//     }

//     // if (pthread_create(&send_tid, NULL, send_thread_handler, this) != 0)
//     // {
//     // 	WRITE_FORMAT_ERROR("Fail to create a worker thread of sending message, due to: %s",strerror(errno));
//     // 	return RET_FAILURE_HANDLE_THREAD;
//     // }

// 	return RET_SUCCESS;
// }

void* FileChannel::send_thread_handler(void* pvoid)
{
	FileChannel* pthis = (FileChannel*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->send_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->send_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	pthread_cleanup_push(send_thread_cleanup_handler, pthis);
	pthis->send_thread_ret = pthis->send_thread_handler_internal();
	pthread_cleanup_pop(1);		

	pthread_exit((CHECK_SUCCESS(pthis->send_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->send_thread_ret)));
}

unsigned short FileChannel::send_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of sending message is running", thread_tag);
	unsigned short ret = RET_SUCCESS;
	assert(tx_filepath != NULL && "tx_filepath should NOT be NULL");
	assert(tx_buf == NULL && "tx_buf should be NULL");

	tx_fp = fopen(tx_filepath, "rb");
	if (tx_fp == NULL)
	{
    	WRITE_FORMAT_ERROR("fopen() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
   	}
   	else
   		WRITE_FORMAT_DEBUG("Open the file for being transferred: %s", tx_filepath);
   	tx_buf = new char[MAX_BUF_SIZE];
   	if (tx_buf == NULL)
   	{
    	WRITE_ERROR("Fail to allocate memory: tx_buf");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
   	}
   	size_t read_bytes;
   	size_t write_bytes;
   	int start_pos = 0;
	size_t write_to_byte;
	WRITE_FORMAT_DEBUG("Start to read data from the file for the Node[%s]...", remote_token.c_str());
   	int read_cnt = 0;
   	int send_cnt = 0;
   	while (exit == 0 && !feof(tx_fp))
   	{
// Read data from the file
   		read_bytes = fread(tx_buf, sizeof(char), MAX_BUF_SIZE, tx_fp);
		if (read_bytes < 0)
		{
	    	WRITE_FORMAT_ERROR("Error occurs while reading file for the Node[%s], due to: %s", remote_token.c_str(), strerror(errno));
			ret = RET_FAILURE_SYSTEM_API;
			goto OUT;
	   	}
	   	else
	   		WRITE_FORMAT_DEBUG("Read %d bytes from the file for the Node[%s]... %d", read_bytes, remote_token.c_str(), ++read_cnt);
// Send data to the remote
		start_pos = 0;
		write_to_byte = read_bytes;
		while (write_to_byte > 0)
		{
			write_bytes = send(tx_socket, &tx_buf[start_pos], write_to_byte, 0);
			if (write_bytes < 0)
			{
				WRITE_FORMAT_ERROR("Error occur while writing data to the Node[%s], due to: %s", remote_token.c_str(), strerror(errno));
				ret = RET_FAILURE_SYSTEM_API;
				goto OUT;
			}
		   	else
		   		WRITE_FORMAT_DEBUG("Send %d bytes to the Node[%s]... %d", write_bytes, remote_token.c_str(), ++send_cnt);
			start_pos += write_bytes;
			write_to_byte -= write_bytes;
		}
		usleep(10000);
   	}

OUT:
	WRITE_FORMAT_INFO("[%s] The worker thread of sending file is done", thread_tag);

	assert(observer != NULL && "observer should NOT be NULL");
// // // Notify the follower 
// // 	observer->send(MSG_COMPLETE_FILE_TRANSFER, (void*)&tx_session_id, (void*)remote_token.c_str());
// // // Close the local file transfer channel
// // 	NodeFileTransferDoneParam node_file_transfer_done_param;
// // 	snprintf(node_file_transfer_done_param.node_token, DEF_VERY_SHORT_STRING_SIZE, "%s", remote_token.c_str());
// // 	observer->set(PARAM_NODE_FILE_TRANSFER_DONE, (void*)&node_file_transfer_done_param);
// // Close the parent to close the local file transfer channel
// 	const int BUF_SIZE = sizeof(int);
// 	char buf[BUF_SIZE];
// 	snprintf(buf, BUF_SIZE, "%d", tx_session_id);
// 	string notify_param = string(buf) + remote_token;
// 	size_t notify_param_size = strlen(notify_param.c_str()) + 1;  // strlen(remote_token.c_str()) + 1;
// 	PNOTIFY_CFG notify_cfg = new NotifySendFileDoneCfg(notify_param.c_str(), notify_param_size);
// 	if (notify_cfg == NULL)
// 		throw bad_alloc();
	PNOTIFY_SEND_FILE_DONE_CFG notify_send_file_done_cfg = NULL;
	NotifySendFileDoneCfg::generate_obj(&notify_send_file_done_cfg, tx_session_id, remote_token.c_str());
	// fprintf(stderr, "[send_thread_handler_internal]  tx_session_id: %d, remote_token: %s\n", tx_session_id, remote_token.c_str());
	// fprintf(stderr, "[send_thread_handler_internal] obj  tx_session_id: %d, remote_token: %s\n", notify_send_file_done_cfg->get_session_id(), notify_send_file_done_cfg->get_remote_token());
	PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_send_file_done_cfg;
// Asynchronous event
	observer->notify(NOTIFY_SEND_FILE_DONE, notify_cfg);
	SAFE_RELEASE(notify_cfg);

	WRITE_FORMAT_INFO("[%s] The worker thread of sending file is dead", thread_tag);	
	return ret;
}

void FileChannel::send_thread_cleanup_handler(void* pvoid)
{
	FileChannel* pthis = (FileChannel*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->send_thread_cleanup_handler_internal();
}

void FileChannel::send_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the send thread......", thread_tag);
	if (tx_buf != NULL)
	{
		delete[] tx_buf;
		tx_buf = NULL;
	}
	if (tx_fp != NULL)
	{
		fclose(tx_fp);
		tx_fp = NULL;
	}
	// return RET_SUCCESS;
}

void* FileChannel::recv_thread_handler(void* pvoid)
{
	FileChannel* pthis = (FileChannel*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->recv_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->recv_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->recv_thread_ret))
	{
		pthis->recv_thread_ret = pthis->recv_thread_handler_internal();
	}

	pthread_exit(NULL);
}

unsigned short FileChannel::recv_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is running", thread_tag, node_token.c_str());
	unsigned short ret = RET_SUCCESS;
	assert(tx_filepath != NULL && "tx_filepath should be NOT NULL");
	assert(tx_buf == NULL && "tx_buf should be NULL");
	tx_fp = fopen(tx_filepath, "wb");
	if (tx_fp == NULL)
	{
    	WRITE_FORMAT_ERROR("fopen() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
   	}
   	tx_buf = new char[MAX_BUF_SIZE];
   	if (tx_buf == NULL)
   	{
    	WRITE_ERROR("Fail to allocate memory: tx_buf");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
   	}

	// fprintf(stderr, "Recv00: Enter RECV thread...\n");
	while(exit == 0)
	{
		struct pollfd pfd;
		pfd.fd = tx_socket;
		pfd.events = POLLIN | POLLHUP | POLLRDNORM;
	    pfd.revents = 0;
		int ret = poll(&pfd, 1, WAIT_DATA_TIMEOUT); // call poll with a timeout of 3000 ms
// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_STRING_SIZE, "poll() return value: %d", ret);
		if (ret < 0)
		{
			WRITE_FORMAT_ERROR("[%s] poll() fail, due to %s", thread_tag, strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (ret > 0) // if result > 0, this means that there is either data available on the socket, or the socket has been closed
		{
		   	size_t read_bytes;
		   	size_t write_bytes;
		 //   	int start_pos = 0;
			// size_t write_to_byte = read_bytes;
			// Read the data from the remote
			memset(tx_buf, 0x0, sizeof(char) * MAX_BUF_SIZE);
			read_bytes = recv(tx_socket, tx_buf, sizeof(char) * MAX_BUF_SIZE, /*MSG_PEEK |*/ MSG_DONTWAIT);			
			if (read_bytes == 0) // if recv() returns zero, that means the connection has been closed
			{
// Allocate the nofity event parameter
				// const char* notify_param = remote_token.c_str();
				size_t notify_param_size = strlen(remote_token.c_str()) + 1;
				PNOTIFY_CFG notify_cfg = new NotifyFileTransferAbortCfg(remote_token.c_str(), notify_param_size);
				if (notify_cfg == NULL)
					throw bad_alloc();
// Notify the event
				WRITE_FORMAT_WARN("[%s] The connection of file transfer is closed......", thread_tag);
				observer->notify(NOTIFY_ABORT_FILE_TRANSFER, notify_cfg);
				ret = RET_FAILURE_CONNECTION_CLOSE;
				goto OUT;
			}
			else
			{
				WRITE_FORMAT_DEBUG("Recv %d bytes from the Node[%s]", read_bytes, remote_token.c_str());
// Write data from into file
// When using fwrite() for record output, set size to 1 and count to 
// the length of the record to obtain the number of bytes written. 
		   		write_bytes = fwrite(tx_buf, sizeof(char), read_bytes, tx_fp);
				if (read_bytes < 0)
				{
			    	WRITE_FORMAT_ERROR("Error occurs while writing file, due to: %s", strerror(errno));
					ret = RET_FAILURE_SYSTEM_API;
					goto OUT;
			   	}
			   	else if (write_bytes != read_bytes)
				{
			    	WRITE_FORMAT_ERROR("Incorrect data size while writing file, expected: %d, actual: %d", read_bytes, write_bytes);
					ret = RET_FAILURE_SYSTEM_API;
					goto OUT;
			   	}
			   	else
			   		WRITE_FORMAT_DEBUG("Write %d bytes to the file", write_bytes);
			}
		}
// A value of 0 indicates that the call timed out and 
// no file descriptors were ready
		// else
		// {
		// 	WRITE_DEBUG("Time out. Nothing happen...");
		// }
	}
// Segmetation fault occurs while calling WRITE_FORMAT_INFO
// I don't know why. Perhaps similiar issue as below:
// https://forum.bitcraze.io/viewtopic.php?t=1089
OUT:
	WRITE_FORMAT_INFO("[%s] The worker thread of receiving file is done", thread_tag);

// 	assert(observer != NULL && "observer should NOT be NULL");
// 	PNOTIFY_RECV_FILE_DONE_CFG notify_send_file_done_cfg = NULL;
// 	NotifyRecvFileDoneCfg::generate_obj(&notify_recv_file_done_cfg, tx_session_id, node_token.c_str());
// 	PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_recv_file_done_cfg;
// // Asynchronous event
// 	observer->notify(NOTIFY_RECV_FILE_DONE, notify_cfg);
// 	SAFE_RELEASE(notify_cfg);

	WRITE_FORMAT_DEBUG("[%s] The worker thread of receiving file is dead", thread_tag);
	return ret;
}

void FileChannel::recv_thread_cleanup_handler(void* pvoid)
{
	FileChannel* pthis = (FileChannel*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->recv_thread_cleanup_handler_internal();
}

void FileChannel::recv_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the recv thread......", thread_tag);
	if (tx_buf != NULL)
	{
		delete[] tx_buf;
		tx_buf = NULL;
	}
	if (tx_fp != NULL)
	{
		fclose(tx_fp);
		tx_fp = NULL;
	}
	// return RET_SUCCESS;
}