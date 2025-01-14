#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <string>
#include <stdexcept>
#include "node_channel.h"


using namespace std;

const char* NodeChannel::thread_tag = "Node Channel Thread";
const int NodeChannel::WAIT_DATA_TIMEOUT = 60 * 1000;

NodeChannel::NodeChannel(PINODE node) :
	action_freeze(0),
	exit(0),
//	node_token(NULL),
	send_tid(0),
	recv_tid(0),
	node_socket(0),
	send_thread_ret(RET_SUCCESS),
	recv_thread_ret(RET_SUCCESS),
	send_msg_trigger(false)
{
	IMPLEMENT_MSG_DUMPER()
	IMPLEMENT_EVT_RECORDER()
	observer = node;
	assert(observer != NULL && "observer should NOT be NULL");
}

NodeChannel::~NodeChannel()
{
	RELEASE_EVT_RECORDER()
	RELEASE_MSG_DUMPER()
}

unsigned short NodeChannel::initialize(int channel_socket, const char* channel_token, const char* channel_remote_token)
{
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

	node_socket = channel_socket;
	node_token = string(channel_token);
	remote_token = string(channel_remote_token);

	mtx_buffer = PTHREAD_MUTEX_INITIALIZER;
	cond_buffer = PTHREAD_COND_INITIALIZER;

// Create a worker thread to access data...
    if (pthread_create(&send_tid, NULL, send_thread_handler, this) != 0)
    {
    	WRITE_FORMAT_ERROR("Fail to create a worker thread of sending message, due to: %s",strerror(errno));
    	return RET_FAILURE_HANDLE_THREAD;
    }
    if (pthread_create(&recv_tid, NULL, recv_thread_handler, this) != 0)
    {
    	WRITE_FORMAT_ERROR("Fail to create a worker thread of receiving message, due to: %s",strerror(errno));
    	return RET_FAILURE_HANDLE_THREAD;
    }

	return RET_SUCCESS;
}

unsigned short NodeChannel::deinitialize()
{
	if (exit > 0)
	{
		WRITE_FORMAT_DEBUG("The NodeChannel::deinitialize() has already been invoked...... %s", remote_token.c_str());
		return RET_SUCCESS;	
	}

	WRITE_FORMAT_DEBUG("Release resource in NodeChannel...... %s", remote_token.c_str());
	unsigned short ret = RET_SUCCESS;
	// int kill_ret;
	__sync_fetch_and_add(&exit, 1);
	// sleep(1);
	usleep(100000);

	bool send_thread_alive = false;
	bool recv_thread_alive = false;
// Check send thread alive
	// bool send_thread_alive = false;
	if (send_tid != 0)
	{
		int kill_ret = pthread_kill(send_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of sending message did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of sending message is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_FORMAT_DEBUG("The signal to the worker thread of sending message is STILL alive...... %s", remote_token.c_str());
// Kill the thread
		    if (pthread_cancel(send_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of sending message, due to: %s", strerror(errno));
			send_thread_alive = true;
		}
	}
// Check recv thread alive
	// bool recv_thread_alive = false;
	if (recv_tid != 0)
	{
		int kill_ret = pthread_kill(recv_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of receiving message did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of receiving message is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}		
		else
		{
			WRITE_FORMAT_DEBUG("The signal to the worker thread of receiving message is STILL alive...... %s", remote_token.c_str());
		    if (pthread_cancel(recv_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of receving message, due to: %s", strerror(errno));
			recv_thread_alive = true;
		}
	}
	// if (thread_alive) sleep(1);
	if (send_thread_alive || recv_thread_alive) usleep(100000);
// Wait for send thread's death
	if (send_thread_alive)
	{
		WRITE_FORMAT_DEBUG("Wait for the worker thread of sending message's death...... %s", remote_token.c_str());
		// fprintf(stderr, "Wait for the worker thread of sending message's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'send_status' variable accesses the illegal address
		// void* send_status;
		// pthread_join(send_tid, &send_status);
		// if (send_status == NULL)
		// 	WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
		// else
		// {
		// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)send_status);
		// 	ret = send_thread_ret;
		// }
		pthread_join(send_tid, NULL);
		if (CHECK_SUCCESS(send_thread_ret))
			WRITE_FORMAT_DEBUG("Wait for the worker thread of sending message's death Successfully...... %s", remote_token.c_str());
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", GetErrorDescription(send_thread_ret));
			ret = send_thread_ret;
		}
		send_tid = 0;
	}
// Wait for recv thread's death
	if (recv_thread_alive)
	{
		WRITE_FORMAT_DEBUG("Wait for the worker thread of receiving message's death...... %s", remote_token.c_str());
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'recv_status' variable accesses the illegal address
		// void* recv_status;
		// pthread_join(recv_tid, &recv_status);
		// if (recv_status == NULL)
		// 	WRITE_DEBUG("Wait for the worker thread of receiving message's death Successfully !!!");
		// else
		// {
		// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving message's death, due to: %s", (char*)recv_status);
		// 	ret = recv_thread_ret;
		// }
		pthread_join(recv_tid, NULL);
		if (CHECK_SUCCESS(recv_thread_ret))
			WRITE_FORMAT_DEBUG("Wait for the worker thread of receiving message's death Successfully...... %s", remote_token.c_str());
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving message's death, due to: %s", GetErrorDescription(recv_thread_ret));
			ret = recv_thread_ret;
		}
		recv_tid = 0;
	}

	if (node_socket != 0)
	{
		close(node_socket);
		node_socket = 0;
	}

	if (observer != NULL)
		observer = NULL;
	return ret;
}

void NodeChannel::notify_exit()
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

const char* NodeChannel::get_token()const
{
	return node_token.c_str();
}

const char* NodeChannel::get_remote_token()const
{
	return remote_token.c_str();
}

void NodeChannel::freeze_action()
{
    if (action_freeze == 0)
    {
    	WRITE_FORMAT_DEBUG("Freeze the action in NodeChannel[%s]...", remote_token);
		__sync_fetch_and_add(&action_freeze, 1);
	}
}

unsigned short NodeChannel::send_msg(const char* msg_data, int msg_data_size)
{
	assert(msg_data != NULL && "msg_data should NOT be NULL");
	char* msg_data_copy = (char*)malloc(sizeof(char) * msg_data_size);
	if (msg_data_copy == NULL)
		throw bad_alloc();
	memset(msg_data_copy, 0x0, sizeof(char) * msg_data_size);
	memcpy(msg_data_copy, msg_data, sizeof(char) * msg_data_size);
	// fprintf(stderr, "msg_data_copy: %s, msg_data: %s\n", msg_data_copy, msg_data);
// Put the new incoming message to the buffer first
	pthread_mutex_lock(&mtx_buffer);
	send_buffer_list.push_back(msg_data_copy);
	if (!send_msg_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		send_msg_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);

	return RET_SUCCESS;
}

void* NodeChannel::send_thread_handler(void* pvoid)
{
	NodeChannel* pthis = (NodeChannel*)pvoid;
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

	if (CHECK_SUCCESS(pthis->send_thread_ret))
	{
		pthread_cleanup_push(send_thread_cleanup_handler, pthis);
		pthis->send_thread_ret = pthis->send_thread_handler_internal();
		pthread_cleanup_pop(1);		
	}

	pthread_exit((CHECK_SUCCESS(pthis->send_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->send_thread_ret)));
}

unsigned short NodeChannel::send_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of sending message[%s] is running", thread_tag, remote_token.c_str());
	unsigned short ret = RET_SUCCESS;

	while(exit == 0)
	{
// Move the data from one buffer to another......
		pthread_mutex_lock(&mtx_buffer);
		if (!send_msg_trigger)
			pthread_cond_wait(&cond_buffer, &mtx_buffer);
		list<char*>::iterator iter_buffer = send_buffer_list.begin();
		while (iter_buffer != send_buffer_list.end())
		{
			// char* msg_data = (char*)*send_buffer_list.erase(iter_buffer++);
			char* msg_data = (char*)*iter_buffer;
			send_access_list.push_back(msg_data);
			iter_buffer++;
		}
		send_buffer_list.clear();
		send_msg_trigger = false;
		pthread_mutex_unlock(&mtx_buffer);
// Send the data to the remote
		list<char*>::iterator iter_access = send_access_list.begin();
		while (iter_access != send_access_list.end())
		{
			char* msg_data = (char*)*iter_access;
			// printf("NodeChannel::send_thread_handler_internal(), message sent: %s\n", msg_data);
			assert(msg_data != NULL && "msg_data should NOT be NULL in send_access_list");
			int start_pos = 0;
			// // // fprintf(stderr, "===> send: %s\n", msg_data);
			// // int write_to_byte = strlen(msg_data);
			// fprintf(stderr, "===> send: Type: %d,Size: %d, Full Size: %d\n", GET_BUF_TYPE(msg_data), GET_BUF_SIZE(msg_data), GET_BUF_FULL_SIZE(msg_data));
			int write_to_byte = GET_BUF_FULL_SIZE(msg_data);
			while (write_to_byte > 0)
			{
				int write_bytes = send(node_socket, &msg_data[start_pos], write_to_byte, 0);
				if (write_bytes == -1)
				{
					static const int ERRMSG_SIZE = 256;
					char errmsg[ERRMSG_SIZE];
					snprintf(errmsg, ERRMSG_SIZE, "Error occur while writing message to the Node[%s], due to: %s", remote_token.c_str(), strerror(errno));
					WRITE_ERROR(errmsg);
					// fprintf(stderr, errmsg);
					ret = RET_FAILURE_SYSTEM_API;
					goto OUT;
				}
				start_pos += write_bytes;
				write_to_byte -= write_bytes;
			}
			// fprintf(stderr, "===> send...... DONE\n");
			iter_access++;
			free(msg_data);
		}
		send_access_list.clear();
	}
OUT:
	// if (CHECK_FAILURE(ret))
	// {
	// 	list<char*>::iterator iter_access_failure = send_access_list.begin(); 
	// 	while(iter_access_failure != send_access_list.end())
	// 	{
	// 		char* msg_data_failure = (char*)(*iter_access_failure);
	// 		if (msg_data_failure != NULL)
	// 			free(msg_data_failure);
	// 		iter_access_failure++;
	// 	}
	// 	send_access_list.clear();
	// }

	WRITE_FORMAT_INFO("[%s] The worker thread of sending message is dead", thread_tag);
	return ret;
}

void NodeChannel::send_thread_cleanup_handler(void* pvoid)
{
	NodeChannel* pthis = (NodeChannel*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->send_thread_cleanup_handler_internal();
}

void NodeChannel::send_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource[%s] in the send thread......", thread_tag, remote_token.c_str());
	list<char*>::iterator iter_buffer = send_buffer_list.begin();
	while (iter_buffer != send_buffer_list.end())
	{
		char* msg_data = (char*)*iter_buffer;
		iter_buffer++;
		free(msg_data);
		send_buffer_list.clear();
	}
	list<char*>::iterator iter_access = send_access_list.begin();
	while (iter_access != send_access_list.end())
	{
		char* msg_data = (char*)*iter_access;
		iter_access++;
		free(msg_data);
		send_access_list.clear();
	}
	// return RET_SUCCESS;
}

void* NodeChannel::recv_thread_handler(void* pvoid)
{
	NodeChannel* pthis = (NodeChannel*)pvoid;
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

unsigned short NodeChannel::recv_thread_handler_internal()
{
	static int MAX_RECV_COUNT = 50;
	WRITE_FORMAT_INFO("[%s] The worker thread of receiving message [%s] is running", thread_tag, remote_token.c_str());

	char buf[RECV_BUF_SIZE];
	unsigned short ret = RET_SUCCESS;
	NodeMessageParser node_message_parser;
	// fprintf(stderr, "Recv00: Enter RECV thread...\n");
	while(exit == 0)
	{
		struct pollfd pfd;
		pfd.fd = node_socket;
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
			int recv_count = 0;
			int recv_ret;
			do{
// Read the data from the remote
				memset(buf, 0x0, sizeof(char) * RECV_BUF_SIZE);
				recv_ret = recv(node_socket, buf, sizeof(char) * RECV_BUF_SIZE, /*MSG_PEEK |*/ MSG_DONTWAIT);
				// fprintf(stderr, "===> recv: %s, recv_ret: %d\n", buf, recv_ret);
				// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_STRING_SIZE, "recv() return value: %d", ret);
				if (recv_ret == 0) // if recv() returns zero, that means the connection has been closed
				{
// Allocate the nofity event parameter
					if (!action_freeze)
					{
						// const char* notify_param = remote_token.c_str();
						size_t notify_param_size = strlen(remote_token.c_str()) + 1;
						PNOTIFY_CFG notify_cfg = new NotifyNodeDieCfg(remote_token.c_str(), notify_param_size);
						if (notify_cfg == NULL)
							throw bad_alloc();
// Notify the event
						WRITE_FORMAT_WARN("[%s] The connection [%s] is closed......", thread_tag, remote_token.c_str());
						observer->notify(NOTIFY_NODE_DIE, notify_cfg);
						return RET_FAILURE_CONNECTION_CLOSE;
					}
				}
				else if (recv_ret > 0) // Success
				{
// Parse the message
					ret = node_message_parser.parse(buf, recv_ret);
					if (CHECK_FAILURE(ret))  //  || CHECK_FAILURE_CONNECTION(ret))
					{
						if (ret == RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE)
						{
							recv_count++;
							if (recv_count >= MAX_RECV_COUNT)
							{
								WRITE_FORMAT_ERROR("[%s] Node[%s] fails to parse message, due to: %s. Max retries exprie......", thread_tag, node_token.c_str(), GetErrorDescription(ret));
								goto OUT;
							}
							else 
								continue;
						}
						else
						{
							WRITE_FORMAT_ERROR("[%s] Node[%s] fails to parse message, due to: %s", thread_tag, node_token.c_str(), GetErrorDescription(ret));
							goto OUT;
							// break;
						}
					}
// Send the message to the observer
					// fprintf(stderr, "Check !!!\n");
					// fprintf(stderr, "===> recv: message: (%d, %s)\n", node_message_parser.get_message_type(), node_message_parser.get_message());
					ret = observer->recv(node_message_parser.get_message_type(), node_message_parser.get_message(), node_message_parser.get_message_size());
					if (CHECK_FAILURE(ret))
					{
						WRITE_FORMAT_ERROR("[%s] Fail to update message to the observer[%s], due to: %s", thread_tag, node_token.c_str(), GetErrorDescription(ret));
						goto OUT;
					}
					else
					{
// Remove the data which is already shown
						// data_buffer = data_buffer.substr(beg_pos + END_OF_MESSAGE_LEN);
						node_message_parser.remove_old();
						break;
					}
				}
				else if (recv_ret < 0 ) 
				{
					if (errno == EAGAIN || errno == EWOULDBLOCK) 
					{
				        // This is expected on a non-blocking socket,
				        // so just return with what's available at the moment.
						recv_count++;
						if (recv_count >= MAX_RECV_COUNT)
						{
							WRITE_FORMAT_ERROR("[%s] fails to receive message. Max retries exprie......", thread_tag);
							goto OUT;
						}
						else 
							continue;		      
				    } 
				    else 
				    {
				        // Everything else is a hard error.
				        // Do something with it in the caller.
						WRITE_FORMAT_ERROR("[%s] recv() fails, due to: %s", thread_tag, strerror(errno));
						return RET_FAILURE_CONNECTION_ERROR;
				    }
			    }
			}while(true);
			// fprintf(stderr, "===> recv...... DONE\n");
		}
		else
		{
			// if (data_buffer.length() != 0)
			// 	WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, data_buffer.c_str());
			// WRITE_DEBUG("Time out. Nothing happen...");
			if (!node_message_parser.is_buffer_empty())
			{
				WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, node_message_parser.get_buffer());
			}
		}
	}
OUT:
// Segmetation fault occurs while calling WRITE_FORMAT_INFO
// I don't know why. Perhaps similiar issue as below:
// https://forum.bitcraze.io/viewtopic.php?t=1089
	// WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is dead !!!", thread_tag, node_token.c_str());
	return ret;
}
