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
	observer = node;
	assert(observer != NULL && "observer should NOT be NULL");
}

NodeChannel::~NodeChannel()
{
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
	WRITE_DEBUG("Release resource in NodeChannel......");
	unsigned short ret = RET_SUCCESS;
	// int kill_ret;
	__sync_fetch_and_add(&exit, 1);
	// sleep(1);
	usleep(100000);

	bool thread_alive = false;
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
			WRITE_DEBUG("The signal to the worker thread of sending message is STILL alive");
// Kill the thread
		    if (pthread_cancel(send_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of sending message, due to: %s", strerror(errno));
			thread_alive = true;
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
			WRITE_DEBUG("The signal to the worker thread of receiving message is STILL alive");
		    if (pthread_cancel(recv_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of receving message, due to: %s", strerror(errno));
			thread_alive = true;
		}
	}
	// if (thread_alive) sleep(1);
	if (thread_alive) usleep(100000);
// Wait for send thread's death
	WRITE_DEBUG("Wait for the worker thread of sending message's death...");
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
		WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", GetErrorDescription(send_thread_ret));
		ret = send_thread_ret;
	}
// Wait for recv thread's death
	WRITE_DEBUG("Wait for the worker thread of receiving message's death...");
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
		WRITE_DEBUG("Wait for the worker thread of receiving message's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving message's death, due to: %s", GetErrorDescription(recv_thread_ret));
		ret = recv_thread_ret;
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

unsigned short NodeChannel::send_msg(const char* msg_data)
{
	assert(msg_data != NULL && "msg_data should NOT be NULL");
	char* msg_data_dup = strdup(msg_data);
// Put the new incoming message to the buffer first
	pthread_mutex_lock(&mtx_buffer);
	send_buffer_list.push_back(msg_data_dup);
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
	WRITE_FORMAT_INFO("[%s] The worker thread of sending message is running", thread_tag);
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
			int write_to_byte = strlen(msg_data);
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
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the send thread......", thread_tag);
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
	WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is running", thread_tag, node_token.c_str());

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
// Read the data from the remote
			memset(buf, 0x0, sizeof(char) * RECV_BUF_SIZE);
			ret = recv(node_socket, buf, sizeof(char) * RECV_BUF_SIZE, /*MSG_PEEK |*/ MSG_DONTWAIT);
			// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_STRING_SIZE, "recv() return value: %d", ret);
			if (ret == 0) // if recv() returns zero, that means the connection has been closed
			{
// Allocate the nofity event parameter
				// const char* notify_param = remote_token.c_str();
				size_t notify_param_size = strlen(remote_token.c_str()) + 1;
				PNOTIFY_CFG notify_cfg = new NotifyNodeDieCfg(remote_token.c_str(), notify_param_size);
				if (notify_cfg == NULL)
					throw bad_alloc();
// Notify the event
				WRITE_FORMAT_WARN("[%s] The connection is closed......", thread_tag);
				observer->notify(NOTIFY_NODE_DIE, notify_cfg);
				return RET_FAILURE_CONNECTION_CLOSE;
			}
			else
			{
// Parse the message
				ret = node_message_parser.parse(buf);
				if (CHECK_FAILURE(ret))
				{
					if (ret == RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE)
						continue;
					else
					{
						WRITE_FORMAT_ERROR("[%s] Node[%s] fails to parse message, due to: %s", thread_tag, node_token.c_str(), GetErrorDescription(ret));
						break;
					}
				}
// Send the message to the observer
				ret = observer->recv(node_message_parser.get_message_type(), node_message_parser.get_message());
				if (CHECK_FAILURE(ret))
				{
					WRITE_FORMAT_ERROR("[%s] Fail to update message to the observer[%s], due to: %s", thread_tag, node_token.c_str(), GetErrorDescription(ret));
					break;
				}
// Remove the data which is already shown
				// data_buffer = data_buffer.substr(beg_pos + END_OF_MESSAGE_LEN);
				node_message_parser.remove_old();
			}
		}
		else
		{
			// if (data_buffer.length() != 0)
			// 	WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, data_buffer.c_str());
			// WRITE_DEBUG("Time out. Nothing happen...");
			if (!node_message_parser.is_cur_message_empty())
			{
				WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, node_message_parser.cur_get_message());
			}
		}
	}
// Segmetation fault occurs while calling WRITE_FORMAT_INFO
// I don't know why. Perhaps similiar issue as below:
// https://forum.bitcraze.io/viewtopic.php?t=1089
	// WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is dead !!!", thread_tag, node_token.c_str());
	return ret;
}
