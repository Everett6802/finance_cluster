#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <string>
#include <stdexcept>
#include "node_channel.h"


using namespace std;

const char* NodeChannel::thread_tag = "Channel Thread";

NodeChannel::NodeChannel() :
	exit(0),
//	node_ip(NULL),
	send_tid(0),
	recv_tid(0),
	node_socket(0),
	parent(NULL),
	thread_ret(RET_SUCCESS),
	send_data_trigger(false)
{
	IMPLEMENT_MSG_DUMPER()
}

NodeChannel::~NodeChannel()
{
	RELEASE_MSG_DUMPER()
}

unsigned short NodeChannel::initialize(PINODE node, int access_socket, const char* ip)
{
	parent = node;
	if (parent == NULL || ip == NULL)
	{
		WRITE_ERROR("parent/ip should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	node_socket = access_socket;
	node_ip = string(ip);

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
	unsigned short ret = RET_SUCCESS;
	void* status;
	int kill_ret;
	// if (pid == 0)
	// 	goto OUT;
// Check send thread alive
	bool send_thread_alive = false;
	if (send_tid != 0)
	{
		kill_ret = pthread_kill(send_tid, 0);
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
			send_thread_alive = true;
		}
	}
// Check recv thread alive
	bool recv_thread_alive = false;
	if (recv_tid != 0)
	{
		kill_ret = pthread_kill(recv_tid, 0);
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
			recv_thread_alive = false;
		}
	}
	
// Notify the worker thread it's time to exit
	notify_exit();
// Wait for send thread's death
	if (send_thread_alive)
	{
		WRITE_DEBUG("Wait for the worker thread of sending message's death...");
		pthread_join(send_tid, &status);
		if (status == NULL)
			WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
			return thread_ret;
			// goto OUT;
		}
	}
// Wait for recv thread's death
	if (recv_thread_alive)
	{
		WRITE_DEBUG("Wait for the worker thread of receiving message's death...");
		pthread_join(recv_tid, &status);
		if (status == NULL)
			WRITE_DEBUG("Wait for the worker thread of receiving message's death Successfully !!!");
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of receiving message's death, due to: %s", (char*)status);
			return thread_ret;
			// goto OUT;
		}
	}

	if (node_socket != 0)
	{
		close(node_socket);
		node_socket = 0;
	}

	parent = NULL;
	return ret;
}

void NodeChannel::notify_exit()
{
	__sync_fetch_and_add(&exit, 1);
// Notify the send thread to exit
	pthread_mutex_lock(&mtx_buffer);
	if (!send_data_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		send_data_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);
}

unsigned short NodeChannel::send_msg(const char* msg_data)
{
	assert(msg_data != NULL && "msg_data should NOT be NULL");
	char* msg_data_dup = strdup(msg_data);
// Put the new incoming message to the buffer first
	pthread_mutex_lock(&mtx_buffer);
	send_buffer_list.push_back(msg_data_dup);
	if (!send_data_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		send_data_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);

	return RET_SUCCESS;
}

void* NodeChannel::send_thread_handler(void* pvoid)
{
	NodeChannel* pthis = (NodeChannel*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->send_thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
}

unsigned short NodeChannel::send_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of sending message is running", thread_tag);
	unsigned short ret = RET_SUCCESS;

	while(exit == 0)
	{
// Move the data from one buffer to another......
		pthread_mutex_lock(&mtx_buffer);
		if (!send_data_trigger)
			pthread_cond_wait(&cond_buffer, &mtx_buffer);
		list<char*>::iterator iter_buffer = send_buffer_list.begin();
		while (iter_buffer != send_buffer_list.end())
		{
			char* msg_data = (char*)*send_buffer_list.erase(iter_buffer++);
			send_access_list.push_back(msg_data);
		}
		send_data_trigger = false;
		pthread_mutex_unlock(&mtx_buffer);
// Send the data to the remote
		list<char*>::iterator iter_access = send_access_list.begin();
		while (iter_access != send_access_list.end())
		{
			char* msg_data = (char*)*iter_access;
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
					snprintf(errmsg, ERRMSG_SIZE, "Error occur while writing message to the Node[%s], due to: %s", remote_ip.c_str(), strerror(errno));
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
	if (CHECK_FAILURE(ret))
	{
		list<char*>::iterator iter_access_failure = send_access_list.begin(); 
		while(iter_access_failure != send_access_list.end())
		{
			char* msg_data_failure = (char*)(*iter_access_failure);
			if (msg_data_failure != NULL)
				free(msg_data_failure);
			iter_access_failure++;
		}
		send_access_list.clear();
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of sending message is dead", thread_tag);
	return ret;
}

void* NodeChannel::recv_thread_handler(void* pvoid)
{
	NodeChannel* pthis = (NodeChannel*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->recv_thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
}

unsigned short NodeChannel::recv_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is running", thread_tag, node_ip.c_str());

	char buf[RECV_BUF_SIZE];
	unsigned short ret = RET_SUCCESS;
//	int read_bytes = RECV_BUF_SIZE;
//	int read_to_bytes = 0;
//	unsigned short ret = RET_SUCCESS;
	// string data_buffer = "";
	NodeMessageParser node_message_parser;
	while(exit == 0)
	{
		struct pollfd pfd;
		pfd.fd = node_socket;
		pfd.events = POLLIN | POLLHUP | POLLRDNORM;
	    pfd.revents = 0;
		int ret = poll(&pfd, 1, 3000); // call poll with a timeout of 3000 ms
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
				WRITE_FORMAT_ERROR("[%s] The connection is closed......", thread_tag);
				return RET_FAILURE_CONNECTION_CLOSE;
			}
			else
			{
				// string new_data = string(buf);
// // Check if the data is completely sent from the remote site
// 				size_t beg_pos = new_data.find(END_OF_MESSAGE);
// 				if (beg_pos == string::npos)
// 				{
// 					WRITE_FORMAT_ERROR("[%s] The new incoming data[%s] is NOT completely......", thread_tag, data_buffer.c_str());
// 					data_buffer += new_data;
// 					continue;
// 				}
// 				else
// 				{
// 					data_buffer += new_data.substr(0, beg_pos);
// 				}

// //				const char* new_message = data_buffer.c_str();
// // Show the data read from the remote site
// 				WRITE_FORMAT_DEBUG("[%s] Receive message: %s", thread_tag, data_buffer.c_str());
// // The data is coming, notify the observer
// 				ret = parent->update(node_ip, data_buffer);
// 				if (CHECK_FAILURE(ret))
// 				{
// 					WRITE_FORMAT_ERROR("[%s] Fail to update message to the observer[%s], due to: %s", thread_tag, node_ip.c_str(), GetErrorDescription(ret));
// 					break;
// 				}
// // Clean the message sent to the observer
// 				data_buffer = "";
// // Remove the data which is already shown
// 				data_buffer = new_data.substr(beg_pos + END_OF_MESSAGE_LEN);

// 				data_buffer += string(buf);
// // Check if the data is completely sent from the remote site
// 				size_t beg_pos = data_buffer.find(END_OF_MESSAGE);
// 				if (beg_pos == string::npos)
// 				{
// 					WRITE_FORMAT_WARN("[%s] The new incoming data[%s] is NOT completely......", thread_tag, data_buffer.c_str());
// 					continue;
// 				}
// // The data is coming, notify the parent
// 				MessageType message_type = (MessageType)data_buffer.front();
// 				if (message_type < 0 || message_type >= MSG_SIZE)
// 				{
// 					WRITE_FORMAT_ERROR("[%s] The message type[%d] is NOT in range [0, %d)", thread_tag, message_type, MSG_SIZE);
// 					return RET_FAILURE_RUNTIME;				
// 				}
// Parse the message
				ret = node_message_parser.parse(buf);
				if (CHECK_FAILURE(ret))
				{
					if (ret == RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE)
						continue;
					else
					{
						WRITE_FORMAT_ERROR("[%s] Node[%s] fails to parse message, due to: %s", thread_tag, node_ip.c_str(), GetErrorDescription(ret));
						break;
					}
				}
// Send the message to the parent
				// ret = parent->recv(meesage_type, data_buffer.substr(1, beg_pos).c_str());
				ret = parent->recv(node_message_parser.get_message_type(), node_message_parser.get_message());
				if (CHECK_FAILURE(ret))
				{
					WRITE_FORMAT_ERROR("[%s] Fail to update message to the observer[%s], due to: %s", thread_tag, node_ip.c_str(), GetErrorDescription(ret));
					break;
				}
// Remove the data which is already shown
				// data_buffer = data_buffer.substr(beg_pos + END_OF_MESSAGE_LEN);
				node_message_parser.remove_old();
			}
		}
		else
		{
			WRITE_DEBUG("Time out. Nothing happen...");
			// if (data_buffer.length() != 0)
			// 	WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, data_buffer.c_str());
			if (node_message_parser.is_cur_message_empty())
				WRITE_FORMAT_ERROR("[%s] The data[%s] is STILL in the buffer !!!", thread_tag, node_message_parser.cur_get_message());
		}
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of receiving message in Node[%s] is dead !!!", thread_tag, node_ip.c_str());

	return ret;
}
