#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <string>
#include <stdexcept>
#include "finance_cluster_leader_send_thread.h"


using namespace std;

const char* FinanceClusterLeaderSendThread::thread_tag = "Send Thread";
// DECLARE_MSG_DUMPER_PARAM();

class FinanceClusterLeaderSendThread::MsgCfg
{
public:
	string src_ip;
	string src_data;

	MsgCfg(string ip, string data)
	{
		src_ip = ip;
		src_data = data + END_OF_PACKET;
	}
};

FinanceClusterLeaderSendThread::FinanceClusterLeaderSendThread() :
	exit(0),
	pid(0),
	client_size(0),
	thread_ret(RET_SUCCESS),
	is_follower_connected(false),
	msg_notify_observer(NULL),
	new_data_trigger(false)
{
	IMPLEMENT_MSG_DUMPER()
}

FinanceClusterLeaderSendThread::~FinanceClusterLeaderSendThread()
{
	RELEASE_MSG_DUMPER()
}

unsigned short FinanceClusterLeaderSendThread::initialize(PMSG_NOTIFY_OBSERVER_INF observer)
{
	msg_notify_observer = observer;
	if (msg_notify_observer == NULL)
	{
		WRITE_ERROR("msg_notify_observer should NOT be None");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	mtx_client_socket = PTHREAD_MUTEX_INITIALIZER;
	mtx_buffer = PTHREAD_MUTEX_INITIALIZER;
	cond_buffer = PTHREAD_COND_INITIALIZER;
// Create a worker thread to access data...
	if (pthread_create(&pid, NULL, thread_handler, this) != 0)
	{
		WRITE_FORMAT_ERROR("Fail to create a worker thread of sending message, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
}

unsigned short FinanceClusterLeaderSendThread::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	void* status;
	int kill_ret;
	if (pid == 0)
		goto OUT;

	kill_ret = pthread_kill(pid, 0);
	if(kill_ret == ESRCH)
	{
		WRITE_WARN("The worker thread of sending message did NOT exist......");
		ret = RET_SUCCESS;
		goto OUT;
	}
	else if(kill_ret == EINVAL)
	{
		WRITE_ERROR("The signal to the worker thread of sending message is invalid");
		ret = RET_FAILURE_HANDLE_THREAD;
		goto OUT;
	}

	WRITE_DEBUG("The signal to the worker thread of sending message is STILL alive");
// Notify the worker thread it's time to exit
	notify_exit();

	pthread_mutex_lock(&mtx_buffer);
	pthread_cond_signal(&cond_buffer);
	pthread_mutex_unlock(&mtx_buffer);

	WRITE_DEBUG("Wait for the worker thread of sending message's death...");
	pthread_join(pid, &status);
	if (status == NULL)
		WRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
		ret = thread_ret;
		goto OUT;
	}
OUT:
	clearall();

	return ret;
}

void FinanceClusterLeaderSendThread::clearall()
{
	client_deque.clear();
	dead_client_index_deque.clear();
	client_socket_deque.clear();

	list<MsgCfg*>::iterator iter_buffer = buffer_list.begin();
	while (iter_buffer != buffer_list.end())
	{
		MsgCfg* msg_cfg = (MsgCfg*)*iter_buffer++;
		delete msg_cfg;
	}
	buffer_list.clear();

	list<MsgCfg*>::iterator iter_access = access_list.begin();
	while (iter_access != access_list.end())
	{
		MsgCfg* msg_cfg = (MsgCfg*)*iter_access++;
		delete msg_cfg;
	}
	access_list.clear();

	msg_notify_observer = NULL;
}

void FinanceClusterLeaderSendThread::notify_exit()
{
	__sync_fetch_and_add(&exit, 1);
}

unsigned short FinanceClusterLeaderSendThread::add_client(const char* ip, int socket)
{
	static char server_candiate_msg_buf[DEF_LONG_STRING_SIZE];
	if (ip == NULL)
	{
		WRITE_ERROR("Invalid argument: ip");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	WRITE_FORMAT_DEBUG("Add Node[%s] into the send list", ip);
	pthread_mutex_lock(&mtx_client_socket);
	client_deque.push_back(string(ip));
	client_socket_deque.push_back(socket);
	client_size = client_socket_deque.size();
	is_follower_connected = (client_size > 0 ? true : false);
	pthread_mutex_unlock(&mtx_client_socket);
	WRITE_FORMAT_INFO("There are %d Follower(s) connected to Leader", client_size);

	WRITE_FORMAT_DEBUG("Send server candidate ID[%d] to Node[%s]", client_size, ip);
	snprintf(server_candiate_msg_buf, DEF_LONG_STRING_SIZE, "%s:%d", CHECK_SERVER_CANDIDATE_TAG.c_str(), client_size);
	MsgCfg* msg_cfg = new MsgCfg(ip, string(server_candiate_msg_buf));
	if (msg_cfg == NULL)
	{
		WRITE_ERROR("Insufficient memory: msg_cfg");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	pthread_mutex_lock(&mtx_buffer);
	buffer_list.push_front(msg_cfg);
	if (!new_data_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		new_data_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);

	return RET_SUCCESS;
}

unsigned short FinanceClusterLeaderSendThread::send_msg(std::string src_ip, std::string data)
{
// Put the new incoming message to the buffer first
	pthread_mutex_lock(&mtx_buffer);
	MsgCfg* msg_cfg = new MsgCfg(src_ip, data);
	if (msg_cfg == NULL)
	{
		WRITE_ERROR("Insufficient memory: msg_cfg");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	buffer_list.push_back(msg_cfg);
	if (!new_data_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		new_data_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);

	return RET_SUCCESS;
}

unsigned short FinanceClusterLeaderSendThread::try_to_transmit_msg(int index, std::string data)
{
	if (index < 0 || index >= client_size)
	{
		WRITE_FORMAT_ERROR("The index[%d] of client_writer_list is out of range", index);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
// Send the data to each socket
	const char* data_ptr = data.c_str();
	int socket = client_socket_deque.at(index);
	string src_ip = client_deque.at(index);
	int start_pos = 0;
	int write_to_byte = data.length();
	while (write_to_byte > 0)
	{
		int write_bytes = send(socket, &data_ptr[start_pos], write_to_byte, 0);
		if (write_bytes == -1)
		{
			WRITE_FORMAT_ERROR("Error occur while writing message to the Node[%s], due to: %s", src_ip.c_str(), strerror(errno));
			fprintf(stderr, "Error occur while writing message to the Node[%s], due to: %s", src_ip.c_str(), strerror(errno));
			dead_client_index_deque.push_front(index);
//			return RET_FAILURE_SYSTEM_API;
		}
//		if (e.getMessage().equals("Broken pipe"))
//		{
//			dead_client_index_list.addFirst(index); // Caution: the index order
//		}
//		else
//		{
//			FinanceClusterCmnDef.format_error("Error occur while writing message to the Node[%s], due to: %s", client_list.get(index), e.toString());
//			return FinanceClusterCmnDef.RET_FAILURE_IO_OPERATION;
//		}
		start_pos += write_bytes;
		write_to_byte -= write_bytes;
	}

	return RET_SUCCESS;
}

unsigned short FinanceClusterLeaderSendThread::send_msg_to_remote()
{
	unsigned short ret = RET_SUCCESS;

	list<MsgCfg*>::iterator iter = access_list.begin();
	while (iter != access_list.end())
	{
//		bool follower_dead = false;
		MsgCfg* msg_cfg = (MsgCfg*)*iter++;
		assert(msg_cfg != NULL && "msg_cfg should NOT be NULL");

		pthread_mutex_lock(&mtx_client_socket);
		bool found = false;
		int index;
		if (!msg_cfg->src_ip.empty())
		{
// Check the destination IP is in the list
			for (int i = 0 ; i < client_size ; i++)
			{
				string src_ip = client_deque[i];
				if (msg_cfg->src_ip.compare(src_ip) == 0)
				{
					found = true;
					index = i;
					break;
				}
			}

			if (!found)
			{
				WRITE_FORMAT_ERROR("IP[%s] is NOT in the list", msg_cfg->src_ip.c_str());
				ret = RET_FAILURE_INCORRECT_CONFIG;
				goto OUT;
			}
		}
// Start to send message
		if (!found)
		{
			WRITE_FORMAT_DEBUG("Broadcast message[%s] to the each Node", msg_cfg->src_data.c_str());
			for(int i = 0 ; i < client_size ; i++)
			{
//				string node_ip = client_deque[i];
				ret = try_to_transmit_msg(i, msg_cfg->src_data);
				if (CHECK_FAILURE(ret))
					goto OUT;
			}
		}
		else
		{
			WRITE_FORMAT_DEBUG("Send message[%s] to the Node[%s]", msg_cfg->src_data.c_str(), msg_cfg->src_ip.c_str());
			ret = try_to_transmit_msg(index, msg_cfg->src_data);
			if (CHECK_FAILURE(ret))
				goto OUT;
		}

// Remove the disconnected clients
		if (!dead_client_index_deque.empty())
		{
			int dead_client_index_deque_size = dead_client_index_deque.size();
			for (int index = 0 ; index < dead_client_index_deque_size ; index++)
			{
//				String node_ip = client_deque.remove(i);
				deque<std::string>::iterator iter = client_deque.erase(client_deque.begin() + index);
				string node_ip = (string)*iter;
				WRITE_FORMAT_WARN("Follower[%s] is DEAD !!!", node_ip.c_str());
				printf("Follower[%s] disconnects from the Leader\n", node_ip.c_str());

				client_socket_deque.erase(client_socket_deque.begin() + index);
			}
			client_size = client_socket_deque.size();
			is_follower_connected = (client_size > 0 ? true : false);
			WRITE_FORMAT_INFO("There are %d Follower(s) connected to Leader", client_size);

			if (msg_notify_observer != NULL)
			{
// Notify the parent to remove the dead client
				WRITE_FORMAT_INFO("Notify the parent to remove %d worker thread of receiving data", dead_client_index_deque_size);
				msg_notify_observer->notify(NOTIFY_DEAD_CLIENT);
			}
			dead_client_index_deque.clear();
		}
OUT:
		pthread_mutex_unlock(&mtx_client_socket);
		delete msg_cfg;
	}
	access_list.clear();

	return RET_SUCCESS;
}

unsigned short FinanceClusterLeaderSendThread::check_keepalive()
{
	pthread_mutex_lock(&mtx_buffer);
	MsgCfg* msg_cfg = new MsgCfg("", CHECK_KEEPALIVE_TAG);
	if (msg_cfg == NULL)
	{
		WRITE_ERROR("Insufficient memory: msg_cfg");
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	}
	buffer_list.push_front(msg_cfg);
	if (!new_data_trigger)
	{
		pthread_cond_signal(&cond_buffer);
		new_data_trigger = true;
	}
	pthread_mutex_unlock(&mtx_buffer);

	return RET_SUCCESS;
}

bool FinanceClusterLeaderSendThread::follower_connected()const
{
	return is_follower_connected;
}

const deque<int>& FinanceClusterLeaderSendThread::get_dead_client_index_deque()const
{
	return dead_client_index_deque;
}

void* FinanceClusterLeaderSendThread::thread_handler(void* pvoid)
{
	FinanceClusterLeaderSendThread* pthis = (FinanceClusterLeaderSendThread*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
}

unsigned short FinanceClusterLeaderSendThread::thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is running", thread_tag);
	unsigned short ret = RET_SUCCESS;

	while(!exit)
	{
		pthread_mutex_lock(&mtx_buffer);
		if (!new_data_trigger)
			pthread_cond_wait(&cond_buffer, &mtx_buffer);
		list<MsgCfg*>::iterator iter = buffer_list.begin();
		while (iter != buffer_list.end())
		{
			MsgCfg* msg = (MsgCfg*)*buffer_list.erase(iter++);
			access_list.push_back(msg);
		}
		new_data_trigger = false;
		pthread_mutex_unlock(&mtx_buffer);

// Send the data to the remote
		ret = send_msg_to_remote();
		if (CHECK_FAILURE(ret))
			break;
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", thread_tag);
	return ret;
}
