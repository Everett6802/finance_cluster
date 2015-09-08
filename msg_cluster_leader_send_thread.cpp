#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string>
#include "msg_cluster_leader_send_thread.h"


using namespace std;

class MsgClusterLeaderSendThread::MsgCfg
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

MsgClusterLeaderSendThread::MsgClusterLeaderSendThread() :
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

MsgClusterLeaderSendThread::~MsgClusterLeaderSendThread()
{
	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterLeaderSendThread::initialize(PMSG_NOTIFY_OBSERVER_INF observer)
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
	if (pthread_create(&pid, NULL, thread_handler, this))
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Fail to create a worker thread of sending message, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderSendThread::deinitialize()
{
	return RET_SUCCESS;
}

void MsgClusterLeaderSendThread::notify_exit()
{
	__sync_fetch_and_add(&exit, 1);
}

unsigned short MsgClusterLeaderSendThread::add_client(const char* ip, int socket)
{
	static char server_candiate_msg_buf[DEF_LONG_STRING_SIZE];
	if (ip == NULL)
	{
		WRITE_ERROR("Invalid argument: ip");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Add Node[%s] into the send list", ip);
	pthread_mutex_lock(&mtx_client_socket);
	client_deque.push_back(string(ip));
	client_socket_deque.push_back(socket);
	client_size = client_socket_deque.size();
	is_follower_connected = (client_size > 0 ? true : false);
	pthread_mutex_unlock(&mtx_client_socket);
	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "There are %d Follower(s) connected to Leader", client_size);

	WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Send server candidate ID[%d] to Node[%s]", client_size, ip);
	snprintf(server_candiate_msg_buf, LONG_STRING_SIZE, "%s:%d", CHECK_SERVER_CANDIDATE_TAG.c_str(), client_size);
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

unsigned short MsgClusterLeaderSendThread::send_msg(std::string src_ip, std::string data)
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

unsigned short MsgClusterLeaderSendThread::try_to_transmit_msg(int index, std::string data)
{
	if (index < 0 || index >= client_size)
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "The index[%d] of client_writer_list is out of range", index);
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
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Error occur while writing message to the Node[%s], due to: %s", src_ip.c_str(), strerror(errno));
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
//			MsgClusterCmnDef.format_error("Error occur while writing message to the Node[%s], due to: %s", client_list.get(index), e.toString());
//			return MsgClusterCmnDef.RET_FAILURE_IO_OPERATION;
//		}
		start_pos += write_bytes;
		write_to_byte -= write_bytes;
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderSendThread::send_msg_to_remote()
{
	unsigned short ret = RET_SUCCESS;

	list<MsgCfg*>::iterator iter = access_list.begin();
	while (iter != access_list.end())
	{
		bool follower_dead = false;
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
				WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "IP[%s] is NOT in the list", msg_cfg->src_ip.c_str());
				ret = RET_FAILURE_INCORRECT_CONFIG;
				goto OUT;
			}
		}
// Start to send message
		if (!found)
		{
			WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Broadcast message[%s] to the each Node", msg_cfg->src_data.c_str());
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
			WRITE_FORMAT_DEBUG(LONG_STRING_SIZE, "Send message[%s] to the Node[%s]", msg_cfg->src_data.c_str(), msg_cfg->src_ip.c_str());
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
				WRITE_FORMAT_WARN(LONG_STRING_SIZE, "Follower[%s] is DEAD !!!", node_ip);
				printf("Follower[%s] disconnects from the Leader\n", node_ip);

				client_socket_deque.erase(client_socket_deque.begin() + index);
			}
			client_size = client_socket_deque.size();
			is_follower_connected = (client_size > 0 ? true : false);
			WRITE_FORMAT_INFO(LONG_STRING_SIZE, "There are %d Follower(s) connected to Leader", client_size);

			if (msg_notify_observer != NULL)
			{
// Notify the parent to remove the dead client
				WRITE_FORMAT_INFO(LONG_STRING_SIZE, "Notify the parent to remove %d worker thread of receiving data", dead_client_index_deque_size);
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

void* MsgClusterLeaderSendThread::thread_handler(void* pvoid)
{
	if (pvoid != NULL)
	{
		MsgClusterLeaderSendThread* pthis = (MsgClusterLeaderSendThread*)pvoid;
		unsigned short ret = pthis->thread_handler_internal();
	}

	pthread_exit((void*)"pvoid should NOT be NULL");
}

unsigned short MsgClusterLeaderSendThread::thread_handler_internal()
{
	return RET_SUCCESS;
}
