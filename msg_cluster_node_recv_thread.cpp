#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <string>
#include <stdexcept>
#include "msg_cluster_node_recv_thread.h"


using namespace std;

const char* MsgClusterNodeRecvThread::thread_tag = "Recv Thread";

MsgClusterNodeRecvThread::MsgClusterNodeRecvThread() :
	exit(0),
//	node_ip(NULL),
	pid(0),
	node_socket(0),
	msg_notify_observer(NULL),
	thread_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()
}

MsgClusterNodeRecvThread::~MsgClusterNodeRecvThread()
{
	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterNodeRecvThread::initialize(PMSG_NOTIFY_OBSERVER_INF observer, int recv_socket, const char* ip)
{
	msg_notify_observer = observer;
	if (msg_notify_observer == NULL || ip == NULL)
	{
		WRITE_ERROR("msg_notify_observer/ip should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	node_socket = recv_socket;
	node_ip = string(ip);

// Create a worker thread to access data...
    if (pthread_create(&pid, NULL, thread_handler, this) != 0)
    {
    	WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Fail to create a worker thread of receiving message, due to: %s",strerror(errno));
    	return RET_FAILURE_HANDLE_THREAD;
    }

	return RET_SUCCESS;
}

unsigned short MsgClusterNodeRecvThread::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	void* status;
	int kill_ret;
	if (pid == 0)
		goto OUT;

	kill_ret = pthread_kill(pid, 0);
	if(kill_ret == ESRCH)
	{
		WRITE_WARN("The worker thread of receiving message did NOT exist......");
		ret = RET_SUCCESS;
		goto OUT;
	}
	else if(kill_ret == EINVAL)
	{
		WRITE_ERROR("The signal to the worker thread of receiving message is invalid");
		ret = RET_FAILURE_HANDLE_THREAD;
		goto OUT;
	}

	WRITE_DEBUG("The signal to the worker thread of receiving message is STILL alive");
// Notify the worker thread it's time to exit
	notify_exit();

	WRITE_DEBUG("Wait for the worker thread of receiving message's death...");
	pthread_join(pid, &status);
	if (status == NULL)
		WRITE_DEBUG("Wait for the worker thread of receiving message's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "Error occur while waiting for the worker thread of receiving message's death, due to: %s", (char*)status);
		ret = thread_ret;
		goto OUT;
	}
OUT:
	clearall();

	return ret;
}

void MsgClusterNodeRecvThread::clearall()
{
	node_socket = 0;
//	if (node_ip != NULL)
//	{
//		delete[] node_ip;
//		node_ip = NULL;
//	}
	msg_notify_observer = NULL;
}

void MsgClusterNodeRecvThread::notify_exit()
{
	__sync_fetch_and_add(&exit, 1);
}

void* MsgClusterNodeRecvThread::thread_handler(void* pvoid)
{
	MsgClusterNodeRecvThread* pthis = (MsgClusterNodeRecvThread*)pvoid;
	if (pthis != NULL)
		pthis->thread_ret = pthis->thread_handler_internal();
	else
		throw std::invalid_argument("pvoid should NOT be NULL");

	pthread_exit((CHECK_SUCCESS(pthis->thread_ret) ? NULL : (void*)GetErrorDescription(pthis->thread_ret)));
}

unsigned short MsgClusterNodeRecvThread::thread_handler_internal()
{
	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] The worker thread of receiving message in Node[%s] is running", thread_tag, node_ip.c_str());

	static const string END_OF_MESSAGE = "\r\n\r\n";
	static const int END_OF_MESSAGE_LEN = END_OF_MESSAGE.length();

	char buf[RECV_BUF_SIZE];
//	int read_bytes = RECV_BUF_SIZE;
//	int read_to_bytes = 0;
//	unsigned short ret = RET_SUCCESS;
	string data_buffer = "";

	while(!exit)
	{
		struct pollfd pfd;
		pfd.fd = node_socket;
		pfd.events = POLLIN | POLLHUP | POLLRDNORM;
	    pfd.revents = 0;
		int ret = poll(&pfd, 1, 3000); // call poll with a timeout of 3000 ms
// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_STRING_SIZE, "poll() return value: %d", ret);
		if (ret < 0)
		{
			WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "[%s] poll() fail, due to %s", thread_tag, strerror(errno));
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
				WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "[%s] The connection is closed......", thread_tag);
				return RET_FAILURE_CONNECTION_CLOSE;
			}
			else
			{
				string new_data = string(buf);
// Check if the data is completely sent from the remote site
				size_t beg_pos = new_data.find(END_OF_MESSAGE);
				if (beg_pos == string::npos)
				{
					WRITE_FORMAT_ERROR(EX_LONG_STRING_SIZE, "[%s] The new incoming data[%s] is NOT completely......", thread_tag, data_buffer.c_str());
					data_buffer += new_data;
					continue;
				}
				else
				{
					data_buffer += new_data.substr(0, beg_pos);
				}

//				const char* new_message = data_buffer.c_str();
// Show the data read from the remote site
				WRITE_FORMAT_DEBUG(EX_LONG_STRING_SIZE, "[%s] Receive message: %s", thread_tag, data_buffer.c_str());
// The data is coming, notify the observer
				ret = msg_notify_observer->update(node_ip, data_buffer);
				if (CHECK_FAILURE(ret))
				{
					WRITE_FORMAT_ERROR(LONG_STRING_SIZE, "[%s] Fail to update message to the observer[%s], due to: %s", thread_tag, node_ip.c_str(), GetErrorDescription(ret));
					break;
				}
// Clean the message sent to the observer
				data_buffer = "";
// Remove the data which is already shown
				data_buffer = new_data.substr(beg_pos + END_OF_MESSAGE_LEN);
			}
		}
		else
		{
			WRITE_DEBUG("Time out. Nothing happen...");
			if (data_buffer.length() != 0)
				WRITE_FORMAT_ERROR(EX_LONG_STRING_SIZE, "[%s] The data[%s] is STILL in the buffer !!!", thread_tag, data_buffer.c_str());
		}
	}

	WRITE_FORMAT_INFO(LONG_STRING_SIZE, "[%s] The worker thread of receiving message in Node[%s] is dead !!!", thread_tag, node_ip.c_str());

	return RET_SUCCESS;
}
