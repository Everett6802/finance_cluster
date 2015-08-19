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
	t(0),
	msg_notify_observer(NULL)
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

//	t = new Thread(this);
//	t.start();

	return RET_SUCCESS;
}

unsigned short MsgClusterLeaderSendThread::deinitialize()
{
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
