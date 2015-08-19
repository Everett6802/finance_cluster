#include "msg_cluster_node_recv_thread.h"


MsgClusterNodeRecvThread::MsgClusterNodeRecvThread() :
	t(0),
	msg_notify_observer(NULL)
{
	IMPLEMENT_MSG_DUMPER()
}

MsgClusterNodeRecvThread::~MsgClusterNodeRecvThread()
{
	RELEASE_MSG_DUMPER()
}

unsigned short MsgClusterNodeRecvThread::initialize(PMSG_NOTIFY_OBSERVER_INF observer, int recv_socket)
{
	msg_notify_observer = observer;
	if (msg_notify_observer == NULL)
	{
		WRITE_ERROR("msg_notify_observer should NOT be NULL");
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	return RET_SUCCESS;
}

unsigned short MsgClusterNodeRecvThread::deinitialize()
{
	return RET_SUCCESS;
}
