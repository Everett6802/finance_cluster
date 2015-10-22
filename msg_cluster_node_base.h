#ifndef MSG_CLUSTER_NODE_BASE_H
#define MSG_CLUSTER_NODE_BASE_H

#include "msg_cluster_common.h"


class MsgClusterNodeBase : public MsgNotifyObserverInf
{
//	DECLARE_MSG_DUMPER()

protected:
	char* local_ip;

public:
	MsgClusterNodeBase();
	virtual ~MsgClusterNodeBase();

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short check_keepalive()=0;
};
typedef MsgClusterNodeBase* PMSG_CLUSTER_NODE_BASE;

#endif
