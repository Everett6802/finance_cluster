#ifndef MSG_CLUSTER_NODE_BASE_H
#define MSG_CLUSTER_NODE_BASE_H


class MsgClusterNodeBase
{
protected:
	char* local_ip;

public:
	MsgClusterNodeBase();
	virtual ~MsgClusterNodeBase(){}

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short check_keepalive()=0;
};
typedef MsgClusterNodeBase* PMSG_CLUSTER_NODE_BASE;

#endif
