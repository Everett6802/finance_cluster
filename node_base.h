#ifndef NODE_BASE_H
#define NODE_BASE_H

#include "common.h"


class NodeBase : public MsgNotifyObserverInf
{
//	DECLARE_MSG_DUMPER()

protected:
	char* local_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_node_id;

public:
	NodeBase();
	NodeBase(const char* ip);
	virtual ~NodeBase();

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short check_keepalive()=0;
};
typedef NodeBase* PNODE_BASE;

#endif
