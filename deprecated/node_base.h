#ifndef NODE_BASE_H
#define NODE_BASE_H

#include <pthread.h>
#include "common.h"


class NodeBase : public INode
{
//	DECLARE_MSG_DUMPER()

protected:
	char* local_ip;
// Start from 1, 1 for leader, otherwise for follower
	int cluster_node_id;
	ClusterMap cluster_map;

public:
	NodeBase();
	NodeBase(const char* ip);
	virtual ~NodeBase();

	// virtual unsigned short initialize()=0;
	// virtual unsigned short deinitialize()=0;
};
typedef NodeBase* PNODE_BASE;

#endif
