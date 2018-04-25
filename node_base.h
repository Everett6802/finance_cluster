#ifndef NODE_BASE_H
#define NODE_BASE_H

#include "common_definition.h"


class NodeBase : public MsgNotifyObserverInf
{
//	DECLARE_MSG_DUMPER()

protected:
	char* local_ip;

public:
	NodeBase();
	virtual ~NodeBase();

	virtual unsigned short initialize()=0;
	virtual unsigned short deinitialize()=0;
	virtual unsigned short check_keepalive()=0;
};
typedef NodeBase* PNODE_BASE;

#endif
