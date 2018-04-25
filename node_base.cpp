#include "node_base.h"


//DECLARE_MSG_DUMPER_PARAM();

NodeBase::NodeBase() :
	local_ip(NULL)
{
//	IMPLEMENT_MSG_DUMPER()
}

NodeBase::~NodeBase()
{
	if (local_ip != NULL)
	{
		delete[] local_ip;
		local_ip = NULL;
	}

//	RELEASE_MSG_DUMPER()
}
