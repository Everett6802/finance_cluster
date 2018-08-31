#include <stdexcept>
#include "node_base.h"


using namespace std;
//DECLARE_MSG_DUMPER_PARAM();

NodeBase::NodeBase() :
	local_ip(NULL),
	cluster_node_id(0)
{
//	IMPLEMENT_MSG_DUMPER()
}

NodeBase::NodeBase(const char* ip) :
	local_ip(NULL),
	cluster_node_id(0)
{
//	IMPLEMENT_MSG_DUMPER()
	if (ip == NULL)
		throw invalid_argument(string("ip == NULL"));
	// int ip_len = strlen(ip) + 1;
	// local_ip = new char[ip_len];
	// if (local_ip == NULL)
	// 	throw bad_alloc();
	// memcpy(local_ip, ip, sizeof(char) * ip_len);
	local_ip = strdup(ip);
}

NodeBase::~NodeBase()
{
	if (local_ip != NULL)
	{
		// delete[] local_ip;
		free(local_ip);
		local_ip = NULL;
	}

//	RELEASE_MSG_DUMPER()
}
