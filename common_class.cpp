#include <assert.h>
#include <stdexcept>
#include <algorithm>
#include "common.h"


using namespace std;

// #define DEBUG 

#ifdef DEBUG
#define PRINT_IPV4(X, Y)\
do{\
	printf("IPv4 %s:  ", X);\
	for (int i = 0 ; i < 4 ; i++)\
		printf("%d ", ipv4_##Y[i]);\
	printf("\n");\
}while(0)
#else
#define PRINT_IPV4(X, Y)
#endif


unsigned short IPv4Addr::ipv4_value2str(const unsigned char ipv4_value[], char** ipv4_str)
{
	assert(ipv4_str != NULL && "ipv4_str should NOT be NULL");
	char* ipv4_str_tmp = new char[16];
	if (ipv4_str_tmp == NULL)
		throw bad_alloc();
	snprintf(ipv4_str_tmp, 16, "%d.%d.%d.%d", ipv4_value[0], ipv4_value[1], ipv4_value[2], ipv4_value[3]);
	*ipv4_str = ipv4_str_tmp;
	return RET_SUCCESS;
}

unsigned short IPv4Addr::ipv4_str2value(const char* ipv4_str, unsigned char ipv4_value[])
{
	assert(ipv4_str != NULL && "ipv4_str should NOT be NULL");
	char *ipv4_str_tmp = new char[strlen(ipv4_str) + 1];
	if (ipv4_str_tmp == NULL)
		throw bad_alloc();
	strcpy(ipv4_str_tmp, ipv4_str);
	char* tmp_ptr = ipv4_str_tmp;
	int tmp_ptr_cnt = 0;
	char* elem = NULL;
	while((elem = strtok(tmp_ptr, ".")) != NULL)
	{
		if (tmp_ptr_cnt == 4)
		{
			STATIC_WRITE_FORMAT_DEBUG("Incorrect IPv4 argument: %s", ipv4_str);
			return RET_FAILURE_INVALID_ARGUMENT;
		}
		ipv4_value[tmp_ptr_cnt++] = (unsigned char)atoi(elem);
		if (tmp_ptr != NULL)
			tmp_ptr = NULL;
	}
	PRINT_IPV4("value", value);
	// printf("IPv4 value:  ");
	// for (int i = 0 ; i < 4 ; i++)
	// 	printf("%d ", ipv4_value[i]);
	// printf("\n");
	return RET_SUCCESS;
}

unsigned short IPv4Addr::get_netmask(int netmask_digits, unsigned char ipv4_mask[])
{
	static const unsigned char NETMASK_DIGIT0 = 0x0;
	static const unsigned char NETMASK_DIGIT1 = (0x1 << 7);
	static const unsigned char NETMASK_DIGIT2 = (0x1 << 6) | NETMASK_DIGIT1;
	static const unsigned char NETMASK_DIGIT3 = (0x1 << 5) | NETMASK_DIGIT2;
	static const unsigned char NETMASK_DIGIT4 = (0x1 << 4) | NETMASK_DIGIT3;
	static const unsigned char NETMASK_DIGIT5 = (0x1 << 3) | NETMASK_DIGIT4;
	static const unsigned char NETMASK_DIGIT6 = (0x1 << 2) | NETMASK_DIGIT5;
	static const unsigned char NETMASK_DIGIT7 = (0x1 << 1) | NETMASK_DIGIT6;
	static const unsigned char NETMASK_DIGIT8 = (0x1 << 0) | NETMASK_DIGIT7;
	static const unsigned char NETMASK_ARRAY[] = {
		NETMASK_DIGIT0,
		NETMASK_DIGIT1,
		NETMASK_DIGIT2,
		NETMASK_DIGIT3,
		NETMASK_DIGIT4,
		NETMASK_DIGIT5,
		NETMASK_DIGIT6,
		NETMASK_DIGIT7,
		NETMASK_DIGIT8
	};
	if (netmask_digits < 0 || netmask_digits > 32)
	{
		STATIC_WRITE_FORMAT_ERROR("The netmask digits[%d] is NOT in range [0, 32]", netmask_digits);
		return RET_FAILURE_INVALID_ARGUMENT;
	}

	int cnt = 0;
	while (cnt < 4)
	{
		if (netmask_digits >= 8)
		{
			ipv4_mask[cnt] = NETMASK_ARRAY[8];
			netmask_digits -= 8;
		}
		else
		{
			ipv4_mask[cnt] = NETMASK_ARRAY[netmask_digits];
			netmask_digits = 0;
		}
		cnt++;	
	}
	PRINT_IPV4("mask", mask);
	// printf("IPv4 mask:  ");
	// for (int i = 0 ; i < 4 ; i++)
	// 	printf("%d ", ipv4_mask[i]);
	// printf("\n");

	return RET_SUCCESS;
}

unsigned short IPv4Addr::get_network(const unsigned char ipv4_value[], int netmask_digits, unsigned char ipv4_network[])
{
	unsigned short ret = RET_SUCCESS;
	unsigned char netmask[4];
	ret = get_netmask(netmask_digits, netmask);
	if (CHECK_FAILURE(ret))
		return ret;
	for (int i = 0 ; i < 4 ; i++)
	{
		ipv4_network[i] = ipv4_value[i] & netmask[i];
	}
	PRINT_IPV4("network", network);
	// printf("IPv4 network:  ");
	// for (int i = 0 ; i < 4 ; i++)
	// 	printf("%d ", ipv4_network[i]);
	// printf("\n");

	return RET_SUCCESS;
}

IPv4Addr::IPv4Addr(unsigned char ipv4_value[]) :
	addr_str(NULL)
{
	memcpy(addr_value, ipv4_value, sizeof(unsigned char) * 4);
}

IPv4Addr::IPv4Addr(const char* ipv4_str) :
	addr_str(NULL)
{
	unsigned short ret = IPv4Addr::ipv4_str2value(ipv4_str, addr_value);
	if (CHECK_FAILURE(ret))
	{
		static int ERRMSG_SIZE = 64;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Incorrect IPv4 argument: %s", ipv4_str);
		throw invalid_argument(string(errmsg));		
	}
}

IPv4Addr::~IPv4Addr()
{
	if (addr_str != NULL)
	{
		delete[] addr_str;
		addr_str = NULL;
	}
}

bool IPv4Addr::is_same_network(int netmask_digits, unsigned char ipv4_network[])const
{
	unsigned char network_value[4];
	unsigned short ret = IPv4Addr::get_network(addr_value, netmask_digits, network_value);
	if (CHECK_FAILURE(ret))
		return ret;
	return (memcmp(network_value, ipv4_network, sizeof(unsigned char) * 4) == 0 ? true : false);
}

bool IPv4Addr::is_same_network(int netmask_digits, const char* ipv4_network_str)const
{
	unsigned short ret = RET_SUCCESS;
	unsigned char ipv4_network_value[4];
	ret = IPv4Addr::ipv4_str2value(ipv4_network_str, ipv4_network_value);
	if (CHECK_FAILURE(ret))
		return ret;
	return is_same_network(netmask_digits, ipv4_network_value);
}

//////////////////////////////////////////////////////////

ClusterNode::ClusterNode(int id, string ip)
{
	node_id = id;
	node_ip = ip;
}

bool ClusterNode::operator== (const ClusterNode &n)
{
	if (this == &n)
		return true;
	return node_id == n.node_id;
}

bool ClusterNode::operator== (const ClusterNode *p)
{
	assert(p != NULL && "p should NOT be NULL");
	return this->operator== (*p);
}

// bool operator== (const ClusterNode &n1, const ClusterNode &n2)
// {
// 	return n1.node_id == n2.node_id;
// }

// bool operator== (const ClusterNode* p1, const ClusterNode* p2)
// {
// 	assert(p1 != NULL && p2 != NULL && "p1/p2 should NOT be NULL");
// 	return operator== 	(*p1, *p2);
// }

void ClusterMap::reset_cluster_map_str()
{
	if (cluster_map_str != NULL)
	{
		free(cluster_map_str);
		cluster_map_str = NULL;
	}
}


ClusterMap::ClusterMap() :
	cluster_map_str(NULL)
{

}
	
ClusterMap::~ClusterMap()
{
	reset_cluster_map_str();
}

unsigned short ClusterMap::add_node(int node_id, std::string node_ip)
{
	ClusterNode* cluster_node = new ClusterNode(node_id, node_ip);
	if (cluster_node == NULL)
		throw bad_alloc();
	cluster_map.push_back(cluster_node);
	reset_cluster_map_str();
	return RET_SUCCESS;
}

unsigned short ClusterMap::add_node(const char* node_id_ip_str)
{
	assert(node_id_ip_str != NULL && "node_id_ip_str should NOT be NULL");
	char* node_id_ip_str_tmp = strdup(node_id_ip_str);
	char* str_ptr = node_id_ip_str_tmp;
	char* node_id_str = strtok(str_ptr, ",");
	char* node_ip_str = strtok(NULL, ",");
	unsigned short ret = add_node(atoi(node_id_str), string(node_ip_str));
	if (CHECK_FAILURE(ret))
		return ret;
	free(node_id_ip_str_tmp);
	return RET_SUCCESS;
}

unsigned short ClusterMap::delete_node(int node_id)
{
	ClusterNode delete_node(node_id, string(""));
// Does NOT work !!!
	// list<ClusterNode*>::iterator iter_find = find(cluster_map.begin(), cluster_map.end(), &delete_nodeClusterNode(node_id, string("")));
	// if (iter_find == cluster_map.end())
	// 	return RET_FAILURE_NOT_FOUND;
// Find the node to be deleted
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_id == node_id)
		{
// Delete the node
			delete cluster_node;
			cluster_map.erase(iter_find);
			found = true;
			break;
		}
		iter_find++;
	}
	if (!found)
		return RET_FAILURE_NOT_FOUND;
	reset_cluster_map_str();
	return RET_SUCCESS;
}

unsigned short ClusterMap::delete_node_by_ip(std::string node_ip)
{
	unsigned short ret = RET_SUCCESS;
	int node_id;
	ret = get_node_id(node_ip, node_id);
	if (CHECK_FAILURE(ret))
		return ret;
	return delete_node(node_id);
}

unsigned short ClusterMap::pop_node(ClusterNode** first_node)
{
// Caution: cluster_node should be released outside
	assert(first_node != NULL && "first_node should NOT be NULL");
	if (cluster_map.empty())
		return RET_FAILURE_INCORRECT_OPERATION;
	list<ClusterNode*>::iterator iter_head = cluster_map.begin();
	ClusterNode* cluster_node = (ClusterNode*)*iter_head;
	cluster_map.erase(iter_head);
	reset_cluster_map_str();
	*first_node = cluster_node;
	return RET_SUCCESS;
}

unsigned short ClusterMap::cleanup_node()
{
	if (cluster_map.empty())
		return RET_SUCCESS;
	list<ClusterNode*>::iterator iter = cluster_map.begin();
	while (iter != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter;
		iter++;
		delete cluster_node;
	}
	cluster_map.clear();
	reset_cluster_map_str();
	return RET_SUCCESS;
}


unsigned short ClusterMap::get_first_node_ip(string& first_node_ip, bool peek_only)
{
	unsigned short ret = RET_SUCCESS;
	if (peek_only)
	{
		if (cluster_map.empty())
			return RET_FAILURE_INCORRECT_OPERATION;
		list<ClusterNode*>::iterator iter = cluster_map.begin();
		ClusterNode* cluster_node = (ClusterNode*)*iter;
		first_node_ip = cluster_node->node_ip;
	}
	else
	{
		ClusterNode* first_node = NULL;
		ret = pop_node(&first_node);
		if (CHECK_FAILURE(ret))
			return ret;
		first_node_ip = first_node->node_ip;
		delete first_node;

	}
	return RET_SUCCESS;
}

unsigned short ClusterMap::get_node_id(const std::string& node_ip, int& node_id)
{
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_ip == node_ip)
		{
			node_id = cluster_node->node_id;
			found = true;
			break;
		}
		iter_find++;
	}
	if (!found)
		return RET_FAILURE_NOT_FOUND;
	return RET_SUCCESS;
}

const char* ClusterMap::to_string()
{
	if (cluster_map_str == NULL)
	{
		string total_str;
		static const int BUF_SIZE = 64;
		char buf[BUF_SIZE];
		list<ClusterNode*>::iterator iter = cluster_map.begin();
		while (iter != cluster_map.end())
		{
			ClusterNode* cluster_node = (ClusterNode*)*iter;
			snprintf(buf, BUF_SIZE, "%d:%s", cluster_node->node_id, cluster_node->node_ip.c_str());
			if (!total_str.empty())
				total_str += ",";
			total_str += buf;
			iter++;
		}
		cluster_map_str = strdup(total_str.c_str());	
	}
	return cluster_map_str;
}

unsigned short ClusterMap::from_string(const char* cluster_map_str)
{
// cluster_map_str format:
// 0:192.17.30.217;1:192.17.30.218;2:192.17.30.219
	assert(cluster_map_str != NULL && "cluster_map_str should NOT be NULL");
	unsigned short ret = cleanup_node();
	if (CHECK_FAILURE(ret))
		return ret;
	char* cluster_map_str_tmp = strdup(cluster_map_str);
	char* cluster_map_str_ptr = cluster_map_str_tmp;
	char* cluster_map_str_rest;
	char* cluster_node_id_ip;
	while((cluster_node_id_ip=strtok_r(cluster_map_str_ptr, ";", &cluster_map_str_rest)) != NULL)
	{
		char* cluster_node_str_rest;
		char* cluster_node_id = strtok_r(cluster_node_id_ip, ":", &cluster_node_str_rest);
		char* cluster_node_ip = strtok_r(NULL, ":", &cluster_node_str_rest);
		ret = add_node(atoi(cluster_node_id), string(cluster_node_ip));
		if (CHECK_FAILURE(ret))
			return ret;
		cluster_map_str_ptr = NULL;
	}

	if (cluster_map_str_tmp != NULL)
	{
		free(cluster_map_str_tmp);
		cluster_map_str_tmp = NULL;
	}
	return RET_SUCCESS;
}

KeepaliveTimerTask::KeepaliveTimerTask()
{
//	IMPLEMENT_MSG_DUMPER()
}

KeepaliveTimerTask::~KeepaliveTimerTask()
{
//	RELEASE_MSG_DUMPER()
}

unsigned short KeepaliveTimerTask::initialize(PIMSG_NOTIFY_OBSERVER observer)
{
	msg_notify_observer = observer;

	return RET_SUCCESS;
}

unsigned short KeepaliveTimerTask::deinitialize()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer = NULL;

	return RET_SUCCESS;
}

void KeepaliveTimerTask::trigger()
{
	if (msg_notify_observer != NULL)
		msg_notify_observer->notify(NOTIFY_CHECK_KEEPALIVE);
}

