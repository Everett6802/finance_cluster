#include <assert.h>
#include <signal.h>
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

#ifdef DEBUG
#define PRINT_ERROR(format, ...)\
do{\
	fprintf(stderr, format, __VA_ARGS__);
}while(0);
#else
#define PRINT_ERROR(format, ...)
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

NodeMessageAssembler::NodeMessageAssembler() :
	full_message_buf(NULL)
{
}

NodeMessageAssembler::~NodeMessageAssembler()
{
	if (full_message_buf != NULL)
	{
		delete[] full_message_buf;
		full_message_buf = NULL;
	}
}

unsigned short NodeMessageAssembler::assemble(MessageType message_type, const char* message)
{
	if (full_message_buf != NULL)
		return RET_FAILURE_INCORRECT_OPERATION;

	int buf_size = MESSAGE_TYPE_LEN + (message != NULL ? strlen(message) : 0) + END_OF_MESSAGE_LEN + 1;
	full_message_buf = new char[buf_size];
	if (full_message_buf == NULL)
		return RET_FAILURE_INSUFFICIENT_MEMORY;

	if (message != NULL)
	{
		snprintf(full_message_buf, buf_size, "%c%s%s", message_type, message, END_OF_MESSAGE.c_str());
	}
	else
	{
		snprintf(full_message_buf, buf_size, "%c%s", message_type, END_OF_MESSAGE.c_str());
	}
	return RET_SUCCESS;
}

const char* NodeMessageAssembler::get_full_message()const
{
	if (full_message_buf == NULL)
		throw runtime_error("node_message_type should be NodeMessage_Assemble");
	return full_message_buf;
}

NodeMessageParser::NodeMessageParser() :
	full_message_found(false)
{
}

NodeMessageParser::~NodeMessageParser(){}

unsigned short NodeMessageParser::parse(const char* new_message)
{
	if (full_message_found)
	{
		PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
    if (new_message == NULL)
    {
    	PRINT_ERROR("%s", "invalid Argument: new_message should NOT be NULL\n");
    	return RET_FAILURE_INVALID_ARGUMENT;
    }

	data_buffer += string(new_message);
// Check if the data is completely sent from the remote site
	data_end_pos = data_buffer.find(END_OF_MESSAGE);
	if (data_end_pos == string::npos)
		return RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE;
// Parse the content of the full message
	message_type = (MessageType)data_buffer.front();
	if (message_type < 0 || message_type >= MSG_SIZE)
	{
		// static int char ERRMSG_SIZE = 256;
		// char errmsg[ERRMSG_SIZE];
		// snprintf(errmsg, ERRMSG_SIZE, "The message type[%d] is NOT in range [0, %d)", message_type, MSG_SIZE);
		// throw out_of_range(errmsg);
		PRINT_ERROR("The message type[%d] is NOT in range [0, %d)\n", message_type, MSG_SIZE);
		return RET_FAILURE_RUNTIME;	
	}
	full_message_found = true;
	return RET_SUCCESS;
}

unsigned short NodeMessageParser::remove_old()
{
	if (!full_message_found)
	{
		PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	data_buffer = data_buffer.substr(data_end_pos + END_OF_MESSAGE_LEN);
	full_message_found = false;
	return RET_SUCCESS;
}

bool NodeMessageParser::is_cur_message_empty()const
{
	return data_buffer.empty();
}

const char* NodeMessageParser::cur_get_message()const
{
	return data_buffer.c_str();
}

const char* NodeMessageParser::get_message()const
{
	assert(full_message_found && "Incorrect Operation: full_message_found should NOT be True");
	// if (!full_message_found)
	// {
	// 	PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
	// 	return RET_FAILURE_INCORRECT_OPERATION;
	// }
	return data_buffer.substr(1, data_end_pos - 1).c_str();
}

MessageType NodeMessageParser::get_message_type()const
{
	assert(full_message_found && "Incorrect Operation: full_message_found should NOT be True");
	// if (!full_message_found)
	// {
	// 	PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
	// 	return RET_FAILURE_INCORRECT_OPERATION;
	// }
	return message_type;	
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


ClusterMap::const_iterator::const_iterator(CLUSTER_NODE_ITER iterator) : iter(iterator){}

ClusterMap::const_iterator ClusterMap::const_iterator::operator++()
{
	++iter;
	return *this;
}

bool ClusterMap::const_iterator::operator==(const const_iterator& another)
{
	if (this == &another)
		return true;
	return iter == another.iter;
}


bool ClusterMap::const_iterator::operator!=(const const_iterator& another)
{
	// if (this == &another)
	// 	return true;
	// return iter == another.iter;
	return !this->operator==(another);
}

const ClusterNode* ClusterMap::const_iterator::operator->()
{
	return (PCLUSTER_NODE)(*iter);
}

const ClusterNode& ClusterMap::const_iterator::operator*()
{
	return *((PCLUSTER_NODE)(*iter));
}

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

ClusterMap::const_iterator ClusterMap::begin() 
{
	return const_iterator(cluster_map.begin());
}

ClusterMap::const_iterator ClusterMap::end() 
{
	return const_iterator(cluster_map.end());
}

bool ClusterMap::is_empty()const
{
	return cluster_map.empty();
}

unsigned short ClusterMap::copy(const ClusterMap& another_cluster_map)
{
	unsigned short ret = RET_SUCCESS;
	ret = cleanup_node();
	if (CHECK_FAILURE(ret))
		return ret;
	list<ClusterNode*>::const_iterator iter = another_cluster_map.cluster_map.begin();
	while (iter != another_cluster_map.cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter;
		iter++;
		// fprintf(stderr, "id: %d, ip: %s, %d\n", cluster_node->node_id, cluster_node->node_ip.c_str(), strlen(cluster_node->node_ip.c_str()));
		ret = add_node(cluster_node->node_id, cluster_node->node_ip);
		if (CHECK_FAILURE(ret))
			break;
	}
	return ret;
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

unsigned short ClusterMap::get_first_node(int& first_node_id, string& first_node_ip, bool peek_only)
{
	unsigned short ret = RET_SUCCESS;
	if (peek_only)
	{
		if (cluster_map.empty())
			return RET_FAILURE_INCORRECT_OPERATION;
		list<ClusterNode*>::iterator iter = cluster_map.begin();
		ClusterNode* cluster_node = (ClusterNode*)*iter;
		first_node_id = cluster_node->node_id;
		first_node_ip = cluster_node->node_ip;
	}
	else
	{
		ClusterNode* first_node = NULL;
		ret = pop_node(&first_node);
		if (CHECK_FAILURE(ret))
			return ret;
		first_node_id = first_node->node_id;
		first_node_ip = first_node->node_ip;
		delete first_node;

	}
	return RET_SUCCESS;
}

unsigned short ClusterMap::get_first_node_ip(string& first_node_ip, bool peek_only)
{
	int first_node_id;
	return get_first_node(first_node_id, first_node_ip, peek_only);
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

unsigned short ClusterMap::get_last_node_id(int& node_id)
{
	// unsigned short ret = RET_SUCCESS;
    if (cluster_map.empty())
		return RET_FAILURE_INCORRECT_OPERATION;
	list<ClusterNode*>::reverse_iterator iter = cluster_map.rbegin();
    ClusterNode* cluster_node = (ClusterNode*)*iter;
    assert(cluster_node != NULL && "cluster_node should NOT be NULL");
    node_id = cluster_node->node_id;
	return RET_SUCCESS;
}

unsigned short ClusterMap::get_node_ip(int node_id, std::string& node_ip)
{
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_id == node_id)
		{
			node_ip = cluster_node->node_ip;
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
	// fprintf(stderr, "ClusterMap::from_string %s, %d\n", cluster_map_str_tmp, strlen(cluster_map_str_tmp));
	char* cluster_map_str_ptr = cluster_map_str_tmp;
	char* cluster_map_str_rest;
	char* cluster_node_id_ip;
	while((cluster_node_id_ip=strtok_r(cluster_map_str_ptr, ",", &cluster_map_str_rest)) != NULL)
	{
		char* cluster_node_str_rest;
		char* cluster_node_id = strtok_r(cluster_node_id_ip, ":", &cluster_node_str_rest);
		char* cluster_node_ip = strtok_r(NULL, ":", &cluster_node_str_rest);
		// fprintf(stderr, "ClusterMap::from_string id: %d, ip: %s, %d\n", cluster_node_id, cluster_node_ip, strlen(cluster_node_ip));
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

// unsigned short ClusterMap::from_object(const ClusterMap& cluster_map_obj)
// {
// // cluster_map_str format:
// // 0:192.17.30.217;1:192.17.30.218;2:192.17.30.219
// 	return cluster_map_obj.from_string(to_string());
// }

//////////////////////////////////////////////////////////

KeepaliveTimerTask::KeepaliveTimerTask()
{
//	IMPLEMENT_MSG_DUMPER()
}

KeepaliveTimerTask::~KeepaliveTimerTask()
{
//	RELEASE_MSG_DUMPER()
}

unsigned short KeepaliveTimerTask::initialize(PINOTIFY observer)
{
	notify_observer = observer;
	return RET_SUCCESS;
}

unsigned short KeepaliveTimerTask::deinitialize()
{
	if (notify_observer != NULL)
		notify_observer = NULL;
	return RET_SUCCESS;
}

unsigned short KeepaliveTimerTask::trigger()
{
	if (notify_observer != NULL)
		return notify_observer->notify(NOTIFY_CHECK_KEEPALIVE);
	return RET_FAILURE_INCORRECT_OPERATION;
}

//////////////////////////////////////////////////////////

ClusterDetailParam::ClusterDetailParam(){}
ClusterDetailParam::~ClusterDetailParam(){}

///////////////////
// const int SystemInfoParam::NODE_IP_BUF_SIZE = 16;

SystemInfoParam::SystemInfoParam()
{
	memset(node_ip_buf, 0x0, sizeof(char) * DEF_VERY_SHORT_STRING_SIZE);
}
SystemInfoParam::~SystemInfoParam(){}

//////////////////////////////////////////////////////////

NotifyCfg::NotifyCfg(NotifyType type, const void* param, size_t param_size) :
	notify_type(type),
	notify_param(NULL),
	ref_count(0)
{
	// printf("NotifyCfg()\n");
	addref(__FILE__, __LINE__);
	if (param != NULL)
	{
		// printf("NotifyCfg()::malloc\n");
		assert(param_size != 0 && "param_size should NOT be 0");
		notify_param = malloc(param_size);
		if (notify_param == NULL)
			throw bad_alloc();
		memcpy(notify_param, param, param_size);
		// printf("param: %d, notify_param: %d\n", *(FakeAcsptControlType*)param, *(FakeAcsptControlType*)notify_param);
	}
}

NotifyCfg::~NotifyCfg()
{
	// printf("~NotifyCfg()\n");
	// assert(notify_param != NULL && "notify_param should be NULL");
	if (notify_param != NULL)
	{
		// printf("~NotifyCfg():free\n");
/*
When allocating memory, the runtime library keeps track of 
the size of each allocation. When you call free(), 
it looks up the address, and if it finds an allocation for that 
address, the correct amount of memory is freed 
*/
		free(notify_param);
		notify_param = NULL;
	}
}

int NotifyCfg::addref(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_add(&ref_count, 1);
	// printf("addref() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	return ref_count;
}

int NotifyCfg::release(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_sub(&ref_count, 1);
	// printf("release() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	assert(ref_count >= 0 && "ref_count should NOT be smaller than 0");
	if (ref_count == 0)
	{
		delete this;
		return 0;
	}

	return ref_count;
}

int NotifyCfg::getref()const
{
	return ref_count;
}

NotifyType NotifyCfg::get_notify_type()const{return notify_type;}

const void* NotifyCfg::get_notify_param()const{return notify_param;}

///////////////////////////

NotifyNodeDieCfg::NotifyNodeDieCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_NODE_DIE, param, param_size)
{
	// printf("NotifyNodeDieCfg()\n");
	// fprintf(stderr, "NotifyNodeDieCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	remote_ip = (char*)notify_param;
}

NotifyNodeDieCfg::~NotifyNodeDieCfg()
{
	remote_ip = NULL;
	// printf("~NotifyNodeDieCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_node_die_param = (char*)notify_param;
	// 	free(notify_node_die_param);
	// 	notify_param = NULL;
	// }
}

const char* NotifyNodeDieCfg::get_remote_ip()const
{
	return remote_ip;
}

///////////////////////////

NotifySessionExitCfg::NotifySessionExitCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_SESSION_EXIT, param, param_size)
{
	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	session_id = *(int*)notify_param;
}

NotifySessionExitCfg::~NotifySessionExitCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	int* notify_session_exit_param = (int*)notify_param;
	// 	free(notify_session_exit_param);
	// 	notify_param = NULL;
	// }
}

int NotifySessionExitCfg::get_session_id()const
{
	return session_id;
}

///////////////////////////

NotifySystemInfoCfg::NotifySystemInfoCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_SYSTEM_INFO, param, param_size)
{
// session ID[2 digits]|system info
	// fprintf(stderr, "NotifySessionExitCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
	static const int SESSION_ID_BUF_SIZE = PAYLOAD_SYSTEM_INFO_SESSION_ID_DIGITS + 1;
// De-Serialize: convert the type of session id from string to integer  
	char session_id_buf[SESSION_ID_BUF_SIZE];
	memset(session_id_buf, 0x0, sizeof(char) * SESSION_ID_BUF_SIZE);
	memcpy(session_id_buf, notify_param, sizeof(char) * PAYLOAD_SYSTEM_INFO_SESSION_ID_DIGITS);
	session_id = atoi(session_id_buf);

	const char* param_char = (const char*)notify_param;
	system_info = (char*)(param_char + PAYLOAD_SYSTEM_INFO_SESSION_ID_DIGITS);
	if (strlen(system_info) == 0)
		system_info = NULL;
	// fprintf(stderr, "NotifySystemInfoCfg, session id: %d, system_info: %s\n", session_id, system_info);
}

NotifySystemInfoCfg::~NotifySystemInfoCfg()
{
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_system_info_param = (char*)notify_param;
	// 	free(notify_system_info_param);
	// 	notify_param = NULL;
	// }
}

int NotifySystemInfoCfg::get_session_id()const
{
	return session_id;
}

const char* NotifySystemInfoCfg::get_system_info()const
{
	return system_info;
}

///////////////////////////

NotifyFakeAcsptControlCfg::NotifyFakeAcsptControlCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_CONTROL_FAKE_ACSPT, param, param_size)
{
	// printf("NotifyFakeAcsptControlCfg()\n");
	// fprintf(stderr, "NotifyFakeAcsptControlCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize: convert the type of session id from string to integer  
	fake_acspt_control_type = *(FakeAcsptControlType*)notify_param;
	// printf("NotifyFakeAcsptControlCfg::fake_acspt_control_type: %d\n", fake_acspt_control_type);
}

NotifyFakeAcsptControlCfg::~NotifyFakeAcsptControlCfg()
{
	// printf("~NotifyFakeAcsptControlCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_fake_acspt_control_param = (char*)notify_param;
	// 	free(notify_fake_acspt_control_param);
	// 	notify_param = NULL;
	// }
}

FakeAcsptControlType NotifyFakeAcsptControlCfg::get_fake_acspt_control_type()const
{
	return fake_acspt_control_type;
}

///////////////////////////

NotifyFakeUsreptControlCfg::NotifyFakeUsreptControlCfg(const void* param, size_t param_size) :
	NotifyCfg(NOTIFY_CONTROL_FAKE_USREPT, param, param_size)
{
	// printf("NotifyFakeAcsptControlCfg()\n");
	// fprintf(stderr, "NotifyFakeAcsptControlCfg: param:%s, param_size: %d\n", (char*)param, param_size);
	assert(param != NULL && "param should NOT be NULL");
// De-Serialize: convert the type of session id from string to integer  
	fake_usrept_control_type = *(FakeUsreptControlType*)notify_param;
	// printf("NotifyFakeAcsptControlCfg::fake_acspt_control_type: %d\n", fake_acspt_control_type);
}

NotifyFakeUsreptControlCfg::~NotifyFakeUsreptControlCfg()
{
	// printf("~NotifyFakeAcsptControlCfg()\n");
// No need, since the base destructor is virtual
	// if(notify_param != NULL)
	// {
	// 	char* notify_fake_acspt_control_param = (char*)notify_param;
	// 	free(notify_fake_acspt_control_param);
	// 	notify_param = NULL;
	// }
}

FakeUsreptControlType NotifyFakeUsreptControlCfg::get_fake_usrept_control_type()const
{
	return fake_usrept_control_type;
}

//////////////////////////////////////////////////////////

const char* NotifyThread::default_notify_thread_tag = "Notify Thread";

void* NotifyThread::notify_thread_handler(void* pvoid)
{
	// fprintf(stderr, "notify_thread_handler is invokded !!!\n");
	NotifyThread* pthis = (NotifyThread*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
	int setcancelstate_ret;
    if ((setcancelstate_ret=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->notify_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    int setcanceltype_ret;
    if ((setcanceltype_ret=pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->notify_thread_ret = RET_FAILURE_SYSTEM_API;
	}
// Call the thread handler function to run the thread
	if (CHECK_SUCCESS(pthis->notify_thread_ret))
	{
		pthread_cleanup_push(notify_thread_cleanup_handler, pthis);
		pthis->notify_thread_ret = pthis->notify_thread_handler_internal();
		pthread_cleanup_pop(1);
	}
	else
	{
		STATIC_WRITE_FORMAT_ERROR("The event thread is NOT running properly, due to: %s", GetErrorDescription(pthis->notify_thread_ret));
	}
// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->notify_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->notify_thread_ret)));
	pthread_exit(NULL);
}

unsigned short NotifyThread::notify_thread_handler_internal()
{
	assert(notify_observer != NULL && "notify_observer should NOT be NULL");
	WRITE_FORMAT_INFO("[%s] The worker thread of notifying event is running", notify_thread_tag);
	unsigned short ret = RET_SUCCESS;
	while (notify_exit == 0)
	{
		pthread_mutex_lock(&notify_mtx);
//wait for the signal with cond as condition variable
		if (!new_notify_trigger)
		{
			pthread_cond_wait(&notify_cond, &notify_mtx);
		}
		// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_STRING_SIZE, "Thread[%s]=> The worker thread to write the data......", worker_thread_name);
// Move the message
		int notify_buffer_vector_size = notify_buffer_vector.size();
//		WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_LONG_STRING_SIZE, "Thread[%s]=> There are totally %d data in the queue", worker_thread_name, notify_buffer_vector_size);
		if (notify_buffer_vector_size > 0)
		{
			for (int i = 0 ; i < notify_buffer_vector_size ; i++)
			{
//				WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_LONG_STRING_SIZE, "Thread[%s]=> Move the message[%s] to another buffer", worker_thread_name, notify_buffer_vector[i]->data);
				PNOTIFY_CFG notify_cfg =  notify_buffer_vector[i];
				notify_buffer_vector[i] = NULL;
				notify_execute_vector.push_back(notify_cfg);
			}
// Clean-up the container
			notify_buffer_vector.clear();
		}
		new_notify_trigger = false;
		pthread_mutex_unlock(&notify_mtx);
	
		int notify_execute_vector_size = notify_execute_vector.size();
		if (notify_execute_vector_size > 0)
		{
// execute the notification
			for (int i = 0 ; i < notify_execute_vector_size ; i++)
			{
				PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_execute_vector[i];
				assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
				notify_execute_vector[i] = NULL;
				WRITE_FORMAT_DEBUG("Handle asynchronous event: %d", notify_cfg->get_notify_type());
				ret = notify_observer->async_handle(notify_cfg);
// Remove the old notification
				// delete notify_cfg;
				SAFE_RELEASE(notify_cfg);			
				if (CHECK_FAILURE(ret))
				{
					WRITE_FORMAT_DEBUG("Thread[%s]=> Fail to execute event, due to %d", notify_thread_tag, ret);
					break;
				}
			}
			notify_execute_vector.clear();
		}	
	}


	WRITE_FORMAT_INFO("[%s] The worker thread of notifying socket is dead", notify_thread_tag);
	return ret;
}

void NotifyThread::notify_thread_cleanup_handler(void* pvoid)
{
	NotifyThread* pthis = (NotifyThread*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->notify_thread_cleanup_handler_internal();
}

void NotifyThread::notify_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the notify thread......", notify_thread_tag);
	int notify_buffer_vector_size = notify_buffer_vector.size();
	if (notify_buffer_vector_size > 0)
	{
		for (int i = 0 ; i < notify_buffer_vector_size ; i++)
		{
			delete notify_buffer_vector[i];
			notify_buffer_vector[i] = NULL;
		}
		notify_buffer_vector.clear();
	}
	int notify_execute_vector_size = notify_execute_vector.size();
	if (notify_execute_vector_size > 0)
	{
		for (int i = 0 ; i < notify_execute_vector_size ; i++)
		{
			delete notify_execute_vector[i];
			notify_execute_vector[i] = NULL;
		}
		notify_execute_vector.clear();
	}
}

NotifyThread::NotifyThread(PINOTIFY observer, const char* thread_tag) :
	notify_observer(observer),
	notify_exit(0),
	notify_tid(0),
	notify_thread_ret(RET_SUCCESS),
	new_notify_trigger(false)
{
	IMPLEMENT_MSG_DUMPER()
	if (thread_tag == NULL)
		notify_thread_tag = strdup(default_notify_thread_tag);
	else
		notify_thread_tag = strdup(thread_tag);
}

NotifyThread::~NotifyThread()
{
	if (notify_thread_tag != NULL)
	{
		free(notify_thread_tag);
		notify_thread_tag = NULL;
	}
	if (notify_observer != NULL)
		notify_observer = NULL;

	RELEASE_MSG_DUMPER()
}

unsigned short NotifyThread::initialize()
{
	notify_mtx = PTHREAD_MUTEX_INITIALIZER;
	notify_cond = PTHREAD_COND_INITIALIZER;
	// fprintf(stderr, "[%s]Nofity Thread is initialized\n", notify_thread_tag);
	if (pthread_create(&notify_tid, NULL, notify_thread_handler, this) != 0)
	{
		// fprintf(stderr, "[%s]Nofity Thread is initialized1\n", notify_thread_tag);
		WRITE_FORMAT_ERROR("Fail to create a worker thread of notifying event, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}
	// fprintf(stderr, "[%s]Nofity Thread[%d] is initialized2\n", notify_thread_tag, notify_tid);
	return RET_SUCCESS;
}

unsigned short NotifyThread::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	// void* status;
// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&notify_exit, 1);
	// sleep(1);
	usleep(100000);
// Check notify thread alive
	// bool notify_thread_alive = false;
	if (notify_tid != 0)
	{
		int kill_ret = pthread_kill(notify_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of notifying did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of notifying is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker thread of notifying is STILL alive");
			// notify_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(notify_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of receving message, due to: %s", strerror(errno));
			// sleep(1);
			usleep(100000);
		}
	}

	WRITE_DEBUG("Wait for the worker thread of notifying's death...");
// Wait for notify thread's death
	pthread_join(notify_tid, NULL);
	if (CHECK_SUCCESS(notify_thread_ret))
		WRITE_DEBUG("Wait for the worker thread of notifying's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of notifying's death, due to: %s", GetErrorDescription(notify_thread_ret));
		ret = notify_thread_ret;
	}

	return ret;
}

unsigned short NotifyThread::add_event(const PNOTIFY_CFG notify_cfg)
{
	// WRITE_DEBUG_FORMAT_SYSLOG(MSG_DUMPER_LONG_STRING_SIZE, "Write message [severity: %d, message: %s]", severity, msg);
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
	notify_cfg->addref(__FILE__, __LINE__);
	pthread_mutex_lock(&notify_mtx);
	notify_buffer_vector.push_back(notify_cfg);
// Wake up waiting thread with condition variable, if it is called before this function
	if (!new_notify_trigger)
	{
		pthread_cond_signal(&notify_cond);
	}
	new_notify_trigger = true;
	pthread_mutex_unlock(&notify_mtx);
	return RET_SUCCESS;
}
