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
	message_buf_size(0),
	message_buf(NULL)
{
}

NodeMessageAssembler::~NodeMessageAssembler()
{
	message_buf_size = 0;
	if (message_buf != NULL)
	{
		delete[] message_buf;
		message_buf = NULL;
	}
}

unsigned short NodeMessageAssembler::assemble(MessageType message_type, const char* message, unsigned int message_size)
{
	if (message_buf != NULL)
		return RET_FAILURE_INCORRECT_OPERATION;
	if (message_size != 0 && message == NULL)
		return RET_FAILURE_INVALID_ARGUMENT;
	else if (message_size == 0 && message != NULL)
		return RET_FAILURE_INVALID_ARGUMENT;
// // Caution: Should NOT always handle the data like a string. If the first character of the message is 0, for example, 
// // strlen() will return the wrong value
// 	if (message_size == -1)
// 		message_size = (message != NULL ? strlen(message) : 0);

// Format:  message_type | message_size | message | End Of message
	message_buf_size = MESSAGE_TYPE_LEN + MESSAGE_SIZE_LEN + message_size + END_OF_MESSAGE_LEN;
	message_buf = new char[message_buf_size];
	if (message_buf == NULL)
		return RET_FAILURE_INSUFFICIENT_MEMORY;
	// if (message_size == -1)
	// {
	// 	if (message != NULL)
	// 		snprintf(message_buf, buf_size, "%c%s%s", message_type, message, END_OF_MESSAGE.c_str());
	// 	else
	// 		snprintf(message_buf, buf_size, "%c%s", message_type, END_OF_MESSAGE.c_str());
	// }
	// else
	// {
	// 	memset(message_buf, 0x0, sizeof(char) * buf_size);
	// 	char* message_buf_ptr = message_buf;
	// 	memcpy(message_buf_ptr, (void*)&message_type, sizeof(char));
	// 	message_buf_ptr += 1;
	// 	memcpy(message_buf_ptr, (void*)message, sizeof(char) * message_size);
	// 	message_buf_ptr += message_size;
	// 	memcpy(message_buf_ptr, (void*)END_OF_MESSAGE.c_str(), sizeof(char) * END_OF_MESSAGE_LEN);
	// }
	// memcpy(message_buf_ptr, (void*)END_OF_MESSAGE.c_str(), sizeof(char) * END_OF_MESSAGE_LEN);
	// fprintf(stderr, "message_buf_size: %d, MESSAGE_TYPE_LEN: %d, MESSAGE_SIZE_LEN: %d, END_OF_MESSAGE_LEN: %d\n", message_buf_size, MESSAGE_TYPE_LEN, MESSAGE_SIZE_LEN, END_OF_MESSAGE_LEN);
	memset(message_buf, 0x0, sizeof(char) * message_buf_size);
	char* message_buf_ptr = message_buf;
	memcpy(message_buf_ptr, (void*)&message_type, MESSAGE_TYPE_LEN);
	message_buf_ptr += MESSAGE_TYPE_LEN;
	memcpy(message_buf_ptr, (void*)&message_size, MESSAGE_SIZE_LEN);
	message_buf_ptr += MESSAGE_SIZE_LEN;
	if (message_size != 0)
	{
		memcpy(message_buf_ptr, (void*)message, sizeof(char) * message_size);
		message_buf_ptr += message_size;
	}
	memcpy(message_buf_ptr, (void*)END_OF_MESSAGE, sizeof(char) * END_OF_MESSAGE_LEN);
	// message_buf_ptr += END_OF_MESSAGE_LEN;
	// fprintf(stderr, "message_type: %d, message_size: %d, %d\n", message_type, message_size, message_buf_ptr - message_buf);

	return RET_SUCCESS;
}

unsigned int NodeMessageAssembler::get_message_size()const
{
	if (message_buf_size == 0)
		throw runtime_error("message_buf_size should NOT be 0");
	return message_buf_size;
}

const char* NodeMessageAssembler::get_message()const
{
	if (message_buf == NULL)
		throw runtime_error("message_buf should NOT be NULL");
	return message_buf;
}

//////////////////////////////////////////////////////////

NodeMessageParser::NodeMessageParser() :
	full_message_found(false),
	buf_index(0),
	message(NULL)
{
	buf_size = DEF_LONG_STRING_SIZE;
	buf = (char*)malloc(sizeof(char) * buf_size);
	if (buf == NULL)
		throw bad_alloc();
}

NodeMessageParser::~NodeMessageParser()
{
	if (message != NULL)
		message = NULL;
	if (buf != NULL)
	{
		free(buf);
		buf = NULL;
	}
	buf_size = buf_index = 0;
}

unsigned short NodeMessageParser::add(const char* data, unsigned int data_size)
{
	if (full_message_found)
	{
		PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
    if (data == NULL)
    {
    	PRINT_ERROR("%s", "invalid Argument: data should NOT be NULL\n");
    	return RET_FAILURE_INVALID_ARGUMENT;
    }
// Check if the buffer capacity is insufficient
    if (buf_index + data_size >= buf_size)
    {
    	buf_size <<= 1;
    	char* buf_tmp = buf;
    	buf = (char*)realloc(buf_tmp, sizeof(char) * buf_size);
	 	if (buf == NULL)
			throw bad_alloc();
    }
    memcpy(&buf[buf_index], data, sizeof(char) * data_size);
    buf_index += data_size;

	// data_buffer += string(new_message);
	// // fprintf(stderr, "data_buffer: %s\n", data_buffer.c_str());
	return RET_SUCCESS;
}

unsigned short NodeMessageParser::check_completion()
{
// Check if the data is completely sent from the remote site
	// data_end_pos = data_buffer.find(END_OF_MESSAGE);
	// if (data_end_pos == string::npos)
	// char* message_end_ptr = strstr(buf, END_OF_MESSAGE);
	// if (message_end_ptr == NULL)
	// 	return RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE;
	bool check_end_of_message = false;
	int message_end_index;
	for (int i = buf_index ; i >= END_OF_MESSAGE_LEN ; i--)
	{
		if (memcmp(&buf[i - END_OF_MESSAGE_LEN], END_OF_MESSAGE, sizeof(char) * END_OF_MESSAGE_LEN) == 0)
		{
			check_end_of_message = true;
			message_end_index = i - END_OF_MESSAGE_LEN;
			break;
		}
	}
	if (!check_end_of_message)
		return RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE;
// Parse the content of the full message
	int message_index = 0;
// Parse message_type
	// message_type = (MessageType)data_buffer.front();
	char message_type_tmp;
	memcpy(&message_type_tmp, &buf[message_index], MESSAGE_TYPE_LEN);
	message_index += MESSAGE_TYPE_LEN;
	message_type = (MessageType)message_type_tmp;
	if (message_type < 0 || message_type >= MSG_SIZE)
	{
		// static int char ERRMSG_SIZE = 256;
		// char errmsg[ERRMSG_SIZE];
		// snprintf(errmsg, ERRMSG_SIZE, "The message type[%d] is NOT in range [0, %d)", message_type, MSG_SIZE);
		// throw out_of_range(errmsg);
		PRINT_ERROR("The message type[%d] is NOT in range [0, %d)\n", message_type, MSG_SIZE);
		return RET_FAILURE_RUNTIME;	
	}
// Parse message_size
	unsigned int message_size_tmp;
	memcpy(&message_size_tmp, &buf[message_index], MESSAGE_SIZE_LEN);
	message_index += MESSAGE_SIZE_LEN;
	message_size = message_size_tmp;
// Parse message
	// if (message != NULL)
	// {
	// 	free(message);
	// 	message = NULL;
	// }
	// // message = strdup(data_buffer.substr(1, data_end_pos - 1).c_str());
	// int message_size_in_buf = message_end_ptr - (buf + message_index);
	unsigned int message_size_in_buf = message_end_index - message_index;
	if (message_size != message_size_in_buf)
	{
		PRINT_ERROR("The message size is incorrect, message_size: %d, message_size_in_buf: %d\n", message_size, message_size_in_buf);
		return RET_FAILURE_RUNTIME;			
	}
	// message = new char[message_size];
	// if (message == NULL)
	// 	throw bad_alloc();
	// memcpy(message, &buf[message_index], sizeof(char) * message_size);
	message = &buf[message_index];

	full_message_found = true;
#if 0
	fprintf(stderr, "get_message() => data_buffer: %s\n", data_buffer.c_str());
	fprintf(stderr, "get_message() => data_end_pos: %d\n", data_end_pos);
	fprintf(stderr, "get_message() => message: %s\n", data_buffer.substr(1, data_end_pos - 1).c_str());
	fprintf(stderr, "get_message() => message len: %d\n", strlen(data_buffer.substr(1, data_end_pos - 1).c_str()));
	fprintf(stderr, "message_type: %d, message: %s\n", get_message_type(), get_message());
#endif
	return RET_SUCCESS;
}

unsigned short NodeMessageParser::parse(const char* data, unsigned int data_size)
{
	unsigned short ret = RET_SUCCESS;
	ret = add(data, data_size);
	if (CHECK_FAILURE(ret))
		return ret;
	ret = check_completion();
	return ret;
}

unsigned short NodeMessageParser::remove_old()
{
	if (!full_message_found)
	{
		PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
		return RET_FAILURE_INCORRECT_OPERATION;
	}
	// data_buffer = data_buffer.substr(data_end_pos + END_OF_MESSAGE_LEN);
	int message_index = MESSAGE_TYPE_LEN + MESSAGE_SIZE_LEN + message_size + END_OF_MESSAGE_LEN;
	int buf_index_diff = buf_index - message_index;
	if (buf_index_diff < 0)
	{
		PRINT_ERROR("%s", "Incorrect buffer index, buf_index: %d, message_index: %d\n", buf_index, message_index);
		return RET_FAILURE_RUNTIME;
	}
	if (buf_index_diff > 0)
	{
// new data exist !!!
		char* buf_tmp = (char*)malloc(sizeof(char) * buf_index_diff);
		if (buf_tmp == NULL)
			throw bad_alloc();
		memcpy(buf_tmp, &buf[message_index], sizeof(char) * buf_index_diff);
		memcpy(buf, buf_tmp, sizeof(char) * buf_index_diff);
		free(buf_tmp);
	}
	buf_index -= message_index;

	full_message_found = false;
	return RET_SUCCESS;
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

unsigned int NodeMessageParser::get_message_size()const
{
	assert(full_message_found && "Incorrect Operation: full_message_found should NOT be True");
	// if (!full_message_found)
	// {
	// 	PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
	// 	return RET_FAILURE_INCORRECT_OPERATION;
	// }
	return message_size;	
}

const char* NodeMessageParser::get_message()const
{
	assert(full_message_found && "Incorrect Operation: full_message_found should NOT be True");
	// if (!full_message_found)
	// {
	// 	PRINT_ERROR("%s", "Incorrect Operation: full_message_found should NOT be True\n");
	// 	return RET_FAILURE_INCORRECT_OPERATION;
	// }
	// fprintf(stderr, "get_message() => data_buffer: %s\n", data_buffer.c_str());
	// fprintf(stderr, "get_message() => data_end_pos: %d\n", data_end_pos);
	// fprintf(stderr, "get_message() => message: %s\n", data_buffer.substr(1, data_end_pos - 1).c_str());
	// fprintf(stderr, "get_message() => message len: %d\n", strlen(data_buffer.substr(1, data_end_pos - 1).c_str()));
	// return (data_buffer.substr(1, data_end_pos - 1)).c_str();
	return message;
}

bool NodeMessageParser::is_buffer_empty()const
{
	// return data_buffer.empty();
	return (buf_index == 0 ? true : false);
}

const char* NodeMessageParser::get_buffer()const
{
	// return data_buffer.c_str();
	return buf;
}

//////////////////////////////////////////////////////////

ClusterNode::ClusterNode(int id, string token)
{
	node_id = id;
	node_token = token;
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
	local_cluster(false),
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

size_t ClusterMap::size()const
{
	return cluster_map.size();
}

bool ClusterMap::is_empty()const
{
	return cluster_map.empty();
}

bool ClusterMap::is_single()const
{
	return (cluster_map.size() == 1 ? true : false);
}

void ClusterMap::set_local_cluster(bool need_local_cluster)
{
	if (need_local_cluster != local_cluster)
	{
		local_cluster = need_local_cluster;
		if (!is_empty()) cleanup_node();
	}
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
		// fprintf(stderr, "id: %d, token: %s, %d\n", cluster_node->node_id, cluster_node->node_token.c_str(), strlen(cluster_node->node_token.c_str()));
		ret = add_node(cluster_node->node_id, cluster_node->node_token);
		if (CHECK_FAILURE(ret))
			break;
	}
	return ret;
}

unsigned short ClusterMap::add_node(int node_id, std::string node_token)
{
	ClusterNode* cluster_node = new ClusterNode(node_id, node_token);
	if (cluster_node == NULL)
		throw bad_alloc();
	cluster_map.push_back(cluster_node);
	reset_cluster_map_str();
	return RET_SUCCESS;
}

unsigned short ClusterMap::add_node(const char* node_id_token_str)
{
	assert(node_id_token_str != NULL && "node_id_token_str should NOT be NULL");
	char* node_id_token_str_tmp = strdup(node_id_token_str);
	char* str_ptr = node_id_token_str_tmp;
	char* node_id_str = strtok(str_ptr, ",");
	char* node_token_str = strtok(NULL, ",");
	unsigned short ret = add_node(atoi(node_id_str), string(node_token_str));
	if (CHECK_FAILURE(ret))
		return ret;
	free(node_id_token_str_tmp);
	return RET_SUCCESS;
}

unsigned short ClusterMap::delete_node(int node_id)
{
	// ClusterNode delete_node(node_id, string(""));
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

unsigned short ClusterMap::delete_node_by_token(std::string node_token)
{
	unsigned short ret = RET_SUCCESS;
	int node_id;
	ret = get_node_id(node_token, node_id);
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

unsigned short ClusterMap::cleanup_node_except_one(int alive_node_id)
{
	unsigned short ret = RET_SUCCESS;
	string alive_node_token;
	ret = get_node_token(alive_node_id, alive_node_token);
	if (CHECK_FAILURE(ret))
		return ret;
	cleanup_node();
	return add_node(alive_node_id, alive_node_token);
}

unsigned short ClusterMap::set_first_node(const int first_node_id)
{
// Find the node
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
// The designated node is already the first node, it's no need to move the nodes in the list
	if (((ClusterNode*)*iter_find)->node_id == first_node_id)
		return RET_SUCCESS;
	iter_find++;
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_id == first_node_id)
		{
// Delete the node
			cluster_map.erase(iter_find);
// Insert the node in the head of the list
			cluster_map.push_front(cluster_node);
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

unsigned short ClusterMap::set_first_node_token(const std::string& first_node_token)
{
// Find the node
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
// The designated node is already the first node, it's no need to move the nodes in the list
	if (((ClusterNode*)*iter_find)->node_token == first_node_token)
		return RET_SUCCESS;
	iter_find++;
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_token == first_node_token)
		{
// Delete the node
			cluster_map.erase(iter_find);
// Insert the node in the head of the list
			cluster_map.push_front(cluster_node);
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

unsigned short ClusterMap::get_first_node(int& first_node_id, string& first_node_token, bool peek_only)
{
	unsigned short ret = RET_SUCCESS;
	if (peek_only)
	{
		if (cluster_map.empty())
			return RET_FAILURE_INCORRECT_OPERATION;
		list<ClusterNode*>::iterator iter = cluster_map.begin();
		ClusterNode* cluster_node = (ClusterNode*)*iter;
		first_node_id = cluster_node->node_id;
		first_node_token = cluster_node->node_token;
	}
	else
	{
		ClusterNode* first_node = NULL;
		ret = pop_node(&first_node);
		if (CHECK_FAILURE(ret))
			return ret;
		first_node_id = first_node->node_id;
		first_node_token = first_node->node_token;
		delete first_node;

	}
	return RET_SUCCESS;
}

unsigned short ClusterMap::get_first_node_token(string& first_node_token, bool peek_only)
{
	int first_node_id;
	return get_first_node(first_node_id, first_node_token, peek_only);
}

unsigned short ClusterMap::get_node_id(const std::string& node_token, int& node_id)const
{
	list<ClusterNode*>::const_iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_token == node_token)
		{
			node_id = cluster_node->node_id;
			return RET_SUCCESS;
		}
		iter_find++;
	}
	return RET_FAILURE_NOT_FOUND;
}

unsigned short ClusterMap::get_node_token(int node_id, string& node_token)const
{
	list<ClusterNode*>::const_iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_id == node_id)
		{
			node_token = cluster_node->node_token;
			return RET_SUCCESS;
		}
		iter_find++;
	}
	return RET_FAILURE_NOT_FOUND;
}

unsigned short ClusterMap::check_exist_by_node_id(int node_id, bool& found)const
{
	string node_token;
	unsigned short ret = get_node_token(node_id, node_token);
	if (CHECK_FAILURE(ret))
	{
		assert(ret == RET_FAILURE_NOT_FOUND && "ret should be RET_FAILURE_NOT_FOUND");
		if (ret == RET_FAILURE_NOT_FOUND)
			found = false;
	}
	else
		found = true;
	return RET_SUCCESS;
}

unsigned short ClusterMap::check_exist_by_node_token(const string& node_token, bool& found)const
{
	int node_id;
	unsigned short ret = get_node_id(node_token, node_id);
	if (CHECK_FAILURE(ret))
	{
		assert(ret == RET_FAILURE_NOT_FOUND && "ret should be RET_FAILURE_NOT_FOUND");
		if (ret == RET_FAILURE_NOT_FOUND)
			found = false;
	}
	else
		found = true;
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

unsigned short ClusterMap::get_node_token(int node_id, std::string& node_token)
{
	bool found = false;
	list<ClusterNode*>::iterator iter_find = cluster_map.begin();
	while(iter_find != cluster_map.end())
	{
		ClusterNode* cluster_node = (ClusterNode*)*iter_find;
		if (cluster_node->node_id == node_id)
		{
			node_token = cluster_node->node_token;
			found = true;
			break;
		}
		iter_find++;
	}
	if (!found)
		return RET_FAILURE_NOT_FOUND;
	return RET_SUCCESS;
}

const char* ClusterMap::to_string()const
{
	if (cluster_map_str == NULL)
	{
		string total_str;
		static const int BUF_SIZE = 64;
		char buf[BUF_SIZE];
		list<ClusterNode*>::const_iterator iter = cluster_map.begin();
		while (iter != cluster_map.end())
		{
			ClusterNode* cluster_node = (ClusterNode*)*iter;
			snprintf(buf, BUF_SIZE, "%d:%s", cluster_node->node_id, cluster_node->node_token.c_str());
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
	char* cluster_node_id_token;
	while((cluster_node_id_token=strtok_r(cluster_map_str_ptr, ",", &cluster_map_str_rest)) != NULL)
	{
		char* cluster_node_str_rest;
		char* cluster_node_id = strtok_r(cluster_node_id_token, ":", &cluster_node_str_rest);
		char* cluster_node_token = strtok_r(NULL, ":", &cluster_node_str_rest);
		// fprintf(stderr, "ClusterMap::from_string id: %d, token: %s, %d\n", cluster_node_id, cluster_node_token, strlen(cluster_node_token));
		ret = add_node(atoi(cluster_node_id), string(cluster_node_token));
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

ClusterParam::ClusterParam() :
	session_id(0)
{

}

ClusterParam::~ClusterParam(){}

//////////////////////////////////////////////////////////

ClusterDetailParam::ClusterDetailParam(){}
ClusterDetailParam::~ClusterDetailParam(){}

///////////////////
// const int SystemInfoParam::NODE_IP_BUF_SIZE = 16;

SystemInfoParam::SystemInfoParam()
{
	// memset(node_token_buf, 0x0, sizeof(char) * DEF_VERY_SHORT_STRING_SIZE);
}

SystemInfoParam::~SystemInfoParam(){}

ClusterSystemInfoParam::ClusterSystemInfoParam(){}

ClusterSystemInfoParam::~ClusterSystemInfoParam(){}

//////////////////////////////////////////////////////////

SystemMonitorParam::SystemMonitorParam()
{
	// memset(node_token_buf, 0x0, sizeof(char) * DEF_VERY_SHORT_STRING_SIZE);
}

SystemMonitorParam::~SystemMonitorParam(){}

ClusterSystemMonitorParam::ClusterSystemMonitorParam(){}

ClusterSystemMonitorParam::~ClusterSystemMonitorParam(){}

//////////////////////////////////////////////////////////

SimulatorVersionParam::SimulatorVersionParam(int buf_size) :
	simulator_version_buf_size(buf_size),
	simulator_version(NULL)
{
	simulator_version = new char[simulator_version_buf_size + 1];
	if (simulator_version == NULL)
		throw bad_alloc();
	memset(simulator_version, 0x0, sizeof(char) * (simulator_version_buf_size + 1));
}

SimulatorVersionParam::~SimulatorVersionParam()
{
	if (simulator_version != NULL)
	{
		delete[] simulator_version;
		simulator_version = NULL;
	}
	simulator_version_buf_size = 0;
}

//////////////////////////////////////////////////////////

ClusterSimulatorVersionParam::ClusterSimulatorVersionParam(){}

ClusterSimulatorVersionParam::~ClusterSimulatorVersionParam(){}

//////////////////////////////////////////////////////////

FakeAcsptStateParam::FakeAcsptStateParam(int buf_size) :
	fake_acspt_state_buf_size(buf_size),
	fake_acspt_state(NULL)
{
	fake_acspt_state = new char[fake_acspt_state_buf_size + 1];
	if (fake_acspt_state == NULL)
		throw bad_alloc();
	memset(fake_acspt_state, 0x0, sizeof(char) * (fake_acspt_state_buf_size + 1));
}

FakeAcsptStateParam::~FakeAcsptStateParam()
{
	if (fake_acspt_state != NULL)
	{
		delete[] fake_acspt_state;
		fake_acspt_state = NULL;
	}
	fake_acspt_state_buf_size = 0;
}

//////////////////////////////////////////////////////////

ClusterFakeAcsptStateParam::ClusterFakeAcsptStateParam(){}

ClusterFakeAcsptStateParam::~ClusterFakeAcsptStateParam(){}

//////////////////////////////////////////////////////////

FakeAcsptDetailParam::FakeAcsptDetailParam()
{
	// memset(node_token_buf, 0x0, sizeof(char) * DEF_VERY_SHORT_STRING_SIZE);
}

FakeAcsptDetailParam::~FakeAcsptDetailParam(){}

//////////////////////////////////////////////////////////

ClusterFakeAcsptDetailParam::ClusterFakeAcsptDetailParam(){}

ClusterFakeAcsptDetailParam::~ClusterFakeAcsptDetailParam(){}

//////////////////////////////////////////////////////////

FileTransferParam::FileTransferParam() :
	session_id(-1),
	sender_token(NULL),
	filepath(NULL)
{
}

FileTransferParam::~FileTransferParam()
{
	if (filepath != NULL)
	{
		delete[] filepath;
		filepath = NULL;
	}
	if (sender_token != NULL)
	{
		delete[] sender_token;
		sender_token = NULL;
	}
	session_id = -1;
}

//////////////////////////////////////////////////////////

ClusterFileTransferParam::ClusterFileTransferParam(){}

ClusterFileTransferParam::~ClusterFileTransferParam(){}

//////////////////////////////////////////////////////////

FakeAcsptConfigValueParam::FakeAcsptConfigValueParam(){}

FakeAcsptConfigValueParam::~FakeAcsptConfigValueParam(){}

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
		STATIC_WRITE_FORMAT_ERROR("The notify thread is NOT running properly, due to: %s", GetErrorDescription(pthis->notify_thread_ret));
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
					WRITE_FORMAT_DEBUG("Thread[%s]=> Fail to execute event, due to %s", notify_thread_tag, GetErrorDescription(ret));
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
	// fprintf(stderr, "[%s]Nofity Thread is initialized\n", monitor_system_timer_thread_tag);
	if (pthread_create(&notify_tid, NULL, notify_thread_handler, this) != 0)
	{
		// fprintf(stderr, "[%s]Nofity Thread is initialized1\n", monitor_system_timer_thread_tag);
		WRITE_FORMAT_ERROR("Fail to create a worker thread of notifying event, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}
	// fprintf(stderr, "[%s]Nofity Thread[%d] is initialized2\n", monitor_system_timer_thread_tag, notify_tid);
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
	// bool monitor_system_timer_thread_alive = false;
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
			// monitor_system_timer_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(notify_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deleting the worker thread of notifying event, due to: %s", strerror(errno));
			// sleep(1);
			usleep(100000);
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
		notify_tid = 0;
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


//////////////////////////////////////////////////////////

const char* MonitorSystemTimerThread::DEFAULT_MONITOR_SYSTEM_TIMER_THREAD_TAG = "Monitor System Timer Thread";
// const int MonitorSystemTimerThread::DEFAULT_MONITOR_SYSTEM_DURATION = 10;  // Unit: sec
const int MonitorSystemTimerThread::DEFAULT_MONITOR_SYSTEM_PERIOD = 30;  // Unit: sec

void* MonitorSystemTimerThread::monitor_system_timer_thread_handler(void* pvoid)
{
	// fprintf(stderr, "monitor_system_timer_thread_handler is invokded !!!\n");
	MonitorSystemTimerThread* pthis = (MonitorSystemTimerThread*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
	int setcancelstate_ret;
    if ((setcancelstate_ret=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->monitor_system_timer_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    int setcanceltype_ret;
    if ((setcanceltype_ret=pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->monitor_system_timer_thread_ret = RET_FAILURE_SYSTEM_API;
	}
// Call the thread handler function to run the thread
	if (CHECK_SUCCESS(pthis->monitor_system_timer_thread_ret))
	{
		pthread_cleanup_push(monitor_system_timer_thread_cleanup_handler, pthis);
		pthis->monitor_system_timer_thread_ret = pthis->monitor_system_timer_thread_handler_internal();
		pthread_cleanup_pop(1);
	}
	else
	{
		STATIC_WRITE_FORMAT_ERROR("The timer thread of system monitor is NOT running properly, due to: %s", GetErrorDescription(pthis->monitor_system_timer_thread_ret));
	}
// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->monitor_system_timer_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->monitor_system_timer_thread_ret)));
	pthread_exit(NULL);
}

unsigned short MonitorSystemTimerThread::monitor_system_timer_thread_handler_internal()
{
	assert(observer != NULL && "notify_observer should NOT be NULL");
	assert(manager != NULL && "manager should NOT be NULL");
	WRITE_FORMAT_INFO("[%s] The worker timer thread of system monitor is running", monitor_system_timer_thread_tag);
	unsigned short ret = RET_SUCCESS;
	struct timespec ts;
	struct timespec ts_end;
	NodeType node_type = NONE;
	ret = manager->get(PARAM_NODE_TYPE, (void*)&node_type);
	if (CHECK_FAILURE(ret))
		return ret;
	bool should_exit;
	while (monitor_system_exit == 0)
	{
// If the thread calls sleep(), it is not able to be awake immediately if the thread is falling asleep.
// Exploit pthread_cond_timedwait() instead
		// sleep(monitor_system_period);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts_end = ts;
		ts_end.tv_sec += monitor_system_period;
		should_exit = false;
// https://www.cnblogs.com/qingxia/archive/2012/08/30/2663791.html
		pthread_mutex_lock(&monitor_system_periodic_check_mtx);
		int timedwait_ret = pthread_cond_timedwait(&monitor_system_periodic_check_cond, &monitor_system_periodic_check_mtx, &ts_end);
		if (pthread_cond_timedwait_err(timedwait_ret) != NULL)
		{
			if (timedwait_ret != ETIMEDOUT)
			{
			    WRITE_FORMAT_ERROR("[%s] pthread_cond_timedwait() fails, due to: %s", monitor_system_timer_thread_tag, pthread_cond_timedwait_err(timedwait_ret));
				ret = RET_FAILURE_SYSTEM_API;
				should_exit = true;
			}
		}
		else
		{
			WRITE_FORMAT_DEBUG("[%s] Notifies to exit......", monitor_system_timer_thread_tag);			
			should_exit = true;
		}
		pthread_mutex_unlock(&monitor_system_periodic_check_mtx);
		if (should_exit) goto OUT;

		WRITE_FORMAT_DEBUG("[%s] Get the data of system monitor", monitor_system_timer_thread_tag);
// Get the data
		string system_monitor_string;
		string curtime_str;
		get_curtime_str(curtime_str);
		switch (node_type)
		{
			case LEADER:
			{
				ClusterSystemMonitorParam cluster_system_monitor_param;
			    ret = manager->get(PARAM_SYSTEM_MONITOR, (void*)&cluster_system_monitor_param);
			 	if (CHECK_FAILURE(ret))
					return ret;
			    // SAFE_RELEASE(notify_cfg)
				ClusterDetailParam cluster_detail_param;
			    ret = manager->get(PARAM_CLUSTER_DETAIL, (void*)&cluster_detail_param);
				if (CHECK_FAILURE(ret))
					return ret;
				ClusterMap& cluster_map = cluster_detail_param.cluster_map;

				map<int, string>& cluster_data_map = cluster_system_monitor_param.cluster_data_map;
// Print data in cosole
				system_monitor_string = string("*** System Monitor ***\n");
				system_monitor_string += string(" @ ") + curtime_str + string("\n**********************\n\n");

				map<int, string>::iterator iter = cluster_data_map.begin();
				while (iter != cluster_data_map.end())
				{
					int node_id = (int)iter->first;
					string node_token;
					ret = cluster_map.get_node_token(node_id, node_token);
					if (CHECK_FAILURE(ret))
						return ret;
					char buf[DEF_STRING_SIZE];
					snprintf(buf, DEF_STRING_SIZE, "%s\n", node_token.c_str());
					system_monitor_string += string(buf);
					system_monitor_string += ((string)iter->second);
					system_monitor_string += string("\n**********\n");
					++iter;
				}
				system_monitor_string += string("\n");
			}
			break;
			case FOLLOWER:
			{
				SystemMonitorParam system_monitor_param;
			    ret = manager->get(PARAM_SYSTEM_MONITOR, (void*)&system_monitor_param);
			 	if (CHECK_FAILURE(ret))
					return ret;
				system_monitor_string = string("*** System Monitor (Local) ***\n");
				system_monitor_string += string(" @ ") + curtime_str + string("\n**********************\n\n");
				system_monitor_string += system_monitor_param.system_monitor_data;
				system_monitor_string += string("\n**********\n");
			}
			break;
			default:
			{
				WRITE_FORMAT_ERROR("Unknow node type: %d", node_type);
				ret = RET_FAILURE_INCORRECT_VALUE;
				goto OUT;
			}
			break;
		}
		WRITE_FORMAT_DEBUG("[%s] Get the data of system monitor... Done: %s", monitor_system_timer_thread_tag, system_monitor_string.c_str());
		observer->notify(NOTIFY_GET_SYSTEM_MONITOR, (void*)&system_monitor_string);
	}
OUT:
	WRITE_FORMAT_INFO("[%s] The worker timer thread of system monitor is dead", monitor_system_timer_thread_tag);
	return ret;
}

void MonitorSystemTimerThread::monitor_system_timer_thread_cleanup_handler(void* pvoid)
{
	MonitorSystemTimerThread* pthis = (MonitorSystemTimerThread*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->monitor_system_timer_thread_cleanup_handler_internal();
}

void MonitorSystemTimerThread::monitor_system_timer_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the timer thread of system monitor......", monitor_system_timer_thread_tag);
}

MonitorSystemTimerThread::MonitorSystemTimerThread(PINOTIFY notify, PIMANAGER mgr, const char* thread_tag) :
	observer(notify),
	manager(mgr),
	monitor_system_exit(0),
	monitor_system_tid(0),
	monitor_system_timer_thread_ret(RET_SUCCESS),
	monitor_system_period(DEFAULT_MONITOR_SYSTEM_PERIOD)
{
	IMPLEMENT_MSG_DUMPER()
	if (thread_tag == NULL)
		monitor_system_timer_thread_tag = strdup(DEFAULT_MONITOR_SYSTEM_TIMER_THREAD_TAG);
	else
		monitor_system_timer_thread_tag = strdup(thread_tag);
}

MonitorSystemTimerThread::~MonitorSystemTimerThread()
{
	if (monitor_system_timer_thread_tag != NULL)
	{
		free(monitor_system_timer_thread_tag);
		monitor_system_timer_thread_tag = NULL;
	}
	if (manager != NULL)
		manager = NULL;
	if (observer != NULL)
		observer = NULL;

	RELEASE_MSG_DUMPER()
}

unsigned short MonitorSystemTimerThread::initialize()
{
	monitor_system_periodic_check_mtx = PTHREAD_MUTEX_INITIALIZER;
	monitor_system_periodic_check_cond = PTHREAD_COND_INITIALIZER;
	// fprintf(stderr, "[%s]Nofity One Timer Thread is initialized\n", monitor_system_timer_thread_tag);
	if (pthread_create(&monitor_system_tid, NULL, monitor_system_timer_thread_handler, this) != 0)
	{
		// fprintf(stderr, "[%s]Nofity Thread is initialized1\n", monitor_system_timer_thread_tag);
		WRITE_FORMAT_ERROR("Fail to create a worker timer thread of system monitor, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}
	// fprintf(stderr, "[%s]Nofity Thread[%d] is initialized2\n", monitor_system_timer_thread_tag, notify_tid);
	return RET_SUCCESS;
}

unsigned short MonitorSystemTimerThread::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
	// void* status;
// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&monitor_system_exit, 1);
	// sleep(1);
	usleep(100000);
// Check notify thread alive
	// bool monitor_system_timer_thread_alive = false;
	if (monitor_system_tid != 0)
	{
		int kill_ret = pthread_kill(monitor_system_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker timer thread of system monitor did NOT exist......");
			ret = RET_SUCCESS;
			// goto OUT;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker timer thread of system monitor is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
			// goto OUT;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker timer thread of system monitor is STILL alive");
// Notify the worker thread to wake up
			pthread_mutex_lock(&monitor_system_periodic_check_mtx);
			pthread_cond_signal(&monitor_system_periodic_check_cond);
			pthread_mutex_unlock(&monitor_system_periodic_check_mtx);
			usleep(50000);

			// monitor_system_timer_thread_alive = true;
// Kill the thread
		    if (pthread_cancel(monitor_system_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deleting the worker timer thread of system monitor, due to: %s", strerror(errno));
			// sleep(1);
			usleep(50000);
		}
// Wait for notify thread's death
		WRITE_DEBUG("Wait for the worker timer thread of system monitor's death...");
		pthread_join(monitor_system_tid, NULL);
		if (CHECK_SUCCESS(monitor_system_timer_thread_ret))
			WRITE_DEBUG("Wait for the worker timer thread of system monitor's death Successfully !!!");
		else
		{
			WRITE_FORMAT_ERROR("Error occur while waiting for the worker timer thread of system monitor's death, due to: %s", GetErrorDescription(monitor_system_timer_thread_ret));
			ret = monitor_system_timer_thread_ret;
		}
		monitor_system_tid = 0;
	}

	return ret;
}

unsigned short MonitorSystemTimerThread::set_period(int period)
{
	monitor_system_period = period;
	return RET_SUCCESS;
}

//////////////////////////////////////////////////////////

char* EventFileAccess::EVENT_FOLDERNAME = "log";
char* EventFileAccess::EVENT_FILENAME = "event.log";

EventFileAccess::EventFileAccess() :
	event_log_fp(NULL)
{
	IMPLEMENT_MSG_DUMPER()
}
	
EventFileAccess::~EventFileAccess()
{
	RELEASE_MSG_DUMPER()
}

const char* EventFileAccess::get_event_log_filepath()const
{
	static char* event_log_filepath = NULL;
	if (event_log_filepath == NULL)
	{
		char current_working_directory[DEF_LONG_STRING_SIZE];
		getcwd(current_working_directory, sizeof(current_working_directory));
		event_log_filepath = new char[DEF_LONG_STRING_SIZE];
		if (event_log_filepath == NULL)
			throw bad_alloc();
		snprintf(event_log_filepath, DEF_LONG_STRING_SIZE, "%s/%s/%s", current_working_directory, EVENT_FOLDERNAME, EVENT_FILENAME);
	}
	return event_log_filepath;
}

// unsigned short EventFileAccess::remove_space_from_sides(char **new_string, const char* old_string)
unsigned short EventFileAccess::remove_space_from_sides(string& new_string, const char* old_string)
{
	assert(old_string != NULL && "old_string should NOT be NULL");
	// unsigned short ret = RET_SUCCESS;
	int string_len = strlen(old_string); 
	int start_index = 0;
	int end_index = strlen(old_string);
	bool start_index_found = false;
	for (int i = 0 ; i < string_len ; i++)
	{
		if (old_string[i] != ' ')
		{
			start_index = i;
			start_index_found = true;
			break;
		}
	}
	if (!start_index_found)
	{
		WRITE_FORMAT_ERROR("Fails to find the start index: %s", old_string);
		return RET_FAILURE_INCORRECT_VALUE;
	}
	 
	bool end_index_found = false;
	for (int j = string_len - 1 ; j >= 0 ; j--)
	{
		if (old_string[j] != ' ')
		{
			end_index = j;
			end_index_found = true;
			break;
		}
	}
	if (!end_index_found)
	{
		WRITE_FORMAT_ERROR("Fails to find the end index: %s", old_string);
		return RET_FAILURE_INCORRECT_VALUE;
	}

	int new_string_len = end_index - start_index + 1;
	char* new_string_tmp = new char[new_string_len + 1];
	if (new_string_tmp == NULL)
		throw bad_alloc();
	strncpy(new_string_tmp, &old_string[start_index], new_string_len);
	// *new_string = new_string_tmp;
	new_string = std::string(new_string_tmp);
	delete[] new_string_tmp;
	return RET_SUCCESS;
}

unsigned short EventFileAccess::initialize()
{
    // char current_working_directory[DEF_LONG_STRING_SIZE];
  	// getcwd(current_working_directory, sizeof(current_working_directory));
    // char event_log_filepath[DEF_LONG_STRING_SIZE];
    // snprintf(event_log_filepath, DEF_LONG_STRING_SIZE, "%s/%s/%s", current_working_directory, EVENT_FOLDERNAME, EVENT_FILENAME);

 	WRITE_FORMAT_ERROR("Open the event log file: %s", get_event_log_filepath());
	event_log_fp = fopen(get_event_log_filepath(), "a+");
 	if (event_log_fp == NULL)
 	{
 		WRITE_FORMAT_ERROR("fopen() fails, due to: %s", strerror(errno));
  		return RET_FAILURE_SYSTEM_API;	
  	}
	return RET_SUCCESS;
}

unsigned short EventFileAccess::deinitialize()
{
	// fprintf(stderr, "EventFileAccess::deinitialize()\n");
	if (event_log_fp != NULL)
	{
		fclose(event_log_fp);
		event_log_fp = NULL;
	}
	return RET_SUCCESS;
}

EventDevice EventFileAccess::get_type()const{return EVENT_DEVICE_FILE;}

unsigned short EventFileAccess::write(const EventCfg* event_cfg)
{
	assert(event_cfg != NULL && "event_cfg should NOT be NULL");
	assert(event_log_fp != NULL && "event_log_fp should NOT be NULL");
	unsigned short ret = RET_SUCCESS;
	event_cfg->get_type();
	const char* event_description = event_cfg->get_str();
	int event_description_len = strlen(event_description);
// event description
	// fprintf(stderr, "Write event to file: %s", event_description);
	WRITE_FORMAT_DEBUG("Write event to file: %s", event_description);
	size_t write_bytes = fwrite(event_description, sizeof(char), event_description_len, event_log_fp);
	if (write_bytes != event_description_len)
	{
		WRITE_FORMAT_ERROR("Incorrect data size while writing log, expected: %d, actual: %d", event_description_len, write_bytes);
		return RET_FAILURE_SYSTEM_API;
	}
// newline
	fwrite("\n", sizeof(char), 1, event_log_fp);
/*
Buffering works in such a way that the contents of an output buffer are only written to the stdout stream or FILE object once the buffer is full, 
or there is a new line character at the end of it. This may result in unexpected behavior. 
For instance, the user may not see the string passed in the printf function on their terminal as it is not large enough to fill the buffer completely, 
nor is there a new line character at the end of it.
Here, the programmer can use the fflush function to make sure that the current state of the buffer is immediately printed to the console and written to the stdout stream
*/
	fflush(event_log_fp);
	return ret;
}

unsigned short EventFileAccess::read(list<PEVENT_ENTRY>* event_list, list<string>* event_line_list, EventSearchRule* event_search_rule)
{
	unsigned short ret = RET_SUCCESS;
	list<string>* line_list = NULL;
	if (event_line_list != NULL && event_search_rule == NULL)
		line_list = event_line_list;
	else
	{
		line_list = new list<string>;
		if (line_list == NULL)
			throw bad_alloc();
	}
	ret = read_file_lines_ex(*line_list, get_event_log_filepath());
	if (CHECK_FAILURE(ret))
		return ret;
	// printf("line_list size: %d\n", line_list->size());
	list<string>::iterator iter = line_list->begin();
	while(iter != line_list->end())
	{
// Can NOT do in this way. The line variable is empty
		// char* line = (char*)((string)*iter).c_str();
		char* line = strdup((char*)((string)*iter).c_str());
		if (line == NULL)
			throw bad_alloc();
		// printf("line: %s\n", line);
		char* line_field_tmp;
		char* rest_line_field;
		int line_field_count = 0;
		PEVENT_ENTRY event_entry = new EventEntry;
		if (event_entry == NULL) throw bad_alloc();
// Parse the data
		char* line_tmp = line;
		while ((line_field_tmp = strtok_r(line_tmp, "|", &rest_line_field)) != NULL)
		{
			string line_field;
			ret = remove_space_from_sides(line_field, line_field_tmp);
			if (CHECK_FAILURE(ret))
				return ret;
			// printf("%d  line_field: %s\n", line_field_count, line_field.c_str());
			switch(line_field_count)
			{
				case EVENT_ENTRY_FIELD_TIME:
				{
					if (strptime(line_field.c_str(), "%Y/%m/%d %H:%M:%S", &event_entry->event_time) == NULL)
					{
						WRITE_FORMAT_ERROR("Incorrect time string format: %s, API error: %s", line_field.c_str(), strerror(errno));
						return RET_FAILURE_INTERNAL_ERROR;
					}
					event_entry->event_time.tm_isdst = -1; // Add this line to avoid the field is NOT defined overwise an out-of-range error occurs while calling mktime()
					// printf("Time: %s -> %d/%02d/%02d %02d:%02d:%02d\n", line_field.c_str(), event_entry->event_time.tm_year + 1900, event_entry->event_time.tm_mon + 1, event_entry->event_time.tm_mday, event_entry->event_time.tm_hour, event_entry->event_time.tm_min, event_entry->event_time.tm_sec);
				}
				break;
				case EVENT_ENTRY_FIELD_TYPE:
				{
					event_entry->event_type = GetEventTypeFromDescription(line_field.c_str());
				}
				break;
				case EVENT_ENTRY_FIELD_SEVERITY:
				{
					event_entry->event_severity = GetEventSeverityFromDescription(line_field.c_str());
				}
				break;
				case EVENT_ENTRY_FIELD_CATEGORY:
				{
					event_entry->event_category = GetEventCategoryFromDescription(line_field.c_str());
				}
				break;
				case EVENT_ENTRY_FIELD_DESCRIPTION:
				{
					event_entry->event_description = line_field;
				}
				break;
				default:
				{
					WRITE_FORMAT_ERROR("Unknown event entry field type: %d", line_field_count);
					return RET_FAILURE_INTERNAL_ERROR;
				}
				break;
			}
			if (line_tmp != NULL) line_tmp = NULL;
			line_field_count++;
		}
// Exploit the search criterion if necessary
		if (event_search_rule != NULL)
		{
			if (event_search_rule->need_search_event_time)
			{
				time_t event_time = mktime(&event_entry->event_time);
				// printf("Error: %s\n", strerror(errno));
				// printf("Time: %d/%02d/%02d %02d:%02d:%02d -> %s", event_entry->event_time.tm_year + 1900, event_entry->event_time.tm_mon + 1, event_entry->event_time.tm_mday, event_entry->event_time.tm_hour, event_entry->event_time.tm_min, event_entry->event_time.tm_sec, ctime(&event_time));
				// printf("Begin: %ld, End: %ld, Cur: %ld\n", event_search_rule->search_event_time_begin, event_search_rule->search_event_time_end, event_time);
				if (event_time < event_search_rule->search_event_time_begin)
					goto OUT;
				else if (event_time > event_search_rule->search_event_time_end)
					goto OUT;
			}
			if (event_search_rule->need_search_event_type && event_search_rule->search_event_type != event_entry->event_type)
				goto OUT;
			if (event_search_rule->need_search_event_severity && event_search_rule->search_event_severity != event_entry->event_severity)
				goto OUT;
			if (event_search_rule->need_search_event_category && event_search_rule->search_event_category != event_entry->event_category)
				goto OUT;
			if (event_search_rule->need_search_event_description && event_entry->event_description.find(event_search_rule->search_event_description) == string::npos)
				goto OUT;
			if (event_line_list != NULL)
				event_line_list->push_back((string)*iter);
		}
		event_list->push_back(event_entry);
OUT:
		if (line != NULL)
		{
			free(line);
			line = NULL;
		}
		iter++;
	}
	if (event_line_list == NULL)
	{
		if (line_list != NULL)
		{
			delete line_list;
			line_list = NULL;
		}
	}

	return ret;
}

//////////////////////////////////////////////////////////

EventRecorder* EventRecorder::instance = NULL;

EventRecorder* EventRecorder::get_instance(const char* callable_file_name, unsigned long callable_line_no)
{
	if (instance == NULL)
	{
// If the instance is NOT created...
		instance = new EventRecorder();
		if (instance == NULL)
		{
			assert(0 || "Fail to get the instance of EventRecorder");
			return NULL;
		}
// Initialize the instance
		unsigned short ret = instance->initialize();
		if(CHECK_FAILURE(ret))
		{
			assert(0 || "Fail to get the instance of EventRecorder");
			return NULL;
		}
	}
// Add the reference count
	instance->addref(callable_file_name, callable_line_no);
	return instance;
}

EventRecorder::EventRecorder() :
	event_device_access(NULL),
	notify_thread(NULL),
	ref_count(0)
{
	IMPLEMENT_MSG_DUMPER()
}

EventRecorder::~EventRecorder()
{
	deinitialize();
	RELEASE_MSG_DUMPER()
}

unsigned short EventRecorder::initialize()
{
	unsigned short ret = MSG_DUMPER_SUCCESS;
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "EventRecorder Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
	// sleep(1);
	usleep(100000);
	event_device_access = new EventFileAccess();
	if (event_device_access == NULL)
		throw bad_alloc();
	ret = event_device_access->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
	return ret;
}

void EventRecorder::deinitialize()
{
	if (event_device_access != NULL)
	{
		event_device_access->deinitialize();
		delete event_device_access;
		event_device_access = NULL;
	}
// Stop the event thread
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	if (instance != NULL)
		instance = NULL;
}

unsigned short EventRecorder::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
    	case NOTIFY_ADD_EVENT:
    	{
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");

    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		ret = notify_thread->add_event(notify_cfg);
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d, %s", notify_type, GetNotifyDescription(notify_type));
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short EventRecorder::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
    	case NOTIFY_ADD_EVENT:
    	{
    		// assert(event_device_access != NULL && "event_device_access should NOT be NULL");
    		PNOTIFY_EVENT_CFG notify_event_cfg = (PNOTIFY_EVENT_CFG)notify_cfg;
    		PEVENT_CFG event_cfg = (PEVENT_CFG)notify_event_cfg->get_event_cfg();
    		assert(event_cfg != NULL && "event_cfg should NOT be NULL");
    		WRITE_FORMAT_DEBUG("Write event[%s] into device[%s]...", GetEventTypeDescription(event_cfg->get_type()), GetEventDeviceDescription(event_device_access->get_type()));
    		ret = event_device_access->write(event_cfg);
			SAFE_RELEASE(event_cfg);
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

int EventRecorder::addref(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_add(&ref_count, 1);
	// fprintf(stderr, "EventRecorder::addref -> %d\n", ref_count);
	// printf("EventRecorder::addref() in [%s:%ld], ref_count: %d\n", callable_file_name, callable_line_no, ref_count);
	return ref_count;
}

int EventRecorder::release(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_sub(&ref_count, 1);
	// printf("EventRecorder::release() in [%s:%ld], ref_count: %d\n", callable_file_name, callable_line_no, ref_count);
	// fprintf(stderr, "EventRecorder::release -> %d\n", ref_count);
	assert(ref_count >= 0 && "ref_count should NOT be smaller than 0");
	if (ref_count == 0)
	{
		// fprintf(stderr, "Call EventRecorder::~EventRecorder()......\n");
		delete this;
		return 0;
	}

	return ref_count;
}

unsigned short EventRecorder::write(const PEVENT_CFG event_cfg)
{
	unsigned short ret = RET_SUCCESS;
	assert(event_cfg != NULL && "event_cfg should NOT be NULL");
	event_cfg->addref(__FILE__, __LINE__);
	PNOTIFY_CFG notify_cfg = new NotifyEventCfg(event_cfg);
	if (notify_cfg == NULL)
		throw bad_alloc();
// Asynchronous event
	ret = notify(NOTIFY_ADD_EVENT, notify_cfg);
	return ret;
}

unsigned short EventRecorder::read(list<EventEntry*>* event_list, list<string>* event_line_list, EventSearchRule* event_search_rule)
{
	unsigned short ret = RET_SUCCESS;
	assert(event_list != NULL && "event_list should NOT be NULL");
    ret = event_device_access->read(event_list, event_line_list, event_search_rule);
	return ret;
}