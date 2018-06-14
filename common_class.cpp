#include <assert.h>
#include <stdexcept>
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
