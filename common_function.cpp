#include <netdb.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "common.h"


using namespace std;

unsigned short get_local_interface_ip(map<string, string>& interface_ip_map)
{
	struct ifaddrs* ifAddrStruct = NULL;
	void* tmpAddrPtr = NULL;

	getifaddrs(&ifAddrStruct);
// Traverse the ethernet card on local PC
	STATIC_WRITE_DEBUG("Traverse the all IPs bounded to local network interface...");
	// bool found = false;
	for (struct ifaddrs* ifa = ifAddrStruct ; ifa != NULL ; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) // check it is IP4
		{
			tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			STATIC_WRITE_FORMAT_DEBUG("%s IPv4 Address %s", ifa->ifa_name, addressBuffer);
			string local_interface(ifa->ifa_name);
			string local_ip(ifa->ifa_name);
			interface_ip_map[local_interface] = local_ip;
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6) // check it is IP6
		{
			// tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
			// char addressBuffer[INET6_ADDRSTRLEN];
			// inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			// STATIC_WRITE_FORMAT_DEBUG("%s IPv6 Address %s", ifa->ifa_name, addressBuffer);
		}
	}

// Release the resource
	if (ifAddrStruct!=NULL)
		freeifaddrs(ifAddrStruct);

	return RET_SUCCESS;
}