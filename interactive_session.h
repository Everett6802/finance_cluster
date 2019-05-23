#ifndef INTERACTIVE_SESSION_H
#define INTERACTIVE_SESSION_H

// This header file contains definitions of a number of data types used in system calls. These types are used in the next two include files.
#include <sys/types.h> 
// The header file socket.h includes a number of definitions of structures needed for sockets.
#include <sys/socket.h>
// The header file in.h contains constants and structures needed for internet domain addresses.
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include "common.h"


#define SESSION_TAG_SIZE 64

class InteractiveSession
{
	DECLARE_MSG_DUMPER()
private:
	static const int REQ_BUF_SIZE;
	static const int RSP_BUF_VERY_SHORT_SIZE;
	static const int RSP_BUF_SHORT_SIZE;
	static const int RSP_BUF_SIZE;
	static const int RSP_BUF_LONG_SIZE;
	static const int RSP_BUF_VERY_LONG_SIZE;
	static const int MAX_ARGC;

	// static const char* session_thread_tag;
	static const int WAIT_SESSION_TIMEOUT;

	static void init_command_map();

	PINOTIFY observer;
	PIPARAM manager;

	volatile int session_exit;
	pthread_t session_tid;
	volatile unsigned short session_thread_ret;

	int sock_fd;
	sockaddr_in sock_addr;
	char session_tag[64];
	int session_id;

	static void* session_thread_handler(void* void_tr);
	unsigned short session_thread_handler_internal();

	// unsigned short print_single_stock_support_resistance_string(const char* stock_support_resistance_entry, int stock_support_resistance_entry_len);
	// void reset_search_param();
// Handle command related fundtions
	unsigned short handle_command(int argc, char **argv);
	unsigned short handle_help_command(int argc, char **argv);
	unsigned short handle_exit_command(int argc, char **argv);
	unsigned short handle_get_cluster_detail_command(int argc, char **argv);
	unsigned short print_to_console(std::string response)const;
	unsigned short print_prompt_to_console()const;

public:
	InteractiveSession(PINOTIFY notify, PIMANAGER mgr, int client_fd, const sockaddr_in& sock_addraddress, int interactive_session_id);
	~InteractiveSession();

	unsigned short initialize();
	unsigned short deinitialize();
	const char* get_session_tag()const;
};
typedef InteractiveSession* PINTERACTIVE_SESSION;

#endif
