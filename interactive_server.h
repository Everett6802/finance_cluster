#ifndef INTERACTIVE_SERVER_H
#define INTERACTIVE_SERVER_H

#include <pthread.h>
#include <deque>
#include "common.h"


class InteractiveSession;

typedef std::map<int, InteractiveSession*> INTERACTIVE_SESSION_MAP;
typedef INTERACTIVE_SESSION_MAP* PINTERACTIVE_SESSION_MAP;
typedef std::map<int, InteractiveSession*>::iterator INTERACTIVE_SESSION_ITER;
typedef std::map<int, InteractiveSession*>::const_iterator INTERACTIVE_SESSION_CONST_ITER;

class InteractiveServer : public INotify
{
	DECLARE_MSG_DUMPER()

	class InteractiveSessionIDAssigner
	{
	private:
		int hash_table_size;
		bool* hash_table;

		int hash_function(int hash_key, int hash_offset)const;

	public:
		InteractiveSessionIDAssigner(int session_id_hash_table_size);
		~InteractiveSessionIDAssigner();
		int get_session_id(int hash_key)const;
		void reset_session_id(int session_id);
	};

private:
	static const char* listen_thread_tag;
	static const int WAIT_CONNECTION_TIMEOUT;
	// static const int INTERACTIVE_SERVER_PORT;
	static const int INTERACTIVE_SERVER_BACKLOG;

	InteractiveSessionIDAssigner* interactive_session_id_assigner;
	int server_fd;
	INTERACTIVE_SESSION_MAP interactive_session_map;
	PNOTIFY_THREAD notify_thread;
	PIMANAGER manager; // To ClusterMgr
	int system_monitor_period;

	volatile int listen_exit;
	pthread_t listen_tid;
	volatile unsigned short listen_thread_ret;

	mutable pthread_mutex_t session_mtx;

	unsigned short init_server();
	unsigned short close_session(int session_id);
	unsigned short close_all_session();
	unsigned short print_session(int session_id, const std::string& console_message)const;
	unsigned short print_all_session(const std::string& console_message)const;

	static void* listen_thread_handler(void* pvoid);
	unsigned short listen_thread_handler_internal();
	static void listen_thread_cleanup_handler(void* pvoid);
	void listen_thread_cleanup_handler_internal();

public:
	InteractiveServer(PIMANAGER mgr);
	virtual ~InteractiveServer();

	class const_iterator
	{
	private:
		INTERACTIVE_SESSION_ITER iter;

	public:
		const_iterator(INTERACTIVE_SESSION_ITER iterator);
		const_iterator operator++();
		bool operator==(const const_iterator& another);
		bool operator!=(const const_iterator& another);
		const InteractiveSession* operator->();
		const InteractiveSession& operator*();
	};

	const_iterator begin();
	const_iterator end();

	unsigned short initialize(int system_monitor_period_value);
	unsigned short deinitialize();
	unsigned short print_console(const std::string& console_message, int session_id=-1)const;

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef InteractiveServer* PINTERACTIVE_SERVER;

#endif
