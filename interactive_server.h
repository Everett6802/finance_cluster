#ifndef INTERACTIVE_SERVER_H
#define INTERACTIVE_SERVER_H

#include <pthread.h>
#include <deque>
#include "common.h"


class InteractiveSession;

typedef std::map<int, InteractiveSession*> INTERACTIVE_SESSION_MAP;
typedef INTERACTIVE_SESSION_MAP* PINTERACTIVE_SESSION_MAP;
typedef std::map<int, InteractiveSession*>::iterator INTERACTIVE_SESSION_ITER;

class InteractiveServer : public INotify
{
	DECLARE_MSG_DUMPER()

private:
	static const char* listen_thread_tag;
	static const int WAIT_CONNECTION_TIMEOUT;
	// static const int INTERACTIVE_SERVER_PORT;
	static const int INTERACTIVE_SERVER_BACKLOG;

	int server_fd;
	INTERACTIVE_SESSION_MAP interactive_session_map;
	PNOTIFY_THREAD notify_thread;
	PIMANAGER manager;

	volatile int listen_exit;
	pthread_t listen_tid;
	volatile unsigned short listen_thread_ret;

	pthread_mutex_t session_mtx;

	unsigned short init_server();
	unsigned short remove_session(int session_id);

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

	unsigned short initialize();
	unsigned short deinitialize();

// INotify
	virtual unsigned short notify(NotifyType notify_type, void* param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef InteractiveServer* PINTERACTIVE_SERVER;

#endif
