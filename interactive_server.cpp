// #include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include "interactive_server.h"
#include "interactive_session.h"


using namespace std;

// static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
const char* InteractiveServer::listen_thread_tag = "Listen Thread";
const int InteractiveServer::WAIT_CONNECTION_TIMEOUT = 60; // 68 seconds
// const int InteractiveServer::INTERACTIVE_SERVER_PORT = SESSION_PORT_NO;
const int InteractiveServer::INTERACTIVE_SERVER_BACKLOG = 5;

InteractiveServer::const_iterator::const_iterator(INTERACTIVE_SESSION_ITER iterator) : iter(iterator){}

InteractiveServer::const_iterator InteractiveServer::const_iterator::operator++()
{
	++iter;
	return *this;
}

bool InteractiveServer::const_iterator::operator==(const const_iterator& another)
{
	if (this == &another)
		return true;
	return iter == another.iter;
}
		
bool InteractiveServer::const_iterator::operator!=(const const_iterator& another)
{
	return !(*this == another);
}

const InteractiveSession* InteractiveServer::const_iterator::operator->()
{
	// return (PINTERACTIVE_SESSION_MAP)(*iter);
	return (InteractiveSession*)(iter->second);
}

const InteractiveSession& InteractiveServer::const_iterator::operator*()
{
	// return *((PINTERACTIVE_SESSION_MAP)(*iter));
	return *(InteractiveSession*)(iter->second);
}

///////////////////////////////////////////////////////////////////////////////////////

InteractiveServer::InteractiveServer(PIMANAGER mgr) : 
	server_fd(0),
	notify_thread(NULL),
	manager(mgr),
	listen_exit(0),
	listen_tid(0),
	listen_thread_ret(RET_SUCCESS)
{
	IMPLEMENT_MSG_DUMPER()
}

InteractiveServer::~InteractiveServer()
{
	unsigned short ret = deinitialize();
	if (CHECK_FAILURE(ret))
	{
		static const int ERRMSG_SIZE = 256;
		char errmsg[ERRMSG_SIZE];
		snprintf(errmsg, ERRMSG_SIZE, "Error occurs in InteractiveServer::deinitialize(), due to :%s", GetErrorDescription(ret));
		throw runtime_error(string(errmsg));
	}
	RELEASE_MSG_DUMPER()
}

unsigned short InteractiveServer::init_server()
{
	// unsigned short ret = RET_SUCCESS;
	WRITE_DEBUG("Initailize Finance Interactive Server......");
	sockaddr_in server_sock;
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		WRITE_FORMAT_ERROR("socket() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	int val = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
	bzero((char*)&server_sock, sizeof(server_sock));
	server_sock.sin_family = AF_INET;
	server_sock.sin_addr.s_addr = INADDR_ANY;
	server_sock.sin_port = htons(SESSION_PORT_NO);
	if(bind(server_fd, (struct sockaddr *)&server_sock, sizeof(server_sock)) < 0)
	{
		WRITE_FORMAT_ERROR("bind() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}
	if (listen(server_fd, INTERACTIVE_SERVER_BACKLOG) < 0)
	{
		WRITE_FORMAT_ERROR("listen() fails, due to: %s", strerror(errno));
		return RET_FAILURE_SYSTEM_API;
	}

	return RET_SUCCESS;
}

// unsigned short InteractiveServer::wait_for_connection()
// {
// 	WRITE_DEBUG("Finance Analysis Interactive Server is Ready, Wait for connection......");
// 	unsigned short ret = RET_SUCCESS;
// 	int client_socketfd;
// 	sockaddr_in client_addr;
// 	socklen_t client_addr_len;
// 	int session_cnt = 0;
// 	while (true)
// 	{
// 		client_addr_len = sizeof(client_addr);
// 		client_socketfd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
// 		WRITE_FORMAT_DEBUG("Connection request from %s:%d", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));
// 		if (client_socketfd == -1)
// 		{
// 			WRITE_FORMAT_ERROR("listen() fails, due to: %s", strerror(errno));
// 			return RET_FAILURE_SYSTEM_API;
// 		}
// 		PINTERACTIVE_SESSION interactive_session = new InteractiveSession(client_socketfd, client_addr, session_cnt++, this);
// 		if (interactive_session == NULL)
// 		{
// 			WRITE_ERROR("Fail to allocate memory: interactive_session");
// 			return RET_FAILURE_INSUFFICIENT_MEMORY;
// 		}
// 		ret = interactive_session->initialize();
// 		if (CHECK_FAILURE(ret))
// 			return ret;
// 		interactive_session_map.push_back(interactive_session);
// 	}
// 	return RET_SUCCESS;
// }

unsigned short InteractiveServer::remove_session(int session_id)
{
	unsigned short ret = RET_SUCCESS;
// Remove the session from the container
	pthread_mutex_lock(&session_mtx);
	INTERACTIVE_SESSION_ITER iter = interactive_session_map.find(session_id);
	if (iter == interactive_session_map.end())
	{
		WRITE_FORMAT_ERROR("The Session[%d] does NOT exist", session_id);
		pthread_mutex_unlock(&session_mtx);
		return RET_FAILURE_INVALID_ARGUMENT;
	}
	interactive_session_map.erase(session_id);
	pthread_mutex_unlock(&session_mtx);

	InteractiveSession* interactive_session = (InteractiveSession*)iter->second;
	assert(interactive_session != NULL && "interactive_session should NOT be NULL");
// Stop the session and release the resource
	ret = interactive_session->deinitialize();
	delete interactive_session;
	interactive_session = NULL;	
	return ret;
}

unsigned short InteractiveServer::initialize()
{
	unsigned short ret = RET_SUCCESS;
// Initialize the worker thread for handling events
	notify_thread = new NotifyThread(this, "Interactive Server Notify Thread");
	if (notify_thread == NULL)
		throw bad_alloc();
	ret = notify_thread->initialize();
	if (CHECK_FAILURE(ret))
		return ret;
// Initialize the server for telnet
	ret = init_server();
	if (CHECK_FAILURE(ret))
		return ret;
	// ret = wait_for_connection();
	// if (CHECK_FAILURE(ret))
	// 	return ret;
// Initialize the synchronization object
	session_mtx = PTHREAD_MUTEX_INITIALIZER;
	// mtx_cluster_map = PTHREAD_MUTEX_INITIALIZER;
// Create worker thread
	if (pthread_create(&listen_tid, NULL, listen_thread_handler, this))
	{
		WRITE_FORMAT_ERROR("Fail to create a worker thread of accepting client, due to: %s",strerror(errno));
		return RET_FAILURE_HANDLE_THREAD;
	}

	return RET_SUCCESS;
}

unsigned short InteractiveServer::deinitialize()
{
	unsigned short ret = RET_SUCCESS;
// Notify the worker thread it's time to exit
	__sync_fetch_and_add(&listen_exit, 1);
	sleep(1);
// Check listen thread alive
	// bool listen_thread_alive = false;
	if (listen_tid != 0)
	{
		int kill_ret = pthread_kill(listen_tid, 0);
		if(kill_ret == ESRCH)
		{
			WRITE_WARN("The worker thread of listening did NOT exist......");
			ret = RET_SUCCESS;
		}
		else if(kill_ret == EINVAL)
		{
			WRITE_ERROR("The signal to the worker thread of listening is invalid");
			ret = RET_FAILURE_HANDLE_THREAD;
		}
		else
		{
			WRITE_DEBUG("The signal to the worker thread of listening is STILL alive");
// Kill the thread
		    if (pthread_cancel(listen_tid) != 0)
		        WRITE_FORMAT_ERROR("Error occur while deletinng the worker thread of listening, due to: %s", strerror(errno));
			sleep(1);
		}
	}

	WRITE_DEBUG("Wait for the worker thread of listening's death...");
// Should NOT check the thread status in this way.
// Segmentation fault occurs sometimes, seems the 'status' variable accesses the illegal address
	// pthread_join(listen_tid, &status);
	// if (status == NULL)
	// 	sWRITE_DEBUG("Wait for the worker thread of sending message's death Successfully !!!");
	// else
	// {
	// 	WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of sending message's death, due to: %s", (char*)status);
	// 	return listen_thread_ret;
	// }
// Wait for listen thread's death
	pthread_join(listen_tid, NULL);
	if (CHECK_SUCCESS(listen_thread_ret))
		WRITE_DEBUG("Wait for the worker thread of listening's death Successfully !!!");
	else
	{
		WRITE_FORMAT_ERROR("Error occur while waiting for the worker thread of listening's death, due to: %s", GetErrorDescription(listen_thread_ret));
		ret = listen_thread_ret;
	}
// Notify each session to exit and Delete all the sessions
// Implemented in listen cleanup thread handler 
	// INTERACTIVE_SESSION_ITER iter = interactive_session_map.begin();
	// while(iter != interactive_session_map.end())
	// {
	// 	PINTERACTIVE_SESSION interactive_session = (PINTERACTIVE_SESSION)(*iter);
	// 	iter++;
	// 	if (interactive_session != NULL)
	// 	{
	// 		interactive_session->notify_exit();
	// 		delete interactive_session;
	// 		interactive_session = NULL;
	// 	}
	// }
	// interactive_session_map.clear();
	if (server_fd != -1)
	{
		close(server_fd);
		server_fd = -1;
	}
	if (notify_thread != NULL)
	{
		notify_thread->deinitialize();
		delete notify_thread;
		notify_thread = NULL;
	}
	return ret;
}

InteractiveServer::const_iterator InteractiveServer::begin() 
{
	return const_iterator(interactive_session_map.begin());
}

InteractiveServer::const_iterator InteractiveServer::end() 
{
	return const_iterator(interactive_session_map.end());
}

unsigned short InteractiveServer::notify(NotifyType notify_type, void* notify_param)
{
    unsigned short ret = RET_SUCCESS;
    switch(notify_type)
    {
// Synchronous event:
// Asynchronous event:
      	case NOTIFY_SESSION_EXIT:
    	{
    		assert(notify_thread != NULL && "notify_thread should NOT be NULL");
    		PNOTIFY_CFG notify_cfg = (PNOTIFY_CFG)notify_param;
    		if (notify_cfg == NULL)
    		{
    			WRITE_FORMAT_ERROR("The config of the notify_type[%d] should NOT be NULL", notify_type);
    			return RET_FAILURE_INVALID_ARGUMENT;
    		}
    		ret = notify_thread->add_event(notify_cfg);
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

unsigned short InteractiveServer::async_handle(NotifyCfg* notify_cfg)
{
	assert(notify_cfg != NULL && "notify_cfg should NOT be NULL");
    unsigned short ret = RET_SUCCESS;
    NotifyType notify_type = notify_cfg->get_notify_type();
    switch(notify_type)
    {
      	case NOTIFY_SESSION_EXIT:
    	{
    		int session_id = *((int*)notify_cfg->get_notify_param());
			WRITE_FORMAT_DEBUG("Session[%d] notify the parent to exit", session_id);
			ret = remove_session(session_id);
    	}
    	break;
    	default:
    	{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown notify type: %d", notify_type);
    		throw std::invalid_argument(buf);
    	}
    	break;
    }
    return ret;
}

void* InteractiveServer::listen_thread_handler(void* pvoid)
{
	InteractiveServer* pthis = (InteractiveServer*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");

// https://www.shrubbery.net/solaris9ab/SUNWdev/MTP/p10.html
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcancelstate() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
    }

// PTHREAD_CANCEL_DEFERRED means that it will wait the pthread_join, 
    // pthread_cond_wait, pthread_cond_timewait.. to be call when the 
    // thread receive cancel message.
    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) != 0) 
    {
    	STATIC_WRITE_FORMAT_ERROR("pthread_setcanceltype() fails, due to: %s", strerror(errno));
    	pthis->listen_thread_ret = RET_FAILURE_SYSTEM_API;
	}

	if (CHECK_SUCCESS(pthis->listen_thread_ret))
	{
		pthread_cleanup_push(listen_thread_cleanup_handler, pthis);
		pthis->listen_thread_ret = pthis->listen_thread_handler_internal();
		pthread_cleanup_pop(1);
	}
// No need to send data to pthread_join
	// pthread_exit((CHECK_SUCCESS(pthis->listen_thread_ret) ? NULL : (void*)GetErrorDescription(pthis->listen_thread_ret)));
	pthread_exit(NULL);
}

unsigned short InteractiveServer::listen_thread_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] The worker thread of Interactive Server listening socket is running", listen_thread_tag);
	unsigned short ret = RET_SUCCESS;

	// struct sockaddr client_addr;
	sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int session_cnt = 0;
	while (listen_exit == 0)
	{
		struct timeval tv;
		fd_set sock_set;
		tv.tv_sec = WAIT_CONNECTION_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&sock_set);
		FD_SET(server_fd, &sock_set);
		int res = select(server_fd + 1, &sock_set, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR)
		{
			WRITE_FORMAT_ERROR("select() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		else if (res == 0)
		{
			// WRITE_DEBUG("Accept timeout");
			continue;
		}		
// User telent to the server
		// int client_socketfd = accept(socketfd, &client_addr, (socklen_t*)&client_addr_len);
		// if (client_socketfd < 0)
		// {
		// 	WRITE_FORMAT_ERROR("accept() fails, due to: %s", strerror(errno));
		// 	return RET_FAILURE_SYSTEM_API;
		// }
		// struct sockaddr_in *client_s = (struct sockaddr_in *)&client_addr;
		// char client_ip[INET_ADDRSTRLEN + 1];
		// inet_ntop(AF_INET, &client_s->sin_addr, client_ip, sizeof(client_ip));
		int client_socketfd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_socketfd == -1)
		{
			WRITE_FORMAT_ERROR("accept() fails, due to: %s", strerror(errno));
			return RET_FAILURE_SYSTEM_API;
		}
		WRITE_FORMAT_DEBUG("Session Connection request from %s:%d", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));

// Initialize a session ......
		PINTERACTIVE_SESSION interactive_session = new InteractiveSession(this, manager, client_socketfd, client_addr, session_cnt);
		if (interactive_session == NULL)
		{
			WRITE_ERROR("Fail to allocate memory: interactive_session");
			return RET_FAILURE_INSUFFICIENT_MEMORY;
		}
		ret = interactive_session->initialize();
		if (CHECK_FAILURE(ret))
		{
			delete interactive_session;
			interactive_session = NULL;
			return ret;
		}
// Add a session into the container
		pthread_mutex_lock(&session_mtx);
		interactive_session_map[session_cnt] = interactive_session;
		pthread_mutex_unlock(&session_mtx);
		// PRINT("The Session[%s:%d] is Established......\n", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));
		PRINT("The Session[%s] is Established......\n", interactive_session->get_session_tag());
		session_cnt++;
	}

	WRITE_FORMAT_INFO("[%s] The worker thread of listening socket is dead", listen_thread_tag);
	return ret;
}

void InteractiveServer::listen_thread_cleanup_handler(void* pvoid)
{
	InteractiveServer* pthis = (InteractiveServer*)pvoid;
	if (pthis == NULL)
		throw std::invalid_argument("pvoid should NOT be NULL");
	pthis->listen_thread_cleanup_handler_internal();
}

void InteractiveServer::listen_thread_cleanup_handler_internal()
{
	WRITE_FORMAT_INFO("[%s] Cleanup the resource in the listen thread......", listen_thread_tag);
	INTERACTIVE_SESSION_ITER iter = interactive_session_map.begin();
	unsigned short ret = RET_SUCCESS;
	while(iter != interactive_session_map.end())
	{
		PINTERACTIVE_SESSION interactive_session = (PINTERACTIVE_SESSION)(iter->second);
		iter++;
		if (interactive_session != NULL)
		{
			ret = interactive_session->deinitialize();
			if (CHECK_FAILURE(ret))
				WRITE_FORMAT_ERROR("[%s] Fails to cleanup the session[%s], due to %s", interactive_session->get_session_tag(), GetErrorDescription(ret));
			delete interactive_session;
			interactive_session = NULL;
		}
	}
	interactive_session_map.clear();
}
