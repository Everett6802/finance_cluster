#ifndef FILE_CHANNEL
#define FILE_CHANNEL

#include <pthread.h>
#include <string>
#include "common.h"


class LeaderNode;
class FollowerNode;

class FileChannel
{
	friend class LeaderNode;
	friend class FollowerNode;

	DECLARE_MSG_DUMPER()

	static const char* thread_tag;
	static const int WAIT_DATA_TIMEOUT;
	static const long MAX_BUF_SIZE;

private:
	PINODE observer;
	volatile int exit;
    std::string node_token;
    std::string remote_token;
    bool is_sender;
	pthread_t send_tid;
	pthread_t recv_tid;
	char* tx_filepath;
	int tx_socket;
	int tx_session_id; // For sender only
	FILE* tx_fp;   	
	char* tx_buf;
	// std::list<char*> send_buffer_list;
	std::list<char*> send_access_list;

	pthread_mutex_t mtx_buffer;
	pthread_cond_t cond_buffer;

	unsigned short send_thread_ret;
	unsigned short recv_thread_ret;
	bool send_msg_trigger;

	static void* send_thread_handler(void* pvoid);
	unsigned short send_thread_handler_internal();
	static void send_thread_cleanup_handler(void* pvoid);
	void send_thread_cleanup_handler_internal();
	static void* recv_thread_handler(void* pvoid);
	unsigned short recv_thread_handler_internal();
	static void recv_thread_cleanup_handler(void* pvoid);
	void recv_thread_cleanup_handler_internal();
	void clearall();

	FileChannel(PINODE node);
	~FileChannel();
	unsigned short initialize(const char* filepath, const char* channel_token, const char* channel_remote_token, int channel_socket, bool sender=false, bool session_id=-1/*Only for sender*/);
	unsigned short deinitialize();
	void notify_exit();
	const char* get_token()const;
	const char* get_remote_token()const;

	unsigned short request_transfer();
	// unsigned short complete_transfer();
};
typedef FileChannel* PFILE_CHANNEL;

#endif
