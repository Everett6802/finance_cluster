#ifndef FILE_SENDER_H
#define FILE_SENDER_H

#include <pthread.h>
#include <string>
#include "common.h"
#include "file_channel.h"


class FileSender : public IFileTx
{
	DECLARE_MSG_DUMPER()

private:
	static const char* tx_listen_thread_tag;
	static const int WAIT_CONNECTION_TIMEOUT;

	PIMANAGER observer;
	bool local_cluster;
	char* local_token;
	int tx_socketfd; // For file transfer
// For file transfer
	pthread_mutex_t tx_mtx;
	volatile int tx_listen_exit;
	pthread_t tx_listen_tid;
	volatile unsigned short tx_listen_thread_ret;
	int tx_session_id;
	char* tx_filepath;
	PNOTIFY_THREAD notify_thread;

	std::map<std::string, PFILE_CHANNEL> file_channel_map;
	pthread_mutex_t file_channel_mtx;

	unsigned short remove_file_channel(const std::string& node_token);
	unsigned short become_file_sender();
	unsigned short start_file_transfer();
	unsigned short stop_file_transfer();

	static void* tx_listen_thread_handler(void* pvoid);
	unsigned short tx_listen_thread_handler_internal();
	static void tx_listen_thread_cleanup_handler(void* pvoid);
	void tx_listen_thread_cleanup_handler_internal();

public:
	FileSender(PIMANAGER parent, const char* token=NULL); // token is NULL for local cluster
	virtual ~FileSender();

// Interface
// IFileTx
	virtual unsigned short initialize();
	virtual unsigned short deinitialize();
// IParam
    virtual unsigned short set(ParamType param_type, void* param1=NULL, void* param2=NULL);
    virtual unsigned short get(ParamType param_type, void* param1=NULL, void* param2=NULL);
// INotify
    virtual unsigned short notify(NotifyType notify_type, void* notify_param=NULL);
	virtual unsigned short async_handle(NotifyCfg* notify_cfg);
};
typedef FileSender* PFILE_TRANSFER;

#endif
