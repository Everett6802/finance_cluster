#ifndef FILE_RECEIVER_H
#define FILE_RECEIVER_H

#include <pthread.h>
#include <string>
#include "common.h"
#include "file_channel.h"


class FileReceiver : public IFileTx
{
	DECLARE_MSG_DUMPER()
	DECLARE_EVT_RECORDER()

private:
	static const int WAIT_CONNECTION_TIMEOUT;

	PIMANAGER observer;
	int tx_socketfd; // For file transfer
	bool local_cluster;
	char* local_token;
	char* sender_token;
	PNOTIFY_THREAD notify_thread;
	PFILE_CHANNEL file_channel;

	unsigned short connect_file_sender();
	unsigned short request_file_transfer(const char* tx_filepath);
	unsigned short complete_file_transfer();

public:
	FileReceiver(PIMANAGER parent, const char* server_token=NULL, const char* token=NULL);  // server_token/token is NULL for local cluster
	virtual ~FileReceiver();

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
typedef FileReceiver* PFILE_RECEIVER;

#endif
