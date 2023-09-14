#ifndef FILE_TRANSFER
#define FILE_TRANSFER

#include <pthread.h>
#include <string>
#include "common.h"
#include "file_channel.h"


class FileTransfer
{
	DECLARE_MSG_DUMPER()

private:
public:
};
typedef FileTransfer* PFILE_TRANSFER;

#endif
