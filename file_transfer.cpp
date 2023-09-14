#include "file_transfer.h"


using namespace std;

FileTransfer::FileTransfer(PINODE node)
{
	IMPLEMENT_MSG_DUMPER()
	observer = node;
	assert(observer != NULL && "observer should NOT be NULL");
}

FileTransfer::~FileTransfer()
{
	RELEASE_MSG_DUMPER()
}

unsigned short FileTransfer::initialize(const char* filepath, const char* channel_token, const char* channel_remote_token, int channel_socket, bool sender, bool session_id)
{
	return RET_SUCCESS;
}

unsigned short FileTransfer::deinitialize()
{
	WRITE_DEBUG("Release resource in FileTransfer......");
	unsigned short ret = RET_SUCCESS;
	return ret;
}
