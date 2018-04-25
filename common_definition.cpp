#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include "common_definition.h"


using namespace std;

const unsigned short SHORT_STRING_SIZE = DEF_SHORT_STRING_SIZE;
const unsigned short STRING_SIZE = DEF_STRING_SIZE;
const unsigned short LONG_STRING_SIZE = DEF_LONG_STRING_SIZE;
const unsigned short EX_LONG_STRING_SIZE = DEF_EX_LONG_STRING_SIZE;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return values
const unsigned short RET_SUCCESS = 0;

const unsigned short RET_FAILURE_UNKNOWN = 1;
const unsigned short RET_FAILURE_INVALID_ARGUMENT = 2;
const unsigned short RET_FAILURE_INVALID_POINTER = 3;
const unsigned short RET_FAILURE_INSUFFICIENT_MEMORY = 4;
const unsigned short RET_FAILURE_INCORRECT_OPERATION = 5;
const unsigned short RET_FAILURE_OPEN_FILE = 6;
const unsigned short RET_FAILURE_NOT_FOUND = 7;
const unsigned short RET_FAILURE_INCORRECT_CONFIG = 8;
const unsigned short RET_FAILURE_INCORRECT_PATH = 9;
const unsigned short RET_FAILURE_IO_OPERATION = 10;
const unsigned short RET_FAILURE_HANDLE_THREAD = 11;
const unsigned short RET_FAILURE_SYSTEM_API = 12;

const unsigned short RET_FAILURE_CONNECTION_BASE = 0x100;
const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 1;
const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL = RET_FAILURE_CONNECTION_BASE + 2;
const unsigned short RET_FAILURE_CONNECTION_CLOSE = RET_FAILURE_CONNECTION_BASE + 3;
const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 4;
const unsigned short RET_FAILURE_CONNECTION_NO_SERVER = RET_FAILURE_CONNECTION_BASE + 5;
const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE = RET_FAILURE_CONNECTION_BASE + 6;

const char *GetErrorDescription(unsigned short ret)
{
	static const char *ret_description[] =
	{
		"Success",
		"Failure Unknown",
		"Failure Invalid Argument",
		"Failure Invalid Pointer",
		"Failure Insufficient Memory",
		"Failure Incorrect Operation",
		"Failure Open File",
		"Failure Not Found",
		"Failure Incorrect Config",
		"Failure Incorrect Path",
		"Failure IO Operation",
		"Failure Handle Thread",
		"Failure System API"
	};
	static const char *connection_ret_description[] =
	{
		"ConnectionFailure Base",
		"ConnectionFailure Try Timeout",
		"ConnectionFailure Try Fail",
		"ConnectionFailure Close",
		"ConnectionFailure Keepalive Timeout",
		"ConnectionFailure No Server",
		"ConnectionFailure Already in Use"
	};
	static int ret_description_len = sizeof(ret_description) / sizeof(ret_description[0]);
	static int connection_ret_description_len = sizeof(connection_ret_description) / sizeof(connection_ret_description[0]);

	if (ret >= RET_FAILURE_CONNECTION_BASE)
	{
		ret -= RET_FAILURE_CONNECTION_BASE;
		if (ret >= 0 && ret < connection_ret_description_len)
			return connection_ret_description[ret];
	}
	else
	{
		if (ret >= 0 && ret < ret_description_len)
			return ret_description[ret];
	}

	static char buf[STRING_SIZE];
	snprintf(buf, STRING_SIZE, "Unsupported Error Description: %d", ret);
	return buf;
}

const string CHECK_KEEPALIVE_TAG = string("!1@2#3$4%5^6&7*8");
const string CHECK_SERVER_CANDIDATE_TAG = string("*@ServerCandidate@*");
const int CHECK_KEEPALIVE_TAG_LEN = CHECK_KEEPALIVE_TAG.length();
const int CHECK_SERVER_CANDIDATE_TAG_LEN = CHECK_SERVER_CANDIDATE_TAG.length();
const string END_OF_PACKET = string("\r\n\r\n");
const int KEEPALIVE_DELAY_TIME = 3;
const int KEEPALIVE_PERIOD = 3;
const int MAX_CONNECTED_CLIENT = 5;

const char* CONF_FODLERNAME = "conf";
const int PORT_NO = 6802;
const int RECV_BUF_SIZE = 512;

//const unsigned short NOTIFY_DEAD_CLIENT = 0;
//const unsigned short NOTIFY_CHECK_KEEPALIVE = 1;
