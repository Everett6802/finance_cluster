#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include "msg_cluster_common.h"

using namespace std;


const unsigned short RET_SUCCESS = 0;

const unsigned short RET_FAILURE_UNKNOWN = 1;
const unsigned short RET_FAILURE_INVALID_ARGUMENT = 2;
const unsigned short RET_FAILURE_INVALID_POINTER = 3;
const unsigned short RET_FAILURE_INSUFFICIENT_MEMORY = 4;
const unsigned short RET_FAILURE_INCORRECT_OPERATION = 5;
const unsigned short RET_FAILURE_NOT_FOUND = 6;
const unsigned short RET_FAILURE_INCORRECT_CONFIG = 7;
const unsigned short RET_FAILURE_HANDLE_THREAD = 8;
const unsigned short RET_FAILURE_INCORRECT_PATH = 9;
const unsigned short RET_FAILURE_IO_OPERATION = 10;
const unsigned short RET_FAILURE_SYSTEM_API = 11;

const unsigned short RET_FAILURE_CONNECTION_BASE = 0x100;
const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 1;
const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL = RET_FAILURE_CONNECTION_BASE + 2;
const unsigned short RET_FAILURE_CONNECTION_CLOSE = RET_FAILURE_CONNECTION_BASE + 3;
const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 4;
const unsigned short RET_FAILURE_CONNECTION_NO_SERVER = RET_FAILURE_CONNECTION_BASE + 5;
const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE = RET_FAILURE_CONNECTION_BASE + 6;

const char *RetDescription[] =
{
	"Success",
	"Failure Unknown",
	"Failure Invalid Argument",
	"Failure Invalid Pointer",
	"Failure Insufficient Memory",
	"Failure Incorrect Operation",
	"Failure Not Found",
	"Failure Incorrect Config",
	"Failure Handle Thread",
	"Failure Incorrect Path",
	"Failure IO Operation",
	"Failure System API"
};

const char *ConnectionRetDescription[] =
{
	"ConnectionFailure Base",
	"ConnectionFailure Try Timeout",
	"ConnectionFailure Try Fail",
	"ConnectionFailure Close",
	"ConnectionFailure Keepalive Timeout",
	"ConnectionFailure No Server",
	"ConnectionFailure Already in Use"
};

const char *GetErrorDescription(short error_code)
{
	if (error_code > RET_FAILURE_CONNECTION_BASE)
		return ConnectionRetDescription[error_code - RET_FAILURE_CONNECTION_BASE];
	else
		return RetDescription[error_code];
}

const unsigned short SHORT_STRING_SIZE = 32;
const unsigned short STRING_SIZE = 64;
const unsigned short LONG_STRING_SIZE = 256;
const unsigned short EX_LONG_STRING_SIZE = LONG_STRING_SIZE * 2;

const string CHECK_KEEPALIVE_TAG = string("!1@2#3$4%5^6&7*8");
const string CHECK_SERVER_CANDIDATE_TAG = string("*@ServerCandidate@*");
const int CHECK_KEEPALIVE_TAG_LEN = CHECK_KEEPALIVE_TAG.length();
const string END_OF_PACKET = string("\r\n\r\n");
const int KEEPALIVE_DELAY_TIME = 3;
const int KEEPALIVE_PERIOD = 3;

const char* CONF_FODLERNAME = "conf";
const int PORT_NO = 6802;
const int RECV_BUF_SIZE = 512;

void sigroutine(int signo)
{
  switch (signo)
  {
    case SIGALRM:
      printf("Catch a signal -- SIGALRM \n");
      signal(SIGALRM, sigroutine);
      break;
    case SIGVTALRM:
      printf("Catch a signal -- SIGVTALRM \n");
      signal(SIGVTALRM, sigroutine);
      break;
  }
}
