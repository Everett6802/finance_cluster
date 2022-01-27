#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include "common.h"


using namespace std;

const unsigned short VERY_SHORT_STRING_SIZE = DEF_VERY_SHORT_STRING_SIZE;
const unsigned short SHORT_STRING_SIZE = DEF_SHORT_STRING_SIZE;
const unsigned short STRING_SIZE = DEF_STRING_SIZE;
const unsigned short LONG_STRING_SIZE = DEF_LONG_STRING_SIZE;
const unsigned short VERY_LONG_STRING_SIZE = DEF_VERY_LONG_STRING_SIZE;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Return values
const unsigned short RET_SUCCESS = 0;

const unsigned short RET_FAILURE_BASE = 1;
const unsigned short RET_FAILURE_UNKNOWN = RET_FAILURE_BASE + 0;
const unsigned short RET_FAILURE_RUNTIME = RET_FAILURE_BASE + 1;
const unsigned short RET_FAILURE_INVALID_ARGUMENT = RET_FAILURE_BASE + 2;
const unsigned short RET_FAILURE_INVALID_POINTER = RET_FAILURE_BASE + 3;
const unsigned short RET_FAILURE_INSUFFICIENT_MEMORY = RET_FAILURE_BASE + 4;
const unsigned short RET_FAILURE_INCORRECT_OPERATION = RET_FAILURE_BASE + 5;
const unsigned short RET_FAILURE_OPEN_FILE = RET_FAILURE_BASE + 6;
const unsigned short RET_FAILURE_NOT_FOUND = RET_FAILURE_BASE + 7;
const unsigned short RET_FAILURE_INCORRECT_CONFIG = RET_FAILURE_BASE + 8;
const unsigned short RET_FAILURE_INCORRECT_PATH = RET_FAILURE_BASE + 9;
const unsigned short RET_FAILURE_IO_OPERATION = RET_FAILURE_BASE + 10;
const unsigned short RET_FAILURE_HANDLE_THREAD = RET_FAILURE_BASE + 11;
const unsigned short RET_FAILURE_SYSTEM_API = RET_FAILURE_BASE + 12;
const unsigned short RET_FAILURE_INTERNAL_ERROR = RET_FAILURE_BASE + 13;
const unsigned short RET_FAILURE_END = 0xFF;

const unsigned short RET_FAILURE_CONNECTION_BASE = 0x100;
const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 0;
const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL = RET_FAILURE_CONNECTION_BASE + 1;
const unsigned short RET_FAILURE_CONNECTION_CLOSE = RET_FAILURE_CONNECTION_BASE + 2;
const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 3;
const unsigned short RET_FAILURE_CONNECTION_NO_SERVER = RET_FAILURE_CONNECTION_BASE + 4;
const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE = RET_FAILURE_CONNECTION_BASE + 5;
const unsigned short RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE = RET_FAILURE_CONNECTION_BASE + 6;
const unsigned short RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 7;
const unsigned short RET_FAILURE_CONNECTION_END = 0x1FF;

const unsigned short RET_WARN_BASE = 0x200;
const unsigned short RET_WARN_INTERACTIVE_COMMAND = RET_WARN_BASE + 0;
const unsigned short RET_WARN_SIMULATOR_NOT_INSTALLED = RET_WARN_BASE + 1;
const unsigned short RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND = RET_WARN_BASE + 2;
const unsigned short RET_WARN_FILE_TRANSFER_IN_PROCESS = RET_WARN_BASE + 3;
const unsigned short RET_WARN_END = 0x2FF;

const char *GetErrorDescription(unsigned short ret)
{
	static const char *ret_failure_description[] =
	{
		"Success",
		"Failure Unknown",
		"Failure Runtime",
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
		"Failure System API",
		"Failure Internal Error"
	};
	static const char *connection_ret_failure_description[] =
	{
		// "ConnectionFailure Base",
		"ConnectionFailure Try Timeout",
		"ConnectionFailure Try Fail",
		"ConnectionFailure Close",
		"ConnectionFailure Keepalive Timeout",
		"ConnectionFailure No Server",
		"ConnectionFailure Already in Use",
		"ConnectionFailure Message Incomplete",
		"ConnectionFailure Message Timeout"
	};
	static const char *ret_warn_description[] =
	{
		// "Warn Base",
		"Warn Interactive Command",
		"Warn Simulator Not Installed",
		"Warn Simulator Package Not Found",
		"Warn File Transfer in Process"
	};
	static int ret_failure_description_len = sizeof(ret_failure_description) / sizeof(ret_failure_description[0]);
	static int connection_ret_failure_description_len = sizeof(connection_ret_failure_description) / sizeof(connection_ret_failure_description[0]);
	static int ret_warn_description_len = sizeof(ret_warn_description) / sizeof(ret_warn_description[0]);

	unsigned short orig_ret = ret;
	if (ret >= RET_WARN_BASE)
	{
		ret -= RET_WARN_BASE;
		if (ret >= 0 && ret < ret_warn_description_len)
			return ret_warn_description[ret];
	}
	else if (ret >= RET_FAILURE_CONNECTION_BASE)
	{
		ret -= RET_FAILURE_CONNECTION_BASE;
		if (ret >= 0 && ret < connection_ret_failure_description_len)
			return connection_ret_failure_description[ret];
	}
	else if (ret >= RET_FAILURE_BASE)
	{
		if (ret >= 0 && ret < ret_failure_description_len)
			return ret_failure_description[ret];
	}

	static char buf[STRING_SIZE + 1];
	memset(buf, 0x0, sizeof(buf) / sizeof(buf[0]));
	snprintf(buf, STRING_SIZE, "Unsupported Error Description: %d", orig_ret);
	return buf;
}

bool SHOW_CONSOLE = true;
// const char* CHECK_KEEPALIVE_TAG = "!1@2#3$4%5^6&7*8";
// const string CHECK_SERVER_CANDIDATE_TAG = string("*@ServerCandidate@*");
// const int CHECK_KEEPALIVE_TAG_LEN = string(CHECK_KEEPALIVE_TAG).length();
// const int CHECK_SERVER_CANDIDATE_TAG_LEN = CHECK_SERVER_CANDIDATE_TAG.length();
const int MESSAGE_TYPE_LEN = 1;
const string END_OF_MESSAGE = std::string("\r\n\r\n");
const int END_OF_MESSAGE_LEN = END_OF_MESSAGE.length();

// const char* END_OF_PACKET = "\r\n\r\n";
const int KEEPALIVE_DELAY_TIME = 30;
const int KEEPALIVE_PERIOD = 60;
const int MAX_KEEPALIVE_CNT = 3;
const int MAX_CONNECTED_CLIENT = 5;
// const int MAX_INTERACTIVE_SESSION = 5;

const char* PROCESS_NAME = "finance_cluster";
const char* CONF_FODLERNAME = "conf";
const char* FINANCE_CLUSTER_CONF_FILENAME = "finance_cluster.conf";
const int BASE_PORT_NO = 5988;
const int CLUSTER_PORT_NO = BASE_PORT_NO + 0;
const int SESSION_PORT_NO = BASE_PORT_NO + 1;
const int FILE_TRANSFER_PORT_NO = BASE_PORT_NO + 2;
const int RECV_BUF_SIZE = 512;
const char* CLUSTER_UDS_FILEPATH = "/tmp/finance_cluster.socket";

const char* CONFIG_FOLDER_NAME = "conf";
const char* CONF_FIELD_CLUSTER_NETWORK = "cluster_network";
const char* CONF_FIELD_CLUSTER_NETMASK_DIGITS = "cluster_netmask_digits";
const char* CONF_FIELD_LOCAL_CLUSTER = "local_cluster";

const int PAYLOAD_SESSION_ID_DIGITS = 2;
const char* PAYLOAD_SESSION_ID_STRING_FORMAT = "%02d";
const int PAYLOAD_CLUSTER_ID_DIGITS = 2;
const char* PAYLOAD_CLUSTER_ID_STRING_FORMAT = "%02d";
//const unsigned short NOTIFY_DEAD_CLIENT = 0;
//const unsigned short NOTIFY_CHECK_KEEPALIVE = 1;
const int LOCAL_CLUSTER_SHM_BUFSIZE = 20;
const char* LOCAL_CLUSTER_TOKEN_SHM_FORMOAT = "node_token_%d";
const char* LOCAL_CLUSTER_SHM_FILENAME = "finance_cluster_cluster_token";
