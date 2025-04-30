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
const unsigned short RET_FAILURE_INCORRECT_VALUE = RET_FAILURE_BASE + 14;
const unsigned short RET_FAILURE_RESOURCE_BUSY = RET_FAILURE_BASE + 15;
///// Connection Related /////
const unsigned short RET_FAILURE_CONNECTION_BASE = 0x100;
const unsigned short RET_FAILURE_CONNECTION_ERROR = RET_FAILURE_CONNECTION_BASE + 0;
const unsigned short RET_FAILURE_CONNECTION_TRY_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 1;
const unsigned short RET_FAILURE_CONNECTION_TRY_FAIL = RET_FAILURE_CONNECTION_BASE + 2;
const unsigned short RET_FAILURE_CONNECTION_CLOSE = RET_FAILURE_CONNECTION_BASE + 3;
const unsigned short RET_FAILURE_CONNECTION_KEEPALIVE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 4;
const unsigned short RET_FAILURE_CONNECTION_NO_SERVER = RET_FAILURE_CONNECTION_BASE + 5;
const unsigned short RET_FAILURE_CONNECTION_ALREADY_IN_USE = RET_FAILURE_CONNECTION_BASE + 6;
const unsigned short RET_FAILURE_CONNECTION_MESSAGE_INCOMPLETE = RET_FAILURE_CONNECTION_BASE + 7;
const unsigned short RET_FAILURE_CONNECTION_MESSAGE_TIMEOUT = RET_FAILURE_CONNECTION_BASE + 8;
const unsigned short RET_FAILURE_CONNECTION_END = 0x1FF;
///// Connection Related /////
const unsigned short RET_FAILURE_END = 0xFFF;

const unsigned short RET_WARN_BASE = 0x1000;
const unsigned short RET_WARN_INTERACTIVE_COMMAND = RET_WARN_BASE + 0;
const unsigned short RET_WARN_INTERACTIVE_CONFIG_COMMAND = RET_WARN_BASE + 1;
const unsigned short RET_WARN_SIMULATOR_NOT_INSTALLED = RET_WARN_BASE + 2;
const unsigned short RET_WARN_SIMULATOR_PACKAGE_NOT_FOUND = RET_WARN_BASE + 3;
const unsigned short RET_WARN_FILE_TRANSFER_IN_PROCESS = RET_WARN_BASE + 4;
const unsigned short RET_WARN_CLUSTER_NOT_SINGLE = RET_WARN_BASE + 5;
const unsigned short RET_WARN_REMOTE_FILE_TRANSFER_FAILURE = RET_WARN_BASE + 6;
const unsigned short RET_WARN_END = 0x10FF;

bool SHOW_CONSOLE = true;
// const char* CHECK_KEEPALIVE_TAG = "!1@2#3$4%5^6&7*8";
// const string CHECK_SERVER_CANDIDATE_TAG = string("*@ServerCandidate@*");
// const int CHECK_KEEPALIVE_TAG_LEN = string(CHECK_KEEPALIVE_TAG).length();
// const int CHECK_SERVER_CANDIDATE_TAG_LEN = CHECK_SERVER_CANDIDATE_TAG.length();
const int MESSAGE_TYPE_LEN = sizeof(char);
const int MESSAGE_SIZE_LEN = sizeof(unsigned int);
const char* END_OF_MESSAGE = "\r\n\r\n";  // std::string("\r\n\r\n");
const int END_OF_MESSAGE_LEN = strlen(END_OF_MESSAGE);  // END_OF_MESSAGE.length();
const int MESSAGE_FIXED_SIZE_LEN = MESSAGE_TYPE_LEN + MESSAGE_SIZE_LEN + END_OF_MESSAGE_LEN;

// const char* END_OF_PACKET = "\r\n\r\n";
const int KEEPALIVE_DELAY_TIME = 30;
const int KEEPALIVE_PERIOD = 60;
const int MAX_KEEPALIVE_CNT = 3;
const int MAX_CONNECTED_CLIENT = 5;
// const int MAX_INTERACTIVE_SESSION = 5;

const char* PROCESS_NAME = "finance_cluster";
const char* CONF_FODLERNAME = "conf";
const char* FINANCE_CLUSTER_CONF_FILENAME = "finance_cluster.conf";
const int BASE_PORT_NO = 8588;
const int CLUSTER_PORT_NO = BASE_PORT_NO + 0;
const int SESSION_PORT_NO = BASE_PORT_NO + 1;
const int FILE_TRANSFER_PORT_NO = BASE_PORT_NO + 2;
const int RECV_BUF_SIZE = 512;
const char* CLUSTER_UDS_FILEPATH = "/tmp/finance_cluster.sock";
const char* SHM_FOLDERPATH = "/dev/shm/sim";
const char* RPM_DATA_FILEPATH_FORMAT = "/dev/shm/sim/%s/rpm/%s/%s";

const char* CONFIG_FOLDER_NAME = "conf";
const char* CONF_FIELD_CLUSTER_NETWORK = "cluster_network";
const char* CONF_FIELD_CLUSTER_NETMASK_DIGITS = "cluster_netmask_digits";
const char* CONF_FIELD_LOCAL_CLUSTER = "local_cluster";
const char* CONF_FIELD_SYSTEM_MONITOR_PERIOD = "system_monitor_period";
const char* CONF_FIELD_SYNC_FOLDERPATH = "sync_folderpath";
const char* CONF_FIELD_LIST[] = {
    CONF_FIELD_CLUSTER_NETWORK,
    CONF_FIELD_CLUSTER_NETMASK_DIGITS,
    CONF_FIELD_LOCAL_CLUSTER,
    CONF_FIELD_SYSTEM_MONITOR_PERIOD,
    CONF_FIELD_SYNC_FOLDERPATH
};
const int CONF_FIELD_LIST_SIZE = sizeof(CONF_FIELD_LIST) / sizeof(CONF_FIELD_LIST[0]);

const int PAYLOAD_SESSION_ID_DIGITS = 2;
const char* PAYLOAD_SESSION_ID_STRING_FORMAT = "%02d";
const int PAYLOAD_CLUSTER_ID_DIGITS = 2;
const char* PAYLOAD_CLUSTER_ID_STRING_FORMAT = "%02d";
//const unsigned short NOTIFY_DEAD_CLIENT = 0;
//const unsigned short NOTIFY_CHECK_KEEPALIVE = 1;
const int LOCAL_CLUSTER_SHM_BUFSIZE = 20;
const char* LOCAL_CLUSTER_TOKEN_SHM_FORMOAT = "node_token_%d";
const char* LOCAL_CLUSTER_SHM_FILENAME = "finance_cluster_cluster_token";
