#include <signal.h>
#include "cluster_mgr.h"
#include "common.h"

// extern ClusterMgr cluster_mgr;

// Paramters
static bool param_help = false;
static char* param_join = NULL;

static const int ERRMSG_SIZE = 256;
static char errmsg[ERRMSG_SIZE];

static void signal_handler(int signo);
// static void copy_param(const char* src_param, char** dst_param);
static void print_errmsg(const char* errmsg);
static void print_errmsg_and_exit(const char* errmsg);
static unsigned short parse_param(int argc, char** argv);
static unsigned short check_param();
static unsigned short setup_param();

DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER();

static void signal_handler(int signo)
{
	switch(signo)
	{
		case SIGTERM:
		{
			PRINT("SIGTERM Caught, the Finance Analyzer process[%d] is going to die......\n", getpid());
		}
		break;
		case SIGINT:
		{
			PRINT("SIGINT Caught, the Finance Analyzer process[%d] is going to die......\n", getpid());
		}
		break;
		default:
		{
			snprintf(errmsg, ERRMSG_SIZE,"UnExpected Signal[%d] Caught !!!", signo);
			print_errmsg_and_exit(errmsg);
		}
		break;
	}
	sleep(1);
	exit(EXIT_SUCCESS);
}


void show_usage_and_exit()
{
	PRINT("====================== Usage ======================\n");
	PRINT("-h|--help\n Description: The usage\n Caution: Other flags are ignored\n");
	PRINT("-j|--join\n Description: Join a cluster\n");
	PRINT("===================================================\n");
	exit(EXIT_SUCCESS);
}

void print_errmsg(const char* errmsg)
{
	assert(errmsg != NULL && "errmsg != NULL");
	WRITE_ERROR(errmsg);
	FPRINT(stderr, "%s\n", errmsg);
}

void print_errmsg_and_exit(const char* errmsg)
{
	print_errmsg(errmsg);
	exit(EXIT_FAILURE);
}

unsigned short parse_param(int argc, char** argv)
{
	int index = 1;
	int offset;
	for (; index < argc ; index += offset)
	{
        if ((strcmp(argv[index], "--help") == 0) || (strcmp(argv[index], "-h") == 0))
		{
			param_help = true;
			offset = 1;
		}
		else if ((strcmp(argv[index], "--join") == 0) || (strcmp(argv[index], "-j") == 0))
		{
			if (index + 1 >= argc)
				print_errmsg_and_exit("No argument found in 'join' parameter");
			param_join = argv[index + 1];
			offset = 2;
		}
		else
		{
			FPRINT(stderr, "Unknown parameter: %s\n", argv[index]);
			return RET_FAILURE_INVALID_ARGUMENT;
		}
	}
	return RET_SUCCESS;
}

unsigned short check_param()
{
	// static const int ERROR_MSG_SIZE = 256;
	// static char error_msg[ERROR_MSG_SIZE];
	return RET_SUCCESS;
}

unsigned short setup_param()
{
	return RET_SUCCESS;
}


int main(int argc, char** argv)
{
	// IPv4Addr ipv4_addr("172.17.83.40");
	// printf("Res: %s\n", (ipv4_addr.is_same_network(24, "172.17.83.0") ? "True" : "False"));
	// printf("Res: %s\n", (ipv4_addr.is_same_network(24, "172.17.84.0") ? "True" : "False"));
	// printf("Res: %s\n", (ipv4_addr.is_same_network(23, "172.17.84.0") ? "True" : "False"));
	// exit(EXIT_SUCCESS);
// Register the signals so that the process can exit gracefully
	struct sigaction sa;
	memset(&sa, 0x0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = &signal_handler;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		print_errmsg_and_exit("Fail to register the signal: SIGTERM");
	if (sigaction(SIGINT, &sa, NULL) == -1)
		print_errmsg_and_exit("Fail to register the signal: SIGINT");

	parse_param(argc, argv);
	check_param();
	setup_param();

	ClusterMgr cluster_mgr;
	printf("Start the Node...\n");

	unsigned short ret = cluster_mgr.start();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to initialize...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	ret = cluster_mgr.wait_to_stop();
	if (CHECK_FAILURE(ret))
	{
		fprintf(stderr, "Fail to waiting for stop...\n");
		exit(EXIT_FAILURE);
	}

	getchar();
	printf("The Node is Stopped......\n");

	exit(EXIT_SUCCESS);
}
