#include <signal.h>
#include "cluster_mgr.h"
#include "common.h"

// extern ClusterMgr cluster_mgr;

// Paramters
static bool param_help = false;
static char* param_join = NULL;

static const int ERRMSG_SIZE = 256;
static char errmsg[ERRMSG_SIZE];

static ClusterMgr cluster_mgr;

static void signal_handler(int signo);
// static void copy_param(const char* src_param, char** dst_param);
static void print_errmsg(const char* errmsg);
static void print_errmsg_and_exit(const char* errmsg);
static unsigned short parse_param(int argc, char** argv);
static unsigned short check_param();
static unsigned short setup_param(ClusterMgr& cluster_mgr);

DECLARE_AND_IMPLEMENT_STATIC_MSG_DUMPER();

static void signal_handler(int signo)
{
	switch(signo)
	{
		case SIGTERM:
		{
			PRINT("SIGTERM Caught, the Finance Analyzer process[%d] is going to die......\n", getpid());
            cluster_mgr.deinitialize();
            exit(EXIT_FAILURE);
   		}
		break;
		case SIGINT:
		{
			PRINT("SIGINT Caught, the Finance Analyzer process[%d] is going to die......\n", getpid());
            cluster_mgr.deinitialize();
            exit(EXIT_FAILURE);
		}
		break;
		// default:
		// {
		// 	snprintf(errmsg, ERRMSG_SIZE,"UnExpected Signal[%d] Caught !!!", signo);
		// 	print_errmsg_and_exit(errmsg);
		// }
		// break;
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
	if (param_help)
	{
		FPRINT(stdout, "%s\n", "'help' is enabled, so other parameters are ignored");
	}
	// static const int ERROR_MSG_SIZE = 256;
	// static char error_msg[ERROR_MSG_SIZE];
	return RET_SUCCESS;
}

unsigned short setup_param(ClusterMgr& cluster_mgr)
{
	unsigned short ret = RET_SUCCESS;
	if (param_join != NULL)
	{
		ret = cluster_mgr.set_cluster_ip(param_join);
		if (CHECK_FAILURE(ret))
			return ret;
	}

	return RET_SUCCESS;
}

#include <string>
int main(int argc, char** argv)
{
	// const int RSP_BUF_VERY_SHORT_SIZE = 32;
	// const int RSP_BUF_SIZE = 256;
	// char buf[RSP_BUF_SIZE];
	// int node_id = 1;
	// bool is_local_node = true;
	// std::string node_ip("10.206.24.219");
	// char cluster_node_ip[RSP_BUF_VERY_SHORT_SIZE];
	// snprintf(cluster_node_ip, RSP_BUF_VERY_SHORT_SIZE, "%s", node_ip.c_str());
	// fprintf(stderr, "%s %d\n", cluster_node_ip, strlen(cluster_node_ip));
	// snprintf(buf, RSP_BUF_SIZE, (is_local_node ? "%d %s *\n" : "%d %s\n"), node_id, cluster_node_ip);
	// fprintf(stderr, "%s\n", buf);

	// std::string my_str("0123456789");
	// std::string my_tag("89");
	// size_t pos = my_str.find(my_tag);
	// fprintf(stderr, "%s\n", my_str.substr(1, pos-1).c_str());
	// exit(0);

	// char* message = NULL;
	// int buf_size = MESSAGE_TYPE_LEN + (message != NULL ? strlen(message) : 0) + END_OF_MESSAGE_LEN + 1;
	// MessageType message_type = (MessageType)257; //MSG_CHECK_KEEPALIVE;
	// fprintf(stderr, "message_type: %d, message: %s, buf_size: %d\n", message_type, message, buf_size);
	// char* full_message_buf = new char[buf_size];
	// if (message != NULL)
	// {
	// 	snprintf(full_message_buf, buf_size, "%c%s%s", message_type, message, END_OF_MESSAGE.c_str());
	// }
	// else
	// {
	// 	snprintf(full_message_buf, buf_size, "%c%s", message_type, END_OF_MESSAGE.c_str());
	// 	// snprintf(full_message_buf, buf_size, "%d", message_type);
	// }
	// fprintf(stderr, "assemble message: %s, assemble message length: %d\n", full_message_buf, strlen(full_message_buf));
	// fprintf(stderr, "parser, message type: %d\n", GET_MSG_TYPE(full_message_buf));

	// std::string system_info;
	// get_system_info(system_info);
	// printf("system info:%s\n", system_info.c_str());

	// exit(0);

	// ClusterMap cluster_map;
	// cluster_map.from_string("0:192.17.30.217;1:192.17.30.218;2:192.17.30.219");
	// printf("Map: %s\n", cluster_map.to_string());
	// cluster_map.add_node(3, "192.17.30.220");
	// printf("Map: %s\n", cluster_map.to_string());
	// unsigned ret_test = cluster_map.delete_node(2);
	// printf("Map: %s\n", cluster_map.to_string());
	// printf("Res: %d\n", ret_test);
	// // ClusterNode node1(1, "192.17.30.220");
	// // ClusterNode node2(2, "192.17.30.220");
	// // printf("%s\n", (node1 == node2 ? "True" : "False"));
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

	unsigned short ret = RET_SUCCESS;

	parse_param(argc, argv);
	check_param();

	if (param_help)
		show_usage_and_exit();

	ret = setup_param(cluster_mgr);
	if (CHECK_FAILURE(ret))
	{
		snprintf(errmsg, ERRMSG_SIZE, "setup_param() fails, due to: %s", GetErrorDescription(ret));
		print_errmsg_and_exit(errmsg);
	}

	printf("Start the Node...\n");

	// ret = cluster_mgr.start();
	ret = cluster_mgr.initialize();
	if (CHECK_FAILURE(ret))
	{
		// fprintf(stderr, "Fail to initialize...\n");
		// exit(EXIT_FAILURE);
		print_errmsg_and_exit("Fail to initialize...");
	}

	getchar();
	if (!cluster_mgr.is_leader())
	{
		const char* msg;
		msg = "This is a test 1";
		printf("SND: %s\n", msg);
		cluster_mgr.transmit_text(msg);
		getchar();	
		// msg = "This is a test 2";
		// printf("SND: %s\n", msg);
		// cluster_mgr.transmit_text(msg);
		// getchar();
		// msg = "This is a test 3";
		// printf("SND: %s\n", msg);
		// cluster_mgr.transmit_text(msg);
		// getchar();	
	}

	// ret = cluster_mgr.wait_to_stop();
	printf("Stop the Node\n");
	ret = cluster_mgr.deinitialize();
	if (CHECK_FAILURE(ret))
	{
		// fprintf(stderr, "Fail to waiting for stop...\n");
		// exit(EXIT_FAILURE);
		print_errmsg_and_exit("Fail to de-initialize...");
	}

	getchar();
	printf("The Node is Stopped......\n");

	exit(EXIT_SUCCESS);
}
