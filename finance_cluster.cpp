#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <syslog.h>
#include "cluster_mgr.h"
#include "common.h"

// extern ClusterMgr cluster_mgr;

// Paramters
static bool param_help = false;
static char* param_join = NULL;
static bool param_detach = false;

static const int ERRMSG_SIZE = 256;
static char errmsg[ERRMSG_SIZE + 1];

static ClusterMgr cluster_mgr;

static void signal_handler(int signo);
// static void copy_param(const char* src_param, char** dst_param);
static void print_errmsg(const char* errmsg);
static void print_errmsg_and_exit(const char* errmsg);
static unsigned short parse_param(int argc, char** argv);
static unsigned short check_param();
static unsigned short setup_param(ClusterMgr& cluster_mgr);
static void detach_from_terminal();

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
	// sleep(1);
	usleep(100000);
	exit(EXIT_SUCCESS);
}

void show_usage_and_exit()
{
	PRINT("====================== Usage ======================\n");
	PRINT("-h|--help\n Description: The usage\n Caution: Other flags are ignored\n");
	PRINT("-j|--join\n Description: Join a cluster\n Caution: Only for TCP connection");
	// PRINT("-d|--detach\n Description: Detach from the terminal\n");
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
		// else if ((strcmp(argv[index], "--detach") == 0) || (strcmp(argv[index], "-d") == 0))
		// {
		// 	param_detach = true;
		// 	offset = 1;
		// }
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
		ret = cluster_mgr.set_cluster_token(param_join);
		if (CHECK_FAILURE(ret))
			goto OUT;			
	}
OUT:
	return ret;
}

void detach_from_terminal() 
{ 
// Step 1: Fork off the parent process
 	pid_t pid = fork();
 	// exit(0);
  	if (pid < 0) exit(EXIT_FAILURE);
	if (pid > 0) exit(EXIT_SUCCESS);
// Step 2: Create a unique session ID
	if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
// Step 3: Change the working directory
	chdir("/"); 
// Step 4: Close the standard file descriptors
	int fd = open("/dev/null", O_RDWR, 0);
	if (fd != -1) 
	{
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2) close(fd);
	}
// Step 5: Change the file mode mask
	umask(0027);	
    /* Open the log file */
    openlog ("firstdaemon", LOG_PID, LOG_SYSLOG);
}

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <string>

using namespace std;

// #ifndef MACSTR
// #define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
// #endif
// #ifndef STR2MAC
// #define STR2MAC(a) (unsigned int*)&(a)[0], (unsigned int*)&(a)[1], \
//     (unsigned int*)&(a)[2], (unsigned int*)&(a)[3], \
//     (unsigned int*)&(a)[4], (unsigned int*)&(a)[5]
// #endif

int main(int argc, char** argv)
{
    // char *filename = "/home/super/simulator.tar.xz";
    // char *extension = strchr(filename, '.');  // Find the last dot in the filename
    // int res = strcmp(extension, ".tar.xz1");
    // printf("extension: %s, res: %d\n", extension, res);    

	// int my_value = 4;
	// int my_bufsize = sizeof(int);
	// char* my_buf = new char[my_bufsize];
	// memset(my_buf, 0x0, sizeof(char) * my_bufsize);
	// memcpy(my_buf, &my_value, sizeof(int));
	// int my_value1;
	// memcpy(&my_value1, my_buf, sizeof(int));
	// printf("value[%d]: %s, %d\n", my_value, my_buf, atoi(my_buf));
	// printf("value1[%d]\n", my_value1);
	// FakeAcsptControlType fake_acspt_control_type = FAKE_ACSPT_STOP;
	// size_t notify_param_size = sizeof(FakeAcsptControlType);
	// NotifyFakeAcsptControlCfg* notify_cfg = new NotifyFakeAcsptControlCfg((void*)&fake_acspt_control_type, notify_param_size);
	// printf("fake_acspt_control_type: %d, notify_param_size: %d\n", notify_cfg->get_fake_acspt_control_type(), notify_param_size);
	// char* test = "Test";
	// printf("len: %d\n", strlen(test));
 //    exit(0);

	// char* my_mac = "04:2A:4D:AE:53:D7";
	// unsigned int my_mac_int[6];
	// sscanf(my_mac, MACSTR, STR2MAC(my_mac_int));
	// for (int i = 0; i < 6 ; i++)
	// {
	// 	printf("%d %02x\n", i, my_mac_int[i]);
	// }
	// exit(0);
	// char buf[32] = {'\0'};
	// float value = 32.47;
	// snprintf(buf, 32 , "Test: %.2f %\n", value);
	// printf(buf);
	// exit(0);
	// const char* process_name = "finance_cluster";
	// int process_count;
	// get_process_count(process_name, process_count);
	// fprintf(stderr, "process_count: %d\n", process_count);
	// sockaddr_un un;
	// fprintf(stderr, "sockaddr_un size: %d\n", sizeof(un));
	// exit(EXIT_SUCCESS);
	// fprintf(stderr, "pid: %d\n", getpid());

//     struct dirent *entry = nullptr;
//     DIR *dp = nullptr;

//     dp = opendir("/dev/shm/sim");
//     if (dp != nullptr) {
//         while ((entry = readdir(dp)))
//         {
// // You can't (usefully) compare strings using != or ==, you need to use strcmp
// // The reason for this is because != and == will only compare the base addresses of those strings. 
// // Not the contents of the strings themselves.
//         	if (strcmp(entry->d_name, "apgroup") == 0 || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
//         		continue;
//             printf ("%s\n", entry->d_name);
//         }
//     }

//     closedir(dp);
// 	exit(0);

//  	char* filepath = "/dev/shm/sim/00:01:88:01:35:64/rpm/wsgclientsim/ssn";
//  	FILE* fp = fopen(filepath, "r");
// 	if (fp == NULL)
// 	{
// 		fprintf(stderr, "fopen() fails\n");
// 		exit(0);
// 	}
// 	static const int BUF_SIZE = 512;
// 	static char line_buf[BUF_SIZE];
// 	int last_character_in_string_index = 0;
// 	while (fgets(line_buf, BUF_SIZE, fp) != NULL) 
// 	{
// 		// if (line_buf[0] == '\n' || line_buf[0] == '#')
// 		// {
// 		// 	if (ignore_comment)
// 		// 		continue;
// 		// }
// 		last_character_in_string_index = strlen(line_buf) - 1;
// 		if (line_buf[last_character_in_string_index] == '\n')
// 			line_buf[last_character_in_string_index] = '\0';
// 		printf("line: %s\n", line_buf);
// 		// string line_str(line_buf);
// 		// line_list.push_back(line_str);
// 	}
// // OUT:
// 	if (fp != NULL)
// 	{
// 		fclose(fp);
// 		fp = NULL;
// 	}
// 	exit(0);

	// char* token;
	// char* line = "Model name:                      Intel(R) Core(TM) i7-3770 CPU @ 3.40GHz";
	// char* line_tmp = strdup(line);
	// char* rest;
	// token = strtok_r(line_tmp, ":", &rest);
	// printf("token: %s, rest: %s\n", token, rest);
	// token = strtok_r(NULL, ":", &rest);
	// printf("token: %s, rest: %s\n", token, rest);
	// exit(0);

// 	const char* LOCAL_CLUSTER_SHM_FILENAME = "cluster_shm_file";

// 	printf("shm_unlink: %s\n", LOCAL_CLUSTER_SHM_FILENAME);
// 	shm_unlink(LOCAL_CLUSTER_SHM_FILENAME);
// 	printf("shm_open: %s, create !!!\n", LOCAL_CLUSTER_SHM_FILENAME);
//   	int shm_fd1 = shm_open(LOCAL_CLUSTER_SHM_FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
//    	if (shm_fd1 < 0) 
//   	{
//   		fprintf(stderr, "shm_open() fails, due to : %s\n", strerror(errno));
//   		exit(1);
//   	}
// 	printf("shm_unlink: %s\n", LOCAL_CLUSTER_SHM_FILENAME);
// 	shm_unlink(LOCAL_CLUSTER_SHM_FILENAME);
// // // The /dev/shm/finance_cluster_cluster_token file is created
// // 	printf("shm_open: %s, create !!!\n", LOCAL_CLUSTER_SHM_FILENAME);
// //   	int shm_fd2 = shm_open(LOCAL_CLUSTER_SHM_FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
// //    	if (shm_fd2 < 0) 
// //   	{
// //   		fprintf(stderr, "shm_open() fails, due to : %s\n", strerror(errno));
// //   		exit(1);
// //   	}
// 	exit(0);

	// const char* test_string = "Damn";
	// int test_string_len = strlen(test_string);
	// printf("test_string_len: %d\n", test_string_len);
	// char* test_buf1 = new char[test_string_len + 1];
	// memset(test_buf1, 0x0, sizeof(char) * (test_string_len + 1));
	// memcpy(test_buf1, test_string, sizeof(char) * test_string_len);
	// printf("test_buf1: %s, %d\n", test_buf1, strlen(test_buf1));
	// char* test_buf2 = new char[test_string_len];
	// memset(test_buf2, 0x0, sizeof(char) * test_string_len);
	// memcpy(test_buf2, test_string, sizeof(char) * test_string_len);
	// printf("test_buf2: %s, %d\n", test_buf2, strlen(test_buf2));

	// char my_str[] = "Fuck";
	// printf("%d, %d\n", sizeof(my_str)/sizeof(my_str[0]), strlen(my_str));

	// exit(0);

	// list<string> full_filepath_in_folder_list;
	// // get_filepath_in_folder_recursive(full_filepath_in_folder_list, string("/home/super/test1"));
	// printf("\n============\n");
	// list<string>::iterator iter = full_filepath_in_folder_list.begin();
	// while (iter != full_filepath_in_folder_list.end())
	// {
	// 	string full_filepath = (string)(*iter);
	// 	printf("* %s\n", full_filepath.c_str());
	// 	iter++;
	// }
	// create_folder_recursive("/home/super/test111/test222/test333/test444");
	// exit(0);

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
	if (param_detach)
		detach_from_terminal();
	ret = setup_param(cluster_mgr);
	if (CHECK_FAILURE(ret))
	{
		print_errmsg_and_exit(errmsg);
	}

	printf("Start the Node...\n");

	// ret = cluster_mgr.start();
	ret = cluster_mgr.initialize();
	if (CHECK_FAILURE(ret))
	{
		// fprintf(stderr, "Fail to initialize...\n");
		// exit(EXIT_FAILURE);
		memset(errmsg, 0x0, sizeof(errmsg) / sizeof(errmsg[0]));
		snprintf(errmsg, ERRMSG_SIZE, "Fail to initialize, due to: %s", GetErrorDescription(ret));
		print_errmsg_and_exit(errmsg);
	}

	if (param_detach)
	{
		while(true)
		{
			WRITE_ERROR("Test !!!");
			sleep(5);
		}
	}
	else
	{
		getchar();
	}
	
	// if (!cluster_mgr.is_leader())
	// {
	// 	const char* msg;
	// 	msg = "This is a test 1";
	// 	printf("SND: %s\n", msg);
	// 	cluster_mgr.transmit_text(msg);
	// 	getchar();	
	// }

	// ret = cluster_mgr.wait_to_stop();
	printf("Stop the Node\n");
	ret = cluster_mgr.deinitialize();
	if (CHECK_FAILURE(ret))
	{
		// fprintf(stderr, "Fail to waiting for stop...\n");
		// exit(EXIT_FAILURE);
		print_errmsg_and_exit("Fail to de-initialize...");
	}

	// getchar();
	printf("The Node is Stopped......\n");

	exit(EXIT_SUCCESS);
}

