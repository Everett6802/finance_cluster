#include "common.h"

using namespace std;


//////////////////////////////////////////////////////////

const int EventCfg::PARAM_HEADER_TIME_OFFSET = 20;
const int EventCfg::PARAM_HEADER_TYPE_OFFSET = 1;
const int EventCfg::PARAM_HEADER_SEVERITY_CATEGORY_OFFSET = 1;
const int EventCfg::PARAM_HEADER_OFFSET = EventCfg::PARAM_HEADER_TIME_OFFSET + EventCfg::PARAM_HEADER_TYPE_OFFSET + EventCfg::PARAM_HEADER_SEVERITY_CATEGORY_OFFSET;

EventCfg::EventCfg(EventType event_type, EventSeverity event_severity, EventCategory event_category, const void* event_param, size_t event_param_size) :
	ref_count(0),
	param_size(event_param_size)
{
	int total_param_size = PARAM_HEADER_OFFSET + param_size;
	param = new char[total_param_size];
	if (param == NULL)
		throw bad_alloc();
	memset(param, 0x0, sizeof(char) * total_param_size);
	char* param_char = (char*)param;
	string event_time_str;
	get_curtime_str(event_time_str);
	if (event_time_str.length() != PARAM_HEADER_TIME_OFFSET - 1)
	{
		char err_buf[DEF_STRING_SIZE];
 		memset(err_buf, 0x0, sizeof(char) * DEF_STRING_SIZE);
   		snprintf(err_buf, DEF_SHORT_STRING_SIZE, "Incorrect time string length: %s, %d", event_time_str.c_str(), event_time_str.length());
 		throw runtime_error(err_buf);
	}
// Event Time
	strcpy(param_char, event_time_str.c_str());
// Event Type
	*(param_char + PARAM_HEADER_TIME_OFFSET) = (char)event_type;
// Event Severity and Event Category
	// printf("EventCfg()  data: %d\n", (char)(((char)event_severity) << 4) | ((char)event_category));
	*(param_char + PARAM_HEADER_TIME_OFFSET + PARAM_HEADER_TYPE_OFFSET) = (char)((event_severity << 4) | event_category);
	if (event_param != NULL)
		memcpy((param_char + PARAM_HEADER_OFFSET), event_param, sizeof(char) * param_size);
#if 0
// Debug
	printf("Input Data:\n");
	printf("Time: %s\n", event_time_str.c_str());
	printf("Type: %d\n", (int)event_type);
	printf("Severity: %d\n", (int)event_severity);
	printf("Category: %d\n", (int)event_category);

	printf("Event Header:\n");
	printf("Time: %s\n", get_time());
	printf("Type: %d\n", (int)get_type());
	printf("Severity: %d\n", (int)get_severity());
	printf("Category: %d\n", (int)get_category());
#endif
}

EventCfg::~EventCfg()
{
	if (param != NULL)
	{
		delete[] param;
		param = NULL;
	}
}

void EventCfg::generate_content_base_description()
{
# if 0
	printf("EventCfg::generate_content_base_description\n");
	printf("EventTime(Raw) %s\n", (char*)param);
	printf("EventTime %s\n", get_time());
	printf("EventType: %d\n", get_type());
	printf("EventTypeDescription: %s\n", GetEventTypeDescription(get_type()));
	printf("EventSeverity: %d\n", get_severity());
	printf("EventSeverityDescription: %s\n", GetEventSeverityDescription(get_severity()));
	printf("EventCategory: %d\n", get_category());
	printf("EventCategoryDescription: %s\n", GetEventCategoryDescription(get_category()));
#endif
	event_description = string(get_time()) + string("  |  ")
					  + string(GetEventTypeDescription(get_type())) + string("  |  ") 
					  + string(GetEventSeverityDescription(get_severity())) + string("  |  ")
					  + string(GetEventCategoryDescription(get_category())) + string("  |  ");
}


int EventCfg::addref(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_add(&ref_count, 1);
	// printf("addref() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	return ref_count;
}

int EventCfg::release(const char* callable_file_name, unsigned long callable_line_no)
{
	__sync_fetch_and_sub(&ref_count, 1);
	// printf("release() in [%s:%ld %d], ref_count: %d\n", callable_file_name, callable_line_no, notify_type, ref_count);
	assert(ref_count >= 0 && "ref_count should NOT be smaller than 0");
	if (ref_count == 0)
	{
		delete this;
		return 0;
	}

	return ref_count;
}

int EventCfg::getref()const
{
	return ref_count;
}

const char* EventCfg::get_time()const
{
	assert(param != NULL && "param should NOT be NULL");
	return (char*)param;
}

EventType EventCfg::get_type()const
{
	return (EventType)(*((char*)param + PARAM_HEADER_TIME_OFFSET));
}

EventSeverity EventCfg::get_severity()const
{
	static const unsigned char SEVERITY_MASK = 0xF0;
	char data = *((char*)param + PARAM_HEADER_TIME_OFFSET + PARAM_HEADER_TYPE_OFFSET);
	// printf("get_severity()  data: %d\n", data);
	return (EventSeverity)((SEVERITY_MASK & data) >> 4);
}

EventCategory EventCfg::get_category()const
{
	static const unsigned char CATEGORY_MASK = 0xF;
	char data = *((char*)param + PARAM_HEADER_TIME_OFFSET + PARAM_HEADER_TYPE_OFFSET);
	// printf("get_category()  data: %d\n", data);
	return (EventCategory)(CATEGORY_MASK & data);
}

const void* EventCfg::get_data()const
{
	return (void*)((char*)param + PARAM_HEADER_OFFSET);
}

const char* EventCfg::get_str()const
{
// 	if (event_description.length() == 0)
// 	{
// 		string content_description;
// // get_content_description() is virtual and need to be overrided, should use 'const' as a const 'this' pointer
// 		get_content_description(content_description);
// 		event_description = GetEventTypeDescription(get_type()) + string("  ") 
// 						  + GetEventSeverityDescription(get_severity()) + string("  ")
// 						  + GetEventCategoryDescription(get_category()) + string("    ")
// 						  + content_description;
// 	}
	return event_description.c_str();
}

//////////////////////////////////////////////////////////

const int OperateNodeEventCfg::EVENT_DATA_SIZE = sizeof(OperateNodeEventData);

unsigned short OperateNodeEventCfg::generate_obj(OperateNodeEventCfg **obj, EventOperateNodeType event_operate_node_type, NodeType node_type, const char* node_token)
{
	assert(obj != NULL && "obj should NOT be NULL");
	assert(node_token != NULL && "node_token should NOT be NULL");
	OperateNodeEventData data;
	data.event_operate_node_type = event_operate_node_type;
	data.node_type = node_type;
	memset(data.node_token, 0x0, sizeof(char) * DEF_LONG_STRING_SIZE);
	strcpy(data.node_token, node_token);
	OperateNodeEventCfg *obj_tmp = new OperateNodeEventCfg((void*)&data, EVENT_DATA_SIZE);
	if (obj_tmp == NULL)
		throw bad_alloc();
	*obj = obj_tmp;
	return RET_SUCCESS;
}

OperateNodeEventCfg::OperateNodeEventCfg(const void* param, size_t param_size) :
	EventCfg(EVENT_OPERATE_NODE, EVENT_SEVERITY_INFORMATIONAL, EVENT_CATEGORY_CLUSTER, param, param_size)
{
	generate_content_base_description();
	char buf[LONG_STRING_SIZE];
	POPERATE_NODE_EVENT_DATA event_data = (POPERATE_NODE_EVENT_DATA)get_data();
	assert(event_data != NULL && "event_data should NOT be NULL");
	switch (event_data->event_operate_node_type)
	{
		case EVENT_OPERATE_NODE_START:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Start LEADER[%s]", event_data->node_token);
				}
				break;
				case FOLLOWER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Start FOLLOWER[%s]", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
			// snprintf(buf, LONG_STRING_SIZE, "Start %s[%s]", (event_data->node_type == LEADER ? "LEADER" : "FOLLOWER"), event_data->node_token);
		}
		break;
		case EVENT_OPERATE_NODE_STOP:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Stop LEADER[%s]", event_data->node_token);
				}
				break;
				case FOLLOWER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Stop FOLLOWER[%s]", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
			// snprintf(buf, LONG_STRING_SIZE, "Stop %s[%s]", (event_data->node_type == LEADER ? "LEADER" : "FOLLOWER"), event_data->node_token);
		}
		break;
		case EVENT_OPERATE_NODE_JOIN:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "New FOLLOWER[%s] join", event_data->node_token);
				}
				break;
				case FOLLOWER:
				{
					snprintf(buf, LONG_STRING_SIZE, "FOLLOWER join cluster[%s]", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
		}
		break;
		case EVENT_OPERATE_NODE_LEAVE:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "FOLLOWER[%s] leave", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
		}
		break;
		case EVENT_OPERATE_NODE_SWITCH_LEADER:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Switch LEADER to %s", event_data->node_token);
				}
				break;
				case FOLLOWER:
				{
					snprintf(buf, LONG_STRING_SIZE, "FOLLOWER[%s] to LEADER", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
		}
		break;
		case EVENT_OPERATE_NODE_REMOVE_FOLLOWER:
		{
			switch (event_data->node_type)
			{
				case LEADER:
				{
					snprintf(buf, LONG_STRING_SIZE, "Remove FOLLOWER[%s]", event_data->node_token);
				}
				break;
				case FOLLOWER:
				{
					snprintf(buf, LONG_STRING_SIZE, "FOLLOWER is removed from Cluster[%s]", event_data->node_token);
				}
				break;
				default:
				{
					static const int BUF_SIZE = 256;
					char buf[BUF_SIZE];
					snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
					fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
					throw std::invalid_argument(buf);
				}
				break;
			}
		}
		break;
		default:
		{
    		static const int BUF_SIZE = 256;
    		char buf[BUF_SIZE];
    		snprintf(buf, BUF_SIZE, "Unknown operate node event type: %d", event_data->event_operate_node_type);
    		fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
    		throw std::invalid_argument(buf);
		}
		break;
	}
	string content_description = string(buf);
	event_description += content_description;
}

OperateNodeEventCfg::~OperateNodeEventCfg(){}

//////////////////////////////////////////////////////////

const int TelnetConsoleEventCfg::EVENT_DATA_SIZE = sizeof(TelnetConsoleEventData);

unsigned short TelnetConsoleEventCfg::generate_obj(TelnetConsoleEventCfg **obj, const char* login_address, int session_id, char exit)
{
	assert(obj != NULL && "obj should NOT be NULL");
	assert(login_address != NULL && "login_address should NOT be NULL");
	TelnetConsoleEventData data;
	memset(data.login_address, 0x0, sizeof(char) * DEF_VERY_SHORT_STRING_SIZE);
	strcpy(data.login_address, login_address);
	data.session_id = session_id;
	data.exit = exit;
	TelnetConsoleEventCfg *obj_tmp = new TelnetConsoleEventCfg((void*)&data, EVENT_DATA_SIZE);
	if (obj_tmp == NULL)
		throw bad_alloc();
	*obj = obj_tmp;
	return RET_SUCCESS;
}

// void TelnetConsoleEventCfg::get_content_description(string& content_description)
// {
// 	char buf[LONG_STRING_SIZE];
// 	PTELNET_CONSOLE_EVENT_DATA event_data = (PTELNET_CONSOLE_EVENT_DATA)get_data();
// 	assert(event_data != NULL && "event_data should NOT be NULL");
// 	snprintf(buf, LONG_STRING_SIZE, "%s: %s console %d", event_data->login_address, (event_data->exit != 0 ? "Login" : "Logout"), event_data->session_id);
// 	content_description = string(buf);
// 	return RET_SUCCESS;
// }

TelnetConsoleEventCfg::TelnetConsoleEventCfg(const void* param, size_t param_size) :
	EventCfg(EVENT_TELENT_CONSOLE, EVENT_SEVERITY_INFORMATIONAL, EVENT_CATEGORY_CONSOLE, param, param_size)
{
	generate_content_base_description();
	char buf[LONG_STRING_SIZE];
	PTELNET_CONSOLE_EVENT_DATA event_data = (PTELNET_CONSOLE_EVENT_DATA)get_data();
	assert(event_data != NULL && "event_data should NOT be NULL");
	snprintf(buf, LONG_STRING_SIZE, "%s: %s console[%d]", event_data->login_address, (event_data->exit == 0 ? "Login" : "Logout"), event_data->session_id);
	string content_description = string(buf);
	event_description += content_description;
}

TelnetConsoleEventCfg::~TelnetConsoleEventCfg(){}

//////////////////////////////////////////////////////////

const int SyncDataEventCfg::EVENT_DATA_SIZE = sizeof(SyncDataEventData);

unsigned short SyncDataEventCfg::generate_obj(SyncDataEventCfg **obj, const char* data_path, NodeType node_type, const char* node_token, char is_folder)
{
	assert(obj != NULL && "obj should NOT be NULL");
	assert(node_token != NULL && "node_token should NOT be NULL");
	SyncDataEventData data;
	memset(data.data_path, 0x0, sizeof(char) * DEF_LONG_STRING_SIZE);
	strcpy(data.data_path, data_path);
	data.node_type = node_type;
	memset(data.node_token, 0x0, sizeof(char) * DEF_LONG_STRING_SIZE);
	strcpy(data.node_token, node_token);
	data.is_folder = is_folder;
	SyncDataEventCfg *obj_tmp = new SyncDataEventCfg((void*)&data, EVENT_DATA_SIZE);
	if (obj_tmp == NULL)
		throw bad_alloc();
	*obj = obj_tmp;
	return RET_SUCCESS;
}

SyncDataEventCfg::SyncDataEventCfg(const void* param, size_t param_size) :
	EventCfg(EVENT_SYNC_DATA, EVENT_SEVERITY_INFORMATIONAL, EVENT_CATEGORY_CONSOLE, param, param_size)
{
	generate_content_base_description();
	char buf[LONG_STRING_SIZE];
	PSYNC_DATA_EVENT_DATA event_data = (PSYNC_DATA_EVENT_DATA)get_data();
	assert(event_data != NULL && "event_data should NOT be NULL");
	switch (event_data->node_type)
	{
		case LEADER:
		{
			snprintf(buf, LONG_STRING_SIZE, "LEADER[%s] sync %s[%s] to CLUSTER", event_data->node_token, (event_data->is_folder != 0 ? "folder" : "file"), event_data->data_path);
		}
		break;
		case FOLLOWER:
		{
			snprintf(buf, LONG_STRING_SIZE, "FOLLOWER[%s] sync %s[%s] to LEADER", event_data->node_token, (event_data->is_folder != 0 ? "folder" : "file"), event_data->data_path);
		}
		break;
		default:
		{
			static const int BUF_SIZE = 256;
			char buf[BUF_SIZE];
			snprintf(buf, BUF_SIZE, "Incorrect node type: %d", event_data->node_type);
			fprintf(stderr, "%s in %s:%d\n", buf, __FILE__, __LINE__);
			throw std::invalid_argument(buf);
		}
		break;
	}
	string content_description = string(buf);
	event_description += content_description;
}

SyncDataEventCfg::~SyncDataEventCfg(){}
