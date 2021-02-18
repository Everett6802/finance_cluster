CC := g++
MAKE := make

CXXFLAGS := -g -Wall -std=c++0x

SOURCES := msg_dumper_wrapper.cpp finance_cluster.cpp common_definition.cpp common_function.cpp common_class.cpp node_channel.cpp file_channel.cpp leader_node.cpp follower_node.cpp interactive_session.cpp interactive_server.cpp simulator_handler.cpp cluster_mgr.cpp
OBJS := $(SOURCES:.cpp=.o)
LIB_MSG_DUMPER := libmsg_dumper.so
LIB_MSG_DUMPER_HEADER := msg_dumper.h
LIB_MSG_DUMPER_PATH := ../msg_dumper
LIB_MSG_DUMPER_WRAPPER_FOLDER := wrapper
LIB_MSG_DUMPER_WRAPPER_HEADER := msg_dumper_wrapper.h
LIB_MSG_DUMPER_WRAPPER_SOURCE := msg_dumper_wrapper.cpp

OUTPUT := finance_cluster

build: $(OUTPUT)

deep_build: $(LIB_MSG_DUMPER_HEADER) $(LIB_MSG_DUMPER_WRAPPER_HEADER) $(LIB_MSG_DUMPER_WRAPPER_SOURCE) $(LIB_MSG_DUMPER) $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(CXXFLAGS) $^ -o $@ -Wl,--start-group $(LIB_MSG_DUMPER) -Wl,--end-group -lrt -ldl -lpthread

$(LIB_MSG_DUMPER_WRAPPER_HEADER):
	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_WRAPPER_FOLDER)/$(LIB_MSG_DUMPER_WRAPPER_HEADER) .

$(LIB_MSG_DUMPER_WRAPPER_SOURCE):
	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_WRAPPER_FOLDER)/$(LIB_MSG_DUMPER_WRAPPER_SOURCE) .

$(LIB_MSG_DUMPER_HEADER):
	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_HEADER) .

$(LIB_MSG_DUMPER):
	$(MAKE) -C $(LIB_MSG_DUMPER_PATH)
	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER) .
	$(MAKE) -C $(LIB_MSG_DUMPER_PATH) clean

%.o: %.cpp
	$(CC) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) 2> /dev/null
	rm -f $(OUTPUT) 2> /dev/null

deep_clean:
	rm -f $(OBJS) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER) 2> /dev/null
	rm -f $(OUTPUT) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_HEADER) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_WRAPPER_HEADER) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_WRAPPER_SOURCE) 2> /dev/null
