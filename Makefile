CC := g++
MAKE := make

CXXFLAGS := -g -Wall

SOURCES := msg_cluster.cpp msg_cluster_common.cpp msg_dumper_wrapper.cpp
OBJS := $(SOURCES:.cpp=.o)
LIB_MSG_DUMPER := libmsg_dumper.so
LIB_MSG_DUMPER_HEADER := msg_dumper.h
LIB_MSG_DUMPER_PATH := ../msg_dumper

OUTPUT := msg_cluster

build: $(OUTPUT)

$(OUTPUT): $(LIB_MSG_DUMPER_HEADER) $(LIB_MSG_DUMPER) $(OBJS)
	$(CC) $(CXXFLAGS) $^ -o $@ -Wl,--start-group $(LIB_MSG_DUMPER) -Wl,--end-group -lrt -ldl -lpthread

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
	rm -f $(LIB_MSG_DUMPER) 2> /dev/null
	rm -f $(OUTPUT) 2> /dev/null
