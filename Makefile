CC := g++
MAKE := make

CXXFLAGS := -g -Wall -std=c++0x

# Detect Docker or Host
ifeq ($(shell grep -qE '(docker|kubepods)' /proc/1/cgroup 2>/dev/null && echo yes),yes)
    BIN_DIR := /app/bin
    OBJ_DIR := /app/obj
else
    BIN_DIR := ./bin
    OBJ_DIR := ./obj
endif

# # Ensure directories exist
# $(shell mkdir -p $(BIN_DIR))
# $(shell mkdir -p $(BIN_DIR)/conf)
# $(shell mkdir -p $(OBJ_DIR))

SOURCES := msg_dumper_wrapper.cpp finance_cluster.cpp common_definition.cpp common_function.cpp common_class.cpp common_notify_class.cpp common_event_class.cpp node_channel.cpp file_channel.cpp file_sender.cpp file_receiver.cpp leader_node.cpp follower_node.cpp interactive_session.cpp interactive_server.cpp simulator_handler.cpp system_operator.cpp cluster_mgr.cpp
#OBJS := $(SOURCES:.cpp=.o)
# Compile .o 到 OBJ_DIR => Map .cpp -> /obj/.o
OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
# .o 依賴沒有 .d 檔案（include 變動不會 rebuild）
DEPS := $(OBJS:.o=.d)

LIB_MSG_DUMPER := libmsg_dumper.so
LIB_MSG_DUMPER_HEADER := msg_dumper.h
LIB_MSG_DUMPER_PATH := ../msg_dumper
LIB_MSG_DUMPER_WRAPPER_FOLDER := wrapper
LIB_MSG_DUMPER_WRAPPER_HEADER := msg_dumper_wrapper.h
LIB_MSG_DUMPER_WRAPPER_SOURCE := msg_dumper_wrapper.cpp

CONF_FILES := $(wildcard conf/*)
#OUTPUT := $(OUTPUT_DIR)/finance_cluster
OUTPUT := $(BIN_DIR)/finance_cluster


all: build

build: prepare $(OUTPUT) copy_conf copy_so

prepare:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BIN_DIR)/conf
	@mkdir -p $(OBJ_DIR)

copy_conf: $(CONF_FILES)
	cp conf/* $(BIN_DIR)/conf/

copy_so: $(LIB_MSG_DUMPER)
	cp $(LIB_MSG_DUMPER) $(BIN_DIR)/$(LIB_MSG_DUMPER)

# build: $(OUTPUT)
# 	cp ./conf/* $(BIN_DIR)/conf
# 	cp ./${LIB_MSG_DUMPER} $(BIN_DIR)/${LIB_MSG_DUMPER}

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

# Compile rule
# 在 pattern rule 裡加 mkdir -p 是保險作法 因為Make 的執行順序不保證先跑 prepare
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CXXFLAGS) -c $< -o $@
# %.o: %.cpp
# 	$(CC) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) 2> /dev/null
	rm -rf $(OUTPUT) 2> /dev/null

deep_clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)
	rm -f $(LIB_MSG_DUMPER) 2> /dev/null
	rm -f $(OUTPUT) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_HEADER) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_WRAPPER_HEADER) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER_WRAPPER_SOURCE) 2> /dev/null
