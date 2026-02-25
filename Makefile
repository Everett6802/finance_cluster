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

SOURCES := msg_dumper_wrapper.cpp finance_cluster.cpp common_definition.cpp common_function.cpp common_class.cpp common_notify_class.cpp common_event_class.cpp node_channel.cpp file_channel.cpp file_sender.cpp file_receiver.cpp leader_node.cpp follower_node.cpp interactive_session.cpp interactive_server.cpp simulator_handler.cpp system_operator.cpp cluster_mgr.cpp
#OBJS := $(SOURCES:.cpp=.o)
# Compile .o 到 OBJ_DIR => Map .cpp -> /obj/.o
OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(SOURCES))
# .o 依賴沒有 .d 檔案（include 變動不會 rebuild）
DEPS := $(OBJS:.o=.d)

# =========================
# msg_dumper library (Required)
# =========================
LIB_MSG_DUMPER := libmsg_dumper.so
LIB_MSG_DUMPER_HEADER := msg_dumper.h
LIB_MSG_DUMPER_PATH := ../msg_dumper
# LIB_MSG_DUMPER_WRAPPER_FOLDER := wrapper
# LIB_MSG_DUMPER_WRAPPER_HEADER := msg_dumper_wrapper.h
# LIB_MSG_DUMPER_WRAPPER_SOURCE := msg_dumper_wrapper.cpp
# wildcard 如果目錄存在會回傳目錄名稱 不存在會回傳空字串。
# =========================
# msg_dumper project auto build
# =========================
MSG_DUMPER_PROJECT := $(wildcard $(LIB_MSG_DUMPER_PATH))
ifneq ($(MSG_DUMPER_PROJECT),)
#     $(info msg_dumper project found — will rebuild)
    BUILD_MSG_DUMPER = $(MAKE) -C $(LIB_MSG_DUMPER_PATH)
    COPY_MSG_DUMPER  = cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER) .
    COPY_MSG_HEADER  = cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_HEADER) .
    CLEAN_MSG_DUMPER = $(MAKE) -C $(LIB_MSG_DUMPER_PATH) clean
else
#     $(info msg_dumper project not found)
    BUILD_MSG_DUMPER = @true
    COPY_MSG_DUMPER  = @true
    COPY_MSG_HEADER  = @true
	CLEAN_MSG_DUMPER = @true
endif

# =========================
# pg_db_access library (Optional)
# =========================
LIB_PG_DB_ACCESS := libpg_db_access.so
LIB_PG_DB_ACCESS_HEADER := pg_db_access.h
LIB_PG_DB_ACCESS_PATH := ../pg_db_access
# 潛在問題
# 假設:make deep_build
# 流程:Makefile 被解析->PG_DB_ACCESS_SO 判斷(此時還沒有so)->deep_build build出so->但PG_DB_ACCESS_SO已經是空字串->build 階段仍然認為「沒有 PG」
# 這就是 Make 的解析期 vs 執行期差異。
# # 檢查這個檔案在不在，如果在就回傳檔名，不在就回傳空字串
# PG_DB_ACCESS_SO := $(wildcard $(LIB_PG_DB_ACCESS))
# # 如果 PG_DB_ACCESS_SO 不是空字串 → 條件成立
# # ifneq ($(PG_DB_ACCESS_SO),)
# #     $(info PG plugin found — enabling PG support)
# #     COPY_PG = cp $(LIB_PG_DB_ACCESS) $(BIN_DIR)/
# # else
# #     $(info PG plugin not found — building without PG support)
# #     COPY_PG = @true
# # endif
# =========================
# pg_db_access project auto build
# =========================
PG_DB_ACCESS_PROJECT := $(wildcard $(LIB_PG_DB_ACCESS_PATH))
ifneq ($(PG_DB_ACCESS_PROJECT),)
#     $(info pg_db_access project found — will rebuild)
    BUILD_PG_DB_ACCESS = $(MAKE) -C $(LIB_PG_DB_ACCESS_PATH)
    COPY_PG_DB_ACCESS  = cp $(LIB_PG_DB_ACCESS_PATH)/$(LIB_PG_DB_ACCESS) .
    COPY_PG_DB_ACCESS_HEADER = cp $(LIB_PG_DB_ACCESS_PATH)/$(LIB_PG_DB_ACCESS_HEADER) .
	CLEAN_PG_DB_ACCESS = $(MAKE) -C $(LIB_PG_DB_ACCESS_PATH) clean
else
#     $(info pg_db_access project not found — skip)
    BUILD_PG_DB_ACCESS = @true
    COPY_PG_DB_ACCESS  = @true
    COPY_PG_DB_ACCESS_HEADER = @true
	CLEAN_PG_DB_ACCESS = @true
endif

# =========================
# Link libraries
# =========================
# -L. -lmsg_dumper 是什麼意思？
# -L. → 在目前目錄找 library
# -lmsg_dumper → 找 libmsg_dumper.so => linker 會自動補：lib + 名字 + .so => 所以：-lmsg_dumper=>libmsg_dumper.so
# -Wl,-rpath,'$$ORIGIN' 是什麼意思？
# -Wl,xxx → 這是傳給 linker 的參數
# rpath 是什麼？rpath = runtime library search path 意思：執行時去哪裡找 .so
# $$ORIGIN 是什麼？$$ORIGIN 是一個特殊變數，代表執行檔所在的目錄
# 所以 -Wl,-rpath,'$$ORIGIN' 的意思是：告訴 linker 在執行時從執行檔所在的目錄找 .so
LIBS := -L. -lmsg_dumper -Wl,-rpath,'$$ORIGIN' -lrt -ldl -lpthread

# CONF_FILES := $(wildcard conf/*)
CONF_FOLDER := conf
CONF_FILES := $(wildcard $(BIN_DIR)/*)
#OUTPUT := $(OUTPUT_DIR)/finance_cluster
OUTPUT := $(BIN_DIR)/finance_cluster

# =========================
# Build
# =========================
all: build
build: prepare $(OUTPUT) copy_conf copy_so
# deep_build: $(LIB_MSG_DUMPER_HEADER) $(LIB_MSG_DUMPER_WRAPPER_HEADER) $(LIB_MSG_DUMPER_WRAPPER_SOURCE) $(LIB_MSG_DUMPER) prepare $(OUTPUT) copy_conf copy_so
build_external: $(LIB_MSG_DUMPER) $(LIB_PG_DB_ACCESS)
	@if [ -d "$(LIB_MSG_DUMPER_PATH)" ]; then \
		echo "msg_dumper project found — rebuilding"; \
	else \
		echo "msg_dumper project not found"; \
	fi
	@if [ -d "$(LIB_PG_DB_ACCESS_PATH)" ]; then \
		echo "pg_db_access project found — rebuilding"; \
	else \
		echo "pg_db_access project not found"; \
	fi
deep_build: build_external build

prepare:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BIN_DIR)/conf
	@mkdir -p $(OBJ_DIR)

copy_conf: $(CONF_FILES)
	cp conf/* $(BIN_DIR)/conf/

copy_so: $(LIB_MSG_DUMPER)
# # 	cp $(LIB_MSG_DUMPER) $(BIN_DIR)/$(LIB_MSG_DUMPER)
# 	cp $(LIB_MSG_DUMPER) $(BIN_DIR)/
	@if [ -f "$(LIB_MSG_DUMPER)" ]; then \
		cp $(LIB_MSG_DUMPER) $(BIN_DIR)/; \
	else \
		echo "ERROR: libmsg_dumper.so not found"; \
		exit 1; \
	fi
# 	$(COPY_PG)
	@if [ -f "$(LIB_PG_DB_ACCESS)" ]; then \
		echo "PG plugin detected — copying"; \
		cp $(LIB_PG_DB_ACCESS) $(BIN_DIR)/; \
	fi

# build: $(OUTPUT)
# 	cp ./conf/* $(BIN_DIR)/conf
# 	cp ./${LIB_MSG_DUMPER} $(BIN_DIR)/${LIB_MSG_DUMPER}

$(OUTPUT): $(OBJS)
# 	$(CC) $(CXXFLAGS) $^ -o $@ -Wl,--start-group $(LIB_MSG_DUMPER) $(LINK_PG) -Wl,--end-group -lrt -ldl -lpthread
	$(CC) $(CXXFLAGS) $^ -o $@ $(LIBS)

# Compile rule
# 在 pattern rule 裡加 mkdir -p 是保險作法 因為Make 的執行順序不保證先跑 prepare
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CXXFLAGS) -c $< -o $@
# %.o: %.cpp
# 	$(CC) $(CXXFLAGS) -c $< -o $@

# $(LIB_MSG_DUMPER_WRAPPER_HEADER):
# 	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_WRAPPER_FOLDER)/$(LIB_MSG_DUMPER_WRAPPER_HEADER) .

# $(LIB_MSG_DUMPER_WRAPPER_SOURCE):
# 	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_WRAPPER_FOLDER)/$(LIB_MSG_DUMPER_WRAPPER_SOURCE) .

# $(LIB_MSG_DUMPER_WRAPPER_HEADER):
# 	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_WRAPPER_FOLDER)/$(LIB_MSG_DUMPER_WRAPPER_HEADER) .

# $(LIB_MSG_DUMPER_HEADER):
# 	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER_HEADER) .

$(LIB_MSG_DUMPER):
# 	$(MAKE) -C $(LIB_MSG_DUMPER_PATH)
# 	cp $(LIB_MSG_DUMPER_PATH)/$(LIB_MSG_DUMPER) .
# 	$(MAKE) -C $(LIB_MSG_DUMPER_PATH) clean
	$(BUILD_MSG_DUMPER)
	$(COPY_MSG_DUMPER)
	$(COPY_MSG_HEADER)
# 	$(CLEAN_MSG_DUMPER)

# $(LIB_PG_DB_ACCESS_HEADER):
# 	cp $(LIB_PG_DB_ACCESS_PATH)/$(LIB_PG_DB_ACCESS_HEADER) .

$(LIB_PG_DB_ACCESS):
# 	$(MAKE) -C $(LIB_PG_DB_ACCESS_PATH)
# 	cp $(LIB_PG_DB_ACCESS_PATH)/$(LIB_PG_DB_ACCESS) .
# 	$(MAKE) -C $(LIB_PG_DB_ACCESS_PATH) clean
	$(BUILD_PG_DB_ACCESS)
	$(COPY_PG_DB_ACCESS)
	$(COPY_PG_DB_ACCESS_HEADER)
# 	$(CLEAN_PG_DB_ACCESS)

# =========================
# Clean
# =========================
clean:
	rm -rf $(OBJ_DIR) 2> /dev/null
	rm -rf $(OUTPUT) 2> /dev/null

deep_clean:
# 	rm -rf $(OBJ_DIR)
# 	rm -rf $(BIN_DIR)
# 	rm -f $(OUTPUT) 2> /dev/null
# 	rm -f $(LIB_MSG_DUMPER) 2> /dev/null
# 	rm -f $(LIB_MSG_DUMPER_HEADER) 2> /dev/null
# # 	rm -f $(LIB_MSG_DUMPER_WRAPPER_HEADER) 2> /dev/null
# # 	rm -f $(LIB_MSG_DUMPER_WRAPPER_SOURCE) 2> /dev/null
# 	rm -f $(LIB_PG_DB_ACCESS) 2> /dev/null
# 	rm -f $(LIB_PG_DB_ACCESS_HEADER) 2> /dev/null
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)
	rm -rf $(OUTPUT) 2> /dev/null
	rm -f $(LIB_MSG_DUMPER)
	rm -f $(LIB_PG_DB_ACCESS)
	$(CLEAN_MSG_DUMPER)
	$(CLEAN_PG_DB_ACCESS)

