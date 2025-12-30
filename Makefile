# Makefile for Parallel AVL Tree - Pure C (Optimized)
# Supports Windows (MinGW) and Unix (GCC/Clang)

# Compiler detection
CC ?= gcc

# Optimization flags
CFLAGS_BASE = -std=c11 -Wall -Wextra -pedantic
CFLAGS_OPT = -O3 -march=native -flto -ffast-math
CFLAGS_DEBUG = -g -O0 -DDEBUG -fsanitize=address

# Include paths
INCLUDES = -I include

# Platform detection
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE := .exe
    LDFLAGS = -flto
    RM = del /Q /F
    RMDIR = rmdir /S /Q
    MKDIR = mkdir
    PATHSEP = \\
else
    PLATFORM := unix
    EXE :=
    LDFLAGS = -pthread -lm -flto
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
    PATHSEP = /
endif

# Directories
SRC_DIR = src
INC_DIR = include
BENCH_DIR = bench
TEST_DIR = tests
BUILD_DIR = build

# Source files
SRCS = $(SRC_DIR)/avl_tree.c \
       $(SRC_DIR)/hash_table.c \
       $(SRC_DIR)/shard.c \
       $(SRC_DIR)/router.c \
       $(SRC_DIR)/redirect_index.c \
       $(SRC_DIR)/parallel_avl.c

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Targets
BENCHMARK = benchmark_parallel$(EXE)
TEST = test_avl$(EXE)
LIB = libparallel_avl.a

# Default target
.PHONY: all clean debug release test benchmark lib help

all: release

release: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_OPT)
release: $(BUILD_DIR) $(BENCHMARK) $(TEST)

debug: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DEBUG)
debug: LDFLAGS += -fsanitize=address
debug: $(BUILD_DIR) $(BENCHMARK) $(TEST)

# Create build directory
$(BUILD_DIR):
ifeq ($(PLATFORM),windows)
	@if not exist $(BUILD_DIR) $(MKDIR) $(BUILD_DIR)
else
	@$(MKDIR) $(BUILD_DIR)
endif

# Object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Static library
lib: $(BUILD_DIR) $(OBJS)
	ar rcs $(BUILD_DIR)/$(LIB) $(OBJS)

# Benchmark executable
$(BENCHMARK): $(OBJS) $(BENCH_DIR)/benchmark_parallel.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(BENCH_DIR)/benchmark_parallel.c $(OBJS) $(LDFLAGS)

# Test executable
$(TEST): $(OBJS) $(TEST_DIR)/test_avl.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_DIR)/test_avl.c $(OBJS) $(LDFLAGS)

# Run targets
benchmark: $(BENCHMARK)
	./$(BENCHMARK)

test: $(TEST)
	./$(TEST)

# Clean
clean:
ifeq ($(PLATFORM),windows)
	@if exist $(BUILD_DIR) $(RMDIR) $(BUILD_DIR)
	@if exist $(BENCHMARK) $(RM) $(BENCHMARK)
	@if exist $(TEST) $(RM) $(TEST)
else
	$(RMDIR) $(BUILD_DIR)
	$(RM) $(BENCHMARK) $(TEST)
endif

# Help
help:
	@echo "Parallel AVL Tree - Pure C (Optimized)"
	@echo ""
	@echo "Targets:"
	@echo "  make / make release - Build optimized binaries"
	@echo "  make debug          - Build with debug symbols and sanitizers"
	@echo "  make lib            - Build static library"
	@echo "  make test           - Build and run tests"
	@echo "  make benchmark      - Build and run benchmark"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Compiler: $(CC)"
	@echo "Platform: $(PLATFORM)"
	@echo "Flags:    $(CFLAGS_BASE) $(CFLAGS_OPT)"

# Dependencies
$(BUILD_DIR)/avl_tree.o: $(SRC_DIR)/avl_tree.c $(INC_DIR)/avl_tree.h
$(BUILD_DIR)/hash_table.o: $(SRC_DIR)/hash_table.c $(INC_DIR)/hash_table.h
$(BUILD_DIR)/shard.o: $(SRC_DIR)/shard.c $(INC_DIR)/shard.h $(INC_DIR)/avl_tree.h $(INC_DIR)/atomics.h
$(BUILD_DIR)/router.o: $(SRC_DIR)/router.c $(INC_DIR)/router.h $(INC_DIR)/atomics.h
$(BUILD_DIR)/redirect_index.o: $(SRC_DIR)/redirect_index.c $(INC_DIR)/redirect_index.h $(INC_DIR)/hash_table.h $(INC_DIR)/atomics.h
$(BUILD_DIR)/parallel_avl.o: $(SRC_DIR)/parallel_avl.c $(INC_DIR)/parallel_avl.h $(INC_DIR)/shard.h $(INC_DIR)/router.h $(INC_DIR)/redirect_index.h
