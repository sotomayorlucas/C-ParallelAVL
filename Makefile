# Makefile for concurrent_avl<K, V> — header-only Bronson optimistic AVL.

CXX ?= g++

CXXSTD = -std=c++23
CXXFLAGS_BASE = $(CXXSTD) -Wall -Wextra -Wpedantic -Wno-interference-size
CXXFLAGS_OPT  = -O3 -march=native -flto -ffast-math -fno-exceptions -fno-rtti
CXXFLAGS_DEBUG = -g -O0 -DDEBUG -fsanitize=address,undefined

INCLUDES = -I include

ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE := .exe
    LDFLAGS = -flto
    RM = del /Q /F
    RMDIR = rmdir /S /Q
else
    PLATFORM := unix
    EXE :=
    LDFLAGS = -pthread -flto
    RM = rm -f
    RMDIR = rm -rf
endif

INC_DIR   = include
BENCH_DIR = bench
TEST_DIR  = tests
BUILD_DIR = build

HEADERS = $(INC_DIR)/common.hpp \
          $(INC_DIR)/concurrent_avl.hpp

BENCH  = benchmark_concurrent_avl$(EXE)
TEST   = test_concurrent_avl$(EXE)

.PHONY: all clean debug release test bench help

all: release

release: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
release: $(BENCH) $(TEST)

debug: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_DEBUG)
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(TEST)

$(BENCH): $(BENCH_DIR)/benchmark_concurrent_avl.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(TEST): $(TEST_DIR)/test_concurrent_avl.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

test: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
test: $(TEST)
	./$(TEST)

bench: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
bench: $(BENCH)
	./$(BENCH)

clean:
ifeq ($(PLATFORM),windows)
	@if exist $(BUILD_DIR) $(RMDIR) $(BUILD_DIR)
	@if exist $(BENCH) $(RM) $(BENCH)
	@if exist $(TEST) $(RM) $(TEST)
else
	$(RMDIR) $(BUILD_DIR)
	$(RM) $(BENCH) $(TEST)
endif

help:
	@echo "concurrent_avl<K, V> — Bronson optimistic AVL (header-only)"
	@echo ""
	@echo "Targets:"
	@echo "  make / make release - Build benchmark + tests (optimized)"
	@echo "  make debug          - Build tests with ASan + UBSan"
	@echo "  make test           - Build and run unit tests"
	@echo "  make bench          - Build and run benchmark"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Compiler: $(CXX)"
	@echo "Standard: $(CXXSTD)"
	@echo "Platform: $(PLATFORM)"
