# Makefile for Parallel AVL Tree - C++23 (header-only, optimized)
# Supports Windows (MinGW) and Unix (GCC/Clang)

CXX ?= g++

# C++23 with cherry-picks from C++26 (gated on feature-test macros in code).
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
    MKDIR = mkdir
else
    PLATFORM := unix
    EXE :=
    LDFLAGS = -pthread -flto
    RM = rm -f
    RMDIR = rm -rf
    MKDIR = mkdir -p
endif

INC_DIR   = include
BENCH_DIR = bench
TEST_DIR  = tests
BUILD_DIR = build

HEADERS = $(INC_DIR)/common.hpp \
          $(INC_DIR)/avl_tree.hpp \
          $(INC_DIR)/hash_table.hpp \
          $(INC_DIR)/shard.hpp \
          $(INC_DIR)/router.hpp \
          $(INC_DIR)/redirect_index.hpp \
          $(INC_DIR)/parallel_avl.hpp \
          $(INC_DIR)/concurrent_avl.hpp

BENCHMARK     = benchmark_parallel$(EXE)
BENCH_CVSP    = benchmark_concurrent_vs_parallel$(EXE)
TEST          = test_avl$(EXE)
TEST_CAVL     = test_concurrent_avl$(EXE)
COMPILER_CMP  = compiler_compare$(EXE)
STRESS        = stress_test$(EXE)

.PHONY: all clean debug release test test-cavl benchmark bench-cvsp stress compare help

all: release

release: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
release: $(BENCHMARK) $(TEST) $(TEST_CAVL)

debug: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_DEBUG)
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(BENCHMARK) $(TEST)

$(BENCHMARK): $(BENCH_DIR)/benchmark_parallel.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BENCH_CVSP): $(BENCH_DIR)/benchmark_concurrent_vs_parallel.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(TEST): $(TEST_DIR)/test_avl.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(TEST_CAVL): $(TEST_DIR)/test_concurrent_avl.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(COMPILER_CMP): $(BENCH_DIR)/compiler_compare.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(STRESS): $(BENCH_DIR)/stress_test.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

benchmark: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
benchmark: $(BENCHMARK)
	./$(BENCHMARK)

bench-cvsp: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
bench-cvsp: $(BENCH_CVSP)
	./$(BENCH_CVSP)

test: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
test: $(TEST) $(TEST_CAVL)
	./$(TEST)
	./$(TEST_CAVL)

test-cavl: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
test-cavl: $(TEST_CAVL)
	./$(TEST_CAVL)

stress: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
stress: $(STRESS)
	./$(STRESS)

compare: CXXFLAGS = $(CXXFLAGS_BASE) $(CXXFLAGS_OPT)
compare: $(COMPILER_CMP)
	./$(COMPILER_CMP)

clean:
ifeq ($(PLATFORM),windows)
	@if exist $(BUILD_DIR) $(RMDIR) $(BUILD_DIR)
	@if exist $(BENCHMARK) $(RM) $(BENCHMARK)
	@if exist $(TEST) $(RM) $(TEST)
	@if exist $(COMPILER_CMP) $(RM) $(COMPILER_CMP)
	@if exist $(STRESS) $(RM) $(STRESS)
else
	$(RMDIR) $(BUILD_DIR)
	$(RM) $(BENCHMARK) $(BENCH_CVSP) $(TEST) $(TEST_CAVL) $(COMPILER_CMP) $(STRESS)
endif

help:
	@echo "Parallel AVL Tree - C++23 (header-only, optimized)"
	@echo ""
	@echo "Targets:"
	@echo "  make / make release - Build benchmark + tests (optimized)"
	@echo "  make debug          - Build with ASan + UBSan"
	@echo "  make test           - Build and run unit tests"
	@echo "  make benchmark      - Build and run benchmark"
	@echo "  make bench-cvsp     - Build and run concurrent_avl vs parallel_avl benchmark"
	@echo "  make stress         - Build and run stress test"
	@echo "  make compare        - Build and run compiler comparison"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Compiler: $(CXX)"
	@echo "Standard: $(CXXSTD)"
	@echo "Platform: $(PLATFORM)"
