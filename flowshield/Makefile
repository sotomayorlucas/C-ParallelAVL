# FlowShield - DDoS Detection Engine
# Built on ParallelAVL

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -std=c11 -pthread -D_GNU_SOURCE
CFLAGS += -I../include -Iinclude
LDFLAGS = -pthread -lm

# Debug build
DEBUG_CFLAGS = -Wall -Wextra -g -O0 -std=c11 -pthread -DDEBUG -D_GNU_SOURCE
DEBUG_CFLAGS += -I../include -Iinclude

# Source files
PARALLEL_AVL_SRCS = ../src/parallel_avl.c ../src/avl_tree.c ../src/shard.c \
                    ../src/router.c ../src/redirect_index.c ../src/hash_table.c
FLOWSHIELD_SRCS = src/flow_tracker.c src/anomaly_detector.c src/flowshield.c

# Object files
PARALLEL_AVL_OBJS = $(PARALLEL_AVL_SRCS:.c=.o)
FLOWSHIELD_OBJS = $(FLOWSHIELD_SRCS:.c=.o)

# Targets
.PHONY: all clean demo debug test

all: demo

# Main demo executable
demo: bin/conference_demo

bin/conference_demo: demo/conference_demo.c $(FLOWSHIELD_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/conference_demo"
	@echo "   Run with: ./bin/conference_demo"
	@echo "   Or:       ./bin/conference_demo 2    (hotspot attack demo)"
	@echo ""

# Debug build
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: bin/conference_demo
	@echo "🐛 Debug build complete"

# Quick test run
test: bin/conference_demo
	@echo "Running quick test..."
	./bin/conference_demo 2

# Interactive demo
run: bin/conference_demo
	./bin/conference_demo all

# Live dashboard
live: bin/conference_demo
	./bin/conference_demo 4

# Clean
clean:
	rm -rf bin/
	rm -f $(FLOWSHIELD_OBJS)
	@echo "🧹 Cleaned"

# Help
help:
	@echo "FlowShield Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make          - Build conference demo"
	@echo "  make debug    - Build with debug symbols"
	@echo "  make test     - Run hotspot attack demo"
	@echo "  make run      - Run all demos"
	@echo "  make live     - Run live dashboard"
	@echo "  make clean    - Remove build artifacts"
	@echo ""
	@echo "Demo options:"
	@echo "  ./bin/conference_demo 1     - Normal traffic"
	@echo "  ./bin/conference_demo 2     - Hotspot attack (main demo)"
	@echo "  ./bin/conference_demo 3     - Detection algorithms"
	@echo "  ./bin/conference_demo 4     - Live dashboard"
	@echo "  ./bin/conference_demo all   - All demos"
