# FlowShield - DDoS Detection Engine
# Built on ParallelAVL

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -std=c11 -pthread -D_GNU_SOURCE
CFLAGS += -I../include -Iinclude
LDFLAGS = -pthread -lm

# Debug build
DEBUG_CFLAGS = -Wall -Wextra -g -O0 -std=c11 -pthread -DDEBUG -D_GNU_SOURCE
DEBUG_CFLAGS += -I../include -Iinclude

# libpcap support (optional)
PCAP_CFLAGS = -DHAVE_PCAP
PCAP_LDFLAGS = -lpcap

# Source files
PARALLEL_AVL_SRCS = ../src/parallel_avl.c ../src/avl_tree.c ../src/shard.c \
                    ../src/router.c ../src/redirect_index.c ../src/hash_table.c
FLOWSHIELD_SRCS = src/flow_tracker.c src/anomaly_detector.c src/flowshield.c
PCAP_SRCS = src/pcap_capture.c

# Targets
.PHONY: all clean demo debug test pcap check-pcap help

all: demo

# Main demo executable (no pcap required)
demo: bin/conference_demo

bin/conference_demo: demo/conference_demo.c $(FLOWSHIELD_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/conference_demo"
	@echo "   Run with: ./bin/conference_demo"
	@echo "   Or:       ./bin/conference_demo 2    (hotspot attack demo)"
	@echo ""

# Build with libpcap support for live capture
pcap: check-pcap bin/flowshield_live

check-pcap:
	@echo "Checking for libpcap..."
	@pkg-config --exists libpcap 2>/dev/null || (echo "❌ libpcap not found. Install with: sudo apt-get install libpcap-dev" && exit 1)
	@echo "✓ libpcap found"

bin/flowshield_live: demo/live_capture.c $(FLOWSHIELD_SRCS) $(PCAP_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(PCAP_CFLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/flowshield_live"
	@echo "   Run with: sudo ./bin/flowshield_live eth0"
	@echo ""

# Debug build
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: bin/conference_demo
	@echo "🐛 Debug build complete"

# Quick test run
test: bin/conference_demo
	@echo "Running hotspot attack demo..."
	./bin/conference_demo 2

# Full test suite
test-all: bin/conference_demo
	@echo "Running all demos..."
	./bin/conference_demo all

# Interactive demo
run: bin/conference_demo
	./bin/conference_demo all

# Live dashboard simulation
live: bin/conference_demo
	./bin/conference_demo 4

# Clean
clean:
	rm -rf bin/
	rm -f src/*.o
	@echo "🧹 Cleaned"

# Help
help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║              FlowShield Build System                         ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Build Targets:"
	@echo "  make              Build conference demo (default)"
	@echo "  make pcap         Build with libpcap for live capture"
	@echo "  make debug        Build with debug symbols"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Run Targets:"
	@echo "  make test         Run hotspot attack demo"
	@echo "  make test-all     Run all demos"
	@echo "  make live         Run live dashboard simulation"
	@echo ""
	@echo "Demo Options:"
	@echo "  ./bin/conference_demo 1       Normal traffic comparison"
	@echo "  ./bin/conference_demo 2       Hotspot attack (main demo!)"
	@echo "  ./bin/conference_demo 3       Detection algorithms"
	@echo "  ./bin/conference_demo 4       Live dashboard"
	@echo "  ./bin/conference_demo all     Run all demos"
	@echo ""
	@echo "Live Capture (requires root):"
	@echo "  sudo ./bin/flowshield_live eth0           Capture on eth0"
	@echo "  sudo ./bin/flowshield_live any            Capture on all interfaces"
	@echo "  sudo ./bin/flowshield_live -f file.pcap   Replay pcap file"
	@echo ""
