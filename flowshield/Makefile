# FlowShield - DDoS Detection Engine
# Built on ParallelAVL
#
# Build Options:
#   make          - Standard demo (rule-based detection)
#   make ai       - AI/ML anomaly detection (CPU)
#   make hailo    - Hailo-8L acceleration (Raspberry Pi 5)
#   make pcap     - Live capture with libpcap
#   make full     - All features enabled

CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c11 -pthread -D_GNU_SOURCE
CFLAGS += -I../include -Iinclude
LDFLAGS = -pthread -lm

# Platform-specific optimizations
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
    # Raspberry Pi / ARM64
    CFLAGS += -mcpu=native
else
    # x86_64
    CFLAGS += -march=native
endif

# Debug build
DEBUG_CFLAGS = -Wall -Wextra -g -O0 -std=c11 -pthread -DDEBUG -D_GNU_SOURCE
DEBUG_CFLAGS += -I../include -Iinclude

# Feature flags
PCAP_CFLAGS = -DHAVE_PCAP
PCAP_LDFLAGS = -lpcap

AI_CFLAGS = -DHAVE_AI
AI_SRCS = src/ai_inference.c

HAILO_CFLAGS = -DHAVE_HAILO -DHAVE_AI
HAILO_LDFLAGS = -lhailort

# Source files
PARALLEL_AVL_SRCS = ../src/parallel_avl.c ../src/avl_tree.c ../src/shard.c \
                    ../src/router.c ../src/redirect_index.c ../src/hash_table.c
FLOWSHIELD_SRCS = src/flow_tracker.c src/anomaly_detector.c src/flowshield.c
PCAP_SRCS = src/pcap_capture.c

# Targets
.PHONY: all clean demo debug test ai hailo pcap full check-pcap check-hailo help rpi

all: demo

# ============================================================================
# Standard Builds
# ============================================================================

demo: bin/conference_demo

bin/conference_demo: demo/conference_demo.c $(FLOWSHIELD_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/conference_demo"
	@echo "   Run: ./bin/conference_demo 2  (hotspot attack)"
	@echo ""

# ============================================================================
# AI/ML Builds
# ============================================================================

ai: bin/ai_demo

bin/ai_demo: demo/ai_demo.c $(FLOWSHIELD_SRCS) $(AI_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(AI_CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/ai_demo (CPU inference)"
	@echo "   Run: ./bin/ai_demo"
	@echo ""

# Hailo-8L accelerated build (Raspberry Pi 5)
hailo: check-hailo bin/ai_demo_hailo

check-hailo:
	@echo "Checking for Hailo runtime..."
	@if [ -f /usr/lib/libhailort.so ] || [ -f /usr/lib/aarch64-linux-gnu/libhailort.so ]; then \
		echo "✓ HailoRT found"; \
	else \
		echo "⚠️  HailoRT not found. Install from: https://hailo.ai/developer-zone/"; \
		echo "   Falling back to CPU inference..."; \
	fi

bin/ai_demo_hailo: demo/ai_demo.c $(FLOWSHIELD_SRCS) $(AI_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(HAILO_CFLAGS) -o $@ $^ $(LDFLAGS) $(HAILO_LDFLAGS) 2>/dev/null || \
		$(CC) $(CFLAGS) $(AI_CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/ai_demo_hailo"
	@echo "   Run: ./bin/ai_demo_hailo"
	@echo ""

# ============================================================================
# Live Capture Builds
# ============================================================================

pcap: check-pcap bin/flowshield_live

check-pcap:
	@echo "Checking for libpcap..."
	@pkg-config --exists libpcap 2>/dev/null || \
		(echo "❌ libpcap not found. Install: sudo apt-get install libpcap-dev" && exit 1)
	@echo "✓ libpcap found"

bin/flowshield_live: demo/live_capture.c $(FLOWSHIELD_SRCS) $(PCAP_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(PCAP_CFLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/flowshield_live"
	@echo "   Run: sudo ./bin/flowshield_live eth0"
	@echo ""

# Full build with AI + pcap
full: bin/flowshield_full

bin/flowshield_full: demo/live_capture.c $(FLOWSHIELD_SRCS) $(AI_SRCS) $(PCAP_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(AI_CFLAGS) $(PCAP_CFLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDFLAGS) 2>/dev/null || \
		$(CC) $(CFLAGS) $(PCAP_CFLAGS) -o $@ demo/live_capture.c $(FLOWSHIELD_SRCS) $(PCAP_SRCS) $(PARALLEL_AVL_SRCS) $(LDFLAGS) $(PCAP_LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/flowshield_full (AI + pcap)"
	@echo ""

# ============================================================================
# Raspberry Pi 5 Optimized Build
# ============================================================================

rpi: rpi-check bin/flowshield_rpi

rpi-check:
	@echo "🍓 Building for Raspberry Pi 5..."
	@if [ "$(UNAME_M)" != "aarch64" ]; then \
		echo "⚠️  Warning: Not running on ARM64. Cross-compiling..."; \
	fi

bin/flowshield_rpi: demo/ai_demo.c $(FLOWSHIELD_SRCS) $(AI_SRCS) $(PARALLEL_AVL_SRCS)
	@mkdir -p bin
	$(CC) -Wall -Wextra -O3 -mcpu=cortex-a76 -std=c11 -pthread -D_GNU_SOURCE \
		-I../include -Iinclude $(AI_CFLAGS) \
		-o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "✅ Built: bin/flowshield_rpi (optimized for Cortex-A76)"
	@echo ""

# ============================================================================
# Test & Run
# ============================================================================

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: bin/conference_demo
	@echo "🐛 Debug build complete"

test: bin/conference_demo
	@echo "Running hotspot attack demo..."
	./bin/conference_demo 2

test-ai: bin/ai_demo
	@echo "Running AI demo..."
	./bin/ai_demo

test-all: bin/conference_demo
	./bin/conference_demo all

run: bin/conference_demo
	./bin/conference_demo all

live: bin/conference_demo
	./bin/conference_demo 4

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -rf bin/
	rm -f src/*.o
	@echo "🧹 Cleaned"

# ============================================================================
# Help
# ============================================================================

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║              FlowShield Build System                              ║"
	@echo "║                                                                   ║"
	@echo "║  DDoS Detection with ParallelAVL + Optional AI Acceleration      ║"
	@echo "╚══════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Build Targets:"
	@echo "  make              Standard demo (rule-based detection)"
	@echo "  make ai           AI/ML anomaly detection (CPU)"
	@echo "  make hailo        Hailo-8L acceleration (RPi 5)"
	@echo "  make pcap         Live capture with libpcap"
	@echo "  make full         All features (AI + pcap)"
	@echo "  make rpi          Raspberry Pi 5 optimized build"
	@echo "  make debug        Debug symbols enabled"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Test Targets:"
	@echo "  make test         Hotspot attack demo"
	@echo "  make test-ai      AI inference demo"
	@echo "  make test-all     All demos"
	@echo ""
	@echo "Demo Commands:"
	@echo "  ./bin/conference_demo 1       Normal traffic"
	@echo "  ./bin/conference_demo 2       Hotspot attack"
	@echo "  ./bin/conference_demo 3       Detection algorithms"
	@echo "  ./bin/conference_demo 4       Live dashboard"
	@echo ""
	@echo "AI Demo Commands:"
	@echo "  ./bin/ai_demo platform        Hardware detection"
	@echo "  ./bin/ai_demo features        Feature extraction"
	@echo "  ./bin/ai_demo anomaly         Autoencoder demo"
	@echo "  ./bin/ai_demo integration     Full integration"
	@echo ""
	@echo "Live Capture (requires root):"
	@echo "  sudo ./bin/flowshield_live eth0"
	@echo "  sudo ./bin/flowshield_live -f capture.pcap"
	@echo ""
	@echo "Raspberry Pi 5 with Hailo-8L:"
	@echo "  make hailo && ./bin/ai_demo_hailo"
	@echo ""
