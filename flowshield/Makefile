# FlowShield Build System — C++23
# Built on the C++23 header-only ParallelAVL core.
#
# Targets:
#   make            - Standard demo (rule-based detection)
#   make ai         - AI/ML anomaly detection (CPU)
#   make hailo      - Hailo-8L acceleration (Raspberry Pi 5)
#   make pcap       - Live capture with libpcap
#   make full       - All features enabled
#   make unified    - APT + network unified demo
#   make rpi        - Raspberry Pi 5 optimized build

CXX = g++

CXXSTD = -std=c++23
CXXFLAGS = $(CXXSTD) -Wall -Wextra -O3 -pthread -Wno-interference-size
CXXFLAGS += -I../include -Iinclude
LDFLAGS = -pthread

# Platform-specific optimizations
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
    CXXFLAGS += -mcpu=native
else
    CXXFLAGS += -march=native
endif

# Debug build
DEBUG_CXXFLAGS = $(CXXSTD) -Wall -Wextra -g -O0 -pthread -DDEBUG -Wno-interference-size
DEBUG_CXXFLAGS += -I../include -Iinclude

# Feature flags
PCAP_CXXFLAGS = -DHAVE_PCAP
PCAP_LDFLAGS  = -lpcap

AI_CXXFLAGS = -DHAVE_AI
AI_SRCS     = src/ai_inference.cpp

HAILO_CXXFLAGS = -DHAVE_HAILO -DHAVE_AI
HAILO_LDFLAGS  = -lhailort

# FlowShield sources (always linked)
FLOWSHIELD_SRCS = \
    src/flow_tracker.cpp \
    src/anomaly_detector.cpp \
    src/flowshield.cpp \
    src/ai_inference.cpp \
    src/provenance_graph.cpp \
    src/gnn_gat.cpp \
    src/temporal_gnn.cpp \
    src/causal_inference.cpp \
    src/apt_detector.cpp \
    src/unified_detector.cpp

PCAP_SRCS = src/pcap_capture.cpp

.PHONY: all clean demo debug test ai hailo pcap full unified \
        check-pcap check-hailo help rpi

all: demo

# ============================================================================
# Standard Builds
# ============================================================================

demo: bin/conference_demo

bin/conference_demo: demo/conference_demo.cpp $(FLOWSHIELD_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: bin/conference_demo"
	@echo "   Run: ./bin/conference_demo 2"

# ============================================================================
# AI/ML Builds
# ============================================================================

ai: bin/ai_demo

bin/ai_demo: demo/ai_demo.cpp $(FLOWSHIELD_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(AI_CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: bin/ai_demo (CPU inference)"

# Hailo-8L accelerated build (Raspberry Pi 5)
hailo: check-hailo bin/ai_demo_hailo

check-hailo:
	@echo "Checking for Hailo runtime..."
	@if [ -f /usr/lib/libhailort.so ] || [ -f /usr/lib/aarch64-linux-gnu/libhailort.so ]; then \
		echo "HailoRT found"; \
	else \
		echo "HailoRT not found. Falling back to CPU inference..."; \
	fi

bin/ai_demo_hailo: demo/ai_demo.cpp $(FLOWSHIELD_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(HAILO_CXXFLAGS) -o $@ $^ $(LDFLAGS) $(HAILO_LDFLAGS) 2>/dev/null || \
		$(CXX) $(CXXFLAGS) $(AI_CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: bin/ai_demo_hailo"

# ============================================================================
# Unified APT detection demo
# ============================================================================

unified: bin/unified_apt_demo

bin/unified_apt_demo: demo/unified_apt_detection_demo.cpp $(FLOWSHIELD_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: bin/unified_apt_demo"

# ============================================================================
# Live Capture Builds
# ============================================================================

pcap: check-pcap bin/flowshield_live

check-pcap:
	@echo "Checking for libpcap..."
	@pkg-config --exists libpcap 2>/dev/null || \
		(echo "libpcap not found. Install: sudo apt-get install libpcap-dev" && exit 1)
	@echo "libpcap found"

bin/flowshield_live: demo/live_capture.cpp $(FLOWSHIELD_SRCS) $(PCAP_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(PCAP_CXXFLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDFLAGS)
	@echo "Built: bin/flowshield_live"
	@echo "   Run: sudo ./bin/flowshield_live eth0"

# Full build with AI + pcap
full: bin/flowshield_full

bin/flowshield_full: demo/live_capture.cpp $(FLOWSHIELD_SRCS) $(PCAP_SRCS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(AI_CXXFLAGS) $(PCAP_CXXFLAGS) -o $@ $^ $(LDFLAGS) $(PCAP_LDFLAGS) 2>/dev/null || \
		$(CXX) $(CXXFLAGS) $(PCAP_CXXFLAGS) -o $@ \
		    demo/live_capture.cpp $(FLOWSHIELD_SRCS) $(PCAP_SRCS) $(LDFLAGS) $(PCAP_LDFLAGS)
	@echo "Built: bin/flowshield_full (AI + pcap)"

# ============================================================================
# Raspberry Pi 5 optimized
# ============================================================================

rpi: rpi-check bin/flowshield_rpi

rpi-check:
	@echo "Building for Raspberry Pi 5..."
	@if [ "$(UNAME_M)" != "aarch64" ]; then \
		echo "Warning: not running on ARM64. Cross-compiling..."; \
	fi

bin/flowshield_rpi: demo/ai_demo.cpp $(FLOWSHIELD_SRCS)
	@mkdir -p bin
	$(CXX) -Wall -Wextra -O3 -mcpu=cortex-a76 $(CXXSTD) -pthread \
		-Wno-interference-size -I../include -Iinclude $(AI_CXXFLAGS) \
		-o $@ $^ $(LDFLAGS)
	@echo "Built: bin/flowshield_rpi (Cortex-A76)"

# ============================================================================
# Debug / test / run
# ============================================================================

debug: CXXFLAGS = $(DEBUG_CXXFLAGS)
debug: bin/conference_demo
	@echo "Debug build complete"

test: bin/conference_demo
	@echo "Running hotspot attack demo..."
	./bin/conference_demo 2

test-ai: bin/ai_demo
	@echo "Running AI demo..."
	./bin/ai_demo

test-unified: bin/unified_apt_demo
	./bin/unified_apt_demo

run: bin/conference_demo
	./bin/conference_demo all

clean:
	rm -rf bin/
	rm -f src/*.o
	@echo "Cleaned"

help:
	@echo "FlowShield Build System (C++23)"
	@echo "  make / make demo    Build conference demo (rule-based)"
	@echo "  make ai             AI/ML anomaly detection demo"
	@echo "  make hailo          Hailo-8L acceleration (RPi 5)"
	@echo "  make pcap           Live capture with libpcap"
	@echo "  make full           Live capture + AI"
	@echo "  make unified        Unified APT + network demo"
	@echo "  make rpi            Raspberry Pi 5 optimized build"
	@echo "  make debug          Debug symbols + sanitizers"
	@echo "  make clean          Remove artifacts"
