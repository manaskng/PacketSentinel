# =============================================================================
# Makefile for DPI Engine (MSYS2 MinGW-w64 GCC 16 on Windows, GCC 13+ on Linux)
# =============================================================================
# Windows:  Add C:\msys64\mingw64\bin to PATH first, then run mingw32-make
# Linux:    sudo apt install g++-13 && make all
# =============================================================================

CXX     ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -I include
LDFLAGS  =

# On Linux only, link pthreads explicitly
ifeq ($(OS),Windows_NT)
    PTHREAD_LIB =
    EXT         = .exe
else
    PTHREAD_LIB = -lpthread
    EXT         =
endif

SRCS_COMMON = src/types.cpp \
              src/pcap_reader.cpp \
              src/packet_parser.cpp \
              src/sni_extractor.cpp \
              src/rule_manager.cpp

SRCS_SIMPLE = $(SRCS_COMMON) src/main_simple.cpp
SRCS_MT     = $(SRCS_COMMON) \
              src/load_balancer.cpp \
              src/fast_path.cpp \
              src/flow_analyzer.cpp \
              src/dpi_engine.cpp \
              src/main_mt.cpp

TARGET_SIMPLE = dpi_simple$(EXT)
TARGET_MT     = dpi_engine$(EXT)
TARGET_TEST_SNI = test_sni$(EXT)
TARGET_TEST_DOMAIN = test_domain$(EXT)

# ---- Targets ----------------------------------------------------------------

.PHONY: all simple mt test clean test_data benchmark test_sni test_domain test_all

all: simple mt

simple: $(TARGET_SIMPLE)

mt: $(TARGET_MT)

$(TARGET_SIMPLE): $(SRCS_SIMPLE)
	$(CXX) $(CXXFLAGS) $(SRCS_SIMPLE) -o $@ $(LDFLAGS)
	@echo "Built: $@"

$(TARGET_MT): $(SRCS_MT)
	$(CXX) $(CXXFLAGS) -pthread $(SRCS_MT) -o $@ $(LDFLAGS) $(PTHREAD_LIB)
	@echo "Built: $@"

test_data:
	python scripts/generate_test_pcap.py

# Unit tests (requires C++17 compiler: GCC 13+ or Clang 5+)
test_sni: $(TARGET_TEST_SNI)
	@echo "Running SNI extraction unit tests..."
	./$(TARGET_TEST_SNI)

$(TARGET_TEST_SNI): tests/test_sni_extractor.cpp src/sni_extractor.cpp src/types.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

test_domain: $(TARGET_TEST_DOMAIN)
	@echo "Running domain matching unit tests..."
	./$(TARGET_TEST_DOMAIN)

$(TARGET_TEST_DOMAIN): tests/test_domain_matching.cpp src/rule_manager.cpp src/types.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

# Run all tests (integration + unit)
test_all: all test_data test_sni test_domain
	@echo "--- Single-threaded integration test ---"
	./$(TARGET_SIMPLE) test_data/test_small.pcap test_data/out_simple$(EXT).pcap \
	    --block-app YouTube --block-ip 192.168.1.50
	@echo "--- Multi-threaded integration test ---"
	./$(TARGET_MT) test_data/test_small.pcap test_data/out_mt$(EXT).pcap \
	    --lbs 2 --fps 2 --block-app YouTube --no-stats
	@echo "✅ All tests passed (integration + unit)"

# Legacy integration tests (backward compat)
test: all test_data
	@echo "--- Single-threaded test ---"
	./$(TARGET_SIMPLE) test_data/test_small.pcap test_data/out_simple$(EXT).pcap \
	    --block-app YouTube --block-ip 192.168.1.50
	@echo "--- Multi-threaded test ---"
	./$(TARGET_MT) test_data/test_small.pcap test_data/out_mt$(EXT).pcap \
	    --lbs 2 --fps 2 --block-app YouTube --no-stats
	@echo "--- All tests passed ---"

benchmark: all test_data
	python scripts/benchmark.py

clean:
	rm -f $(TARGET_SIMPLE) $(TARGET_MT) $(TARGET_TEST_SNI) $(TARGET_TEST_DOMAIN) *.o
	@echo "Cleaned."

