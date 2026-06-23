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
              src/dpi_engine.cpp \
              src/main_mt.cpp

TARGET_SIMPLE = dpi_simple$(EXT)
TARGET_MT     = dpi_engine$(EXT)

# ---- Targets ----------------------------------------------------------------

.PHONY: all simple mt test clean test_data benchmark

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
	rm -f $(TARGET_SIMPLE) $(TARGET_MT) *.o
	@echo "Cleaned."
