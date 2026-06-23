#!/usr/bin/env bash
# build.sh — Build DPI Engine using MSYS2 GCC
# Run from MSYS2 MinGW64 shell: bash build.sh
# Or from PowerShell: C:\msys64\usr\bin\bash.exe build.sh

set -e

GCC=/mingw64/bin/g++
CXX_FLAGS="-std=c++17 -O2 -Wall -Wextra -I include"

echo "=========================================="
echo "  DPI Engine Build Script"
echo "  Compiler: $($GCC --version | head -1)"
echo "=========================================="

echo ""
echo "[1/2] Building single-threaded engine..."
$GCC $CXX_FLAGS \
    src/types.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/rule_manager.cpp \
    src/main_simple.cpp \
    -o dpi_simple.exe

echo "      OK: dpi_simple.exe"

echo ""
echo "[2/2] Building multi-threaded engine..."
$GCC $CXX_FLAGS -pthread \
    src/types.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/rule_manager.cpp \
    src/load_balancer.cpp \
    src/fast_path.cpp \
    src/dpi_engine.cpp \
    src/main_mt.cpp \
    -o dpi_engine.exe \
    -lpthread

echo "      OK: dpi_engine.exe"

echo ""
echo "=========================================="
echo "  Build complete!"
echo "=========================================="
echo ""
echo "Quick start:"
echo "  python scripts/generate_test_pcap.py"
echo "  ./dpi_simple.exe test_data/test_small.pcap output.pcap"
echo "  ./dpi_engine.exe test_data/test_small.pcap output_mt.pcap --lbs 2 --fps 2"
echo ""
