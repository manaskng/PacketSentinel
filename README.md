# DPI Engine v2.0

[![Build Status](https://github.com/YOUR_USERNAME/dpi-engine/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_USERNAME/dpi-engine/actions/workflows/build.yml)

A high-performance, **multi-threaded Deep Packet Inspection (DPI) engine** written in modern C++17. Classifies network traffic into 15 application types by parsing TLS SNI, HTTP Host headers, and DNS queries — **without any external libraries** (no libpcap, no Boost).

---

## Architecture

```
Reader (main thread)
    │
    ├──[hash]──→ LB Thread 0 ──[hash]──→ FP Thread 0 ──→ TSQueue<Packet>
    │                          ──[hash]──→ FP Thread 1 ──→ TSQueue<Packet>
    │
    └──[hash]──→ LB Thread 1 ──[hash]──→ FP Thread 2 ──→ TSQueue<Packet>
                               ──[hash]──→ FP Thread 3 ──→ TSQueue<Packet>
                                                              │
                                                    Writer Thread (PCAP out)
```

**Key design decisions:**
- **Per-FP flow tables** (no locks on hot path) — consistent 5-tuple hashing ensures all packets of one connection go to the same FastPath
- **Bounded TSQueue** with `condition_variable` (no busy-wait)  
- **Poison pill shutdown** — graceful drain-and-exit for all threads
- **Zero external dependencies** — pure C++17 stdlib only

---

## Application Detection

Three DPI signals are used:

| Signal | Protocol | How |
|---|---|---|
| **TLS SNI** | HTTPS (port 443) | Walk Client Hello extensions to find type `0x0000` |
| **HTTP Host** | HTTP (port 80/8080) | Scan request headers for `Host:` field |
| **DNS QNAME** | DNS (port 53/UDP) | Parse question section label walk |

Detected apps: YouTube, Netflix, TikTok, Facebook, Instagram, Twitter, Discord, WhatsApp, Twitch, Reddit, GitHub, Google

---

## Building

### Windows (requires MSYS2 + GCC 16)

```powershell
# Install MSYS2 from https://www.msys2.org/ then:
C:\msys64\mingw64\bin\g++.exe -std=c++17 -O2 -I include `
  -o dpi_simple.exe `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp src/main_simple.cpp

# Multi-threaded:
C:\msys64\mingw64\bin\g++.exe -std=c++17 -O2 -pthread -I include `
  -o dpi_engine.exe `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp `
  src/load_balancer.cpp src/fast_path.cpp src/dpi_engine.cpp `
  src/main_mt.cpp -lpthread
```

### Linux (GCC 13+)

```bash
# Ubuntu/Debian
sudo apt install g++-13
# Build
make all
```

---

## Usage

```bash
# Generate test data
python scripts/generate_test_pcap.py

# Single-threaded (shows all detected apps + report)
./dpi_simple test_data/test_small.pcap output.pcap

# Block YouTube and TikTok
./dpi_simple capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block by source IP
./dpi_simple capture.pcap filtered.pcap --block-ip 192.168.1.50

# Load rules from JSON
./dpi_simple capture.pcap filtered.pcap --rules-file rules.json

# Multi-threaded (2 LB × 2 FP = 4 worker threads)
./dpi_engine capture.pcap filtered.pcap --lbs 2 --fps 2

# Write stats.json for web dashboard
./dpi_engine capture.pcap filtered.pcap --stats-json
```

### rules.json format

```json
{
  "blocked_ips":     ["192.168.1.50"],
  "blocked_apps":    ["YouTube", "TikTok"],
  "blocked_domains": ["tiktok.com"],
  "throttled_apps":  ["Netflix"],
  "throttle_delay_ms": 10
}
```

---

## Web Dashboard

Open `dashboard/index.html` in a browser. It polls `stats.json` every 2 seconds.

To produce stats.json, run with `--stats-json`:
```bash
./dpi_engine capture.pcap out.pcap --stats-json
cp stats.json dashboard/
```

The dashboard shows:
- Live packet/forwarded/dropped/throughput metrics
- Application breakdown bar chart
- Per-thread (LB + FP) statistics
- Detected domain list with app classification

---

## Project Structure

```
DPI/
├── include/
│   ├── types.h              # Core types: Packet, Flow, FiveTuple
│   ├── pcap_reader.h        # PCAP file reader/writer (no libpcap)
│   ├── packet_parser.h      # Ethernet/IPv4/TCP/UDP parser
│   ├── sni_extractor.h      # TLS SNI + HTTP Host + DNS extraction
│   ├── rule_manager.h       # IP/app/domain blocking rules
│   ├── thread_safe_queue.h  # Bounded mutex+condvar queue
│   ├── load_balancer.h      # Hash-based packet router thread
│   ├── fast_path.h          # DPI worker thread
│   └── dpi_engine.h         # Multi-threaded orchestrator
├── src/
│   ├── types.cpp            # SNI→App mapping, IP utilities
│   ├── pcap_reader.cpp      # Binary PCAP I/O
│   ├── packet_parser.cpp    # Protocol header parsing
│   ├── sni_extractor.cpp    # Byte-walk DPI extractors
│   ├── rule_manager.cpp     # Rule engine + JSON loader
│   ├── load_balancer.cpp    # LB thread implementation
│   ├── fast_path.cpp        # FP thread implementation
│   ├── dpi_engine.cpp       # Engine orchestrator
│   ├── main_simple.cpp      # Single-threaded entry point
│   └── main_mt.cpp          # Multi-threaded entry point
├── dashboard/
│   ├── index.html           # Real-time web dashboard
│   ├── dashboard.css        # Dark glassmorphism UI
│   └── dashboard.js         # Poll/render logic
├── scripts/
│   ├── generate_test_pcap.py  # 50K-packet test dataset generator
│   └── benchmark.py           # Throughput benchmark harness
├── .github/workflows/build.yml  # CI for Linux + Windows
├── rules.json              # Example blocking rules
└── Makefile                # GNU Make build
```

---

## Interview Key Points

| Topic | Answer |
|---|---|
| Why no libpcap? | "Demonstrates understanding of binary file formats and byte-level I/O. Libpcap is a wrapper — reading the binary directly shows deeper knowledge." |
| Why per-FP flow tables? | "Eliminates all locking on the hot path. A shared table requires a mutex on every lookup — this negates parallelism benefits." |
| Why condition_variable? | "Busy-wait burns CPU. condvar sleeps the thread until data arrives, allowing the OS to schedule other work." |
| How does SNI extraction work? | "Walk the TLS record → Handshake → Client Hello extensions. Extension type 0x0000 is SNI. Extract hostname from bytes 5+ of the extension data." |
| How is traffic blocked? | "Flow table entry has a `blocked` flag. Once set (after first classification), all subsequent packets of that 5-tuple are dropped before rule evaluation." |

---

*Built as a portfolio project demonstrating: systems programming, network protocols, concurrent design patterns, performance engineering.*
