# PacketSentinel — Multi-threaded Deep Packet Inspection Engine

[![CI Build](https://github.com/manaskng/PacketSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/manaskng/PacketSentinel/actions/workflows/build.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-informational)](https://github.com/manaskng/PacketSentinel)
[![Language](https://img.shields.io/badge/language-C%2B%2B17-blue)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A high-performance, **zero-dependency** network traffic analysis engine written in pure C++17. PacketSentinel performs true Deep Packet Inspection — parsing TLS Client Hello extensions, HTTP Host headers, and DNS query sections at the byte level to classify live traffic into 15 application categories at wire speed.

Designed to demonstrate production-grade systems engineering: multi-threaded pipeline architecture, lock-free per-thread flow tables, and a decoupled real-time analytics dashboard.

---

## Performance

Benchmarked on a 4-core machine (2 Load Balancers x 2 Fast Paths):

| Metric | Result |
|---|---|
| Throughput (multi-threaded) | **438,000 packets/sec** |
| Throughput (single-threaded) | **255,000 packets/sec** |
| Packets processed in benchmark run | **35,320 packets** |
| Active flows tracked | **4,990 concurrent flows** |
| External library dependencies | **Zero** |
| Classification accuracy | Layer 7 application name from raw bytes |

> For reference, Python + Scapy (the standard data-science approach) typically saturates at 1,000–5,000 packets/sec before dropping packets. PacketSentinel processes traffic at 80–400x that rate.

---

## Dashboard

<!-- Add dashboard screenshot here -->
> Real-time enterprise analytics dashboard — polling `stats.json` every 2 seconds via Chart.js.
> Displays throughput timeline, application histogram, allowed/blocked ratio, per-thread distribution, and detected domain list.

---

## What It Does

PacketSentinel goes significantly deeper than basic network monitors that only read IP metadata. It performs byte-level parsing of application-layer protocols to determine **what the user is actually doing**, not just who they are talking to.

### Layer 7 Classification Signals

| DPI Signal | Target Protocol | Technique |
|---|---|---|
| **TLS SNI Extraction** | HTTPS (port 443) | Walks TLS record → Handshake → ClientHello extension list. Locates extension type `0x0000` and extracts the hostname string from the extension data offset. |
| **HTTP Host Header** | HTTP (port 80, 8080) | Scans the TCP payload byte-by-byte for the `Host:` header field in raw HTTP/1.x request buffers. |
| **DNS Query Name** | DNS (port 53 / UDP) | Parses the DNS Question Section using the label-length walk defined in RFC 1035 to reconstruct the fully-qualified domain name. |

### Detected Applications

YouTube, Netflix, TikTok, Facebook, Instagram, Twitter/X, Discord, WhatsApp, Twitch, Reddit, GitHub, Google — and any unknown domain is captured and listed.

### Traffic Control

Rules are loaded from `rules.json` at startup and applied on the hot path:

- Block by **application name** (e.g., block all YouTube traffic)
- Block by **source IP address** (e.g., quarantine a specific host)
- Block by **domain name** (e.g., block `tiktok.com` directly)
- Throttle by **application category** with configurable delay

Once a 5-tuple flow is classified, the decision is cached in the per-FastPath flow table. All subsequent packets of that connection are forwarded or dropped without re-running the DPI logic, maintaining wire-speed performance.

---

## Architecture

```
                     ┌─────────────────────────────────────────┐
                     │           Raw PCAP / Live Socket         │
                     └────────────────────┬────────────────────┘
                                          │
                               ┌──────────▼──────────┐
                               │   Reader (main)      │
                               │  5-tuple hash route  │
                               └───────┬──────┬───────┘
                                       │      │
                   ┌───────────────────▼┐    ┌▼───────────────────┐
                   │   Load Balancer 0  │    │   Load Balancer 1   │
                   │  (hash by src IP)  │    │  (hash by dst port) │
                   └──────┬──────┬──────┘    └──────┬──────┬───────┘
                          │      │                  │      │
              ┌───────────▼┐   ┌─▼──────────┐  ┌───▼──────▼───────┐
              │  FastPath 0 │   │  FastPath 1 │  │ FP 2   |  FP 3  │
              │  Flow Table │   │  Flow Table │  │ (own tables, no  │
              │  DPI Engine │   │  DPI Engine │  │  shared locks)   │
              └─────────────┘   └─────────────┘  └─────────────────┘
                                          │
                               ┌──────────▼──────────┐
                               │    stats.json        │
                               │  (async write, 1s)   │
                               └──────────┬──────────┘
                                          │
                               ┌──────────▼──────────┐
                               │  Web Dashboard       │
                               │  (polls every 2s)    │
                               └─────────────────────┘
```

### Design Decisions

**Per-FastPath flow tables (no shared state on hot path)**
A single shared flow table across threads would require a mutex on every packet lookup — a textbook lock contention bottleneck. Instead, the 5-tuple hash deterministically routes all packets belonging to one TCP/UDP flow to the same FastPath. This eliminates locking entirely on the classification path.

**Bounded TSQueue with `condition_variable`**
The thread-safe queue between Load Balancers and FastPaths uses a `std::condition_variable` rather than a busy-wait spin loop. This allows threads to sleep when the queue is empty, freeing the CPU for actual packet processing work rather than wasting cycles polling.

**Poison pill shutdown**
Graceful termination is signaled by enqueuing a sentinel value into each worker's queue. This ensures all threads drain their in-flight packets and flush statistics before exit — no `kill()`, no data loss.

**Decoupled dashboard via JSON**
The C++ engine writes statistics to `stats.json` asynchronously once per second. The web frontend polls this file independently. This means the UI is completely decoupled from the engine's hot path — a slow browser or dropped fetch request cannot stall packet processing.

---

## Build

### Windows (MSYS2 + GCC 16)

```powershell
# Single-threaded build
C:\msys64\mingw64\bin\g++.exe -std=c++17 -O2 -I include `
  -o dpi_simple.exe `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp src/main_simple.cpp

# Multi-threaded build
C:\msys64\mingw64\bin\g++.exe -std=c++17 -O2 -pthread -I include `
  -o dpi_engine.exe `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp `
  src/load_balancer.cpp src/fast_path.cpp src/dpi_engine.cpp `
  src/main_mt.cpp -lpthread
```

### Linux (GCC 13+)

```bash
sudo apt install g++-13
make all
```

CI builds run automatically on every push via GitHub Actions for both platforms.

---

## Usage

```bash
# Generate synthetic test data (50,000 packets across all app types)
python scripts/generate_test_pcap.py

# Single-threaded: classify and report
./dpi_simple test_data/test_small.pcap output.pcap

# Block specific applications
./dpi_simple capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block by source IP
./dpi_simple capture.pcap filtered.pcap --block-ip 192.168.1.50

# Load rules from JSON file
./dpi_simple capture.pcap filtered.pcap --rules-file rules.json

# Multi-threaded: 2 Load Balancers x 2 Fast Paths
./dpi_engine capture.pcap filtered.pcap --lbs 2 --fps 2

# Write real-time stats to stats.json for dashboard
./dpi_engine capture.pcap filtered.pcap --lbs 2 --fps 2 --stats-json

# Run throughput benchmark
python scripts/benchmark.py
```

### rules.json

```json
{
  "blocked_ips":       ["192.168.1.50", "10.0.0.99"],
  "blocked_apps":      ["YouTube", "TikTok", "Netflix"],
  "blocked_domains":   ["tiktok.com", "douyin.com"],
  "throttled_apps":    ["Twitch"],
  "throttle_delay_ms": 10
}
```

---

## Web Dashboard

Open `dashboard/index.html` in any browser. The dashboard polls `stats.json` every 2 seconds and renders live:

- **Throughput Timeline** — packets/sec over a 60-point rolling window
- **Application Histogram** — packet volume per detected application (blue gradient bars)
- **Action Doughnut** — forwarded vs. blocked ratio
- **Per-Thread Stats** — individual Load Balancer and FastPath packet counts
- **Detected Domains** — live list of TLS SNI / HTTP Host / DNS query names

A built-in demo mode activates automatically if no `stats.json` is present, simulating realistic network traffic for presentations.

To serve with live data:

```bash
./dpi_engine capture.pcap out.pcap --lbs 2 --fps 2 --stats-json
cp stats.json dashboard/
# Open dashboard/index.html in browser
```

---

## Project Structure

```
PacketSentinel/
├── include/
│   ├── types.h                # Core types: Packet, Flow, FiveTuple, AppType
│   ├── pcap_reader.h          # Binary PCAP reader/writer (no libpcap)
│   ├── packet_parser.h        # Ethernet / IPv4 / TCP / UDP header parsing
│   ├── sni_extractor.h        # TLS SNI + HTTP Host + DNS QNAME extraction
│   ├── rule_manager.h         # IP / application / domain blocking rules
│   ├── thread_safe_queue.h    # Bounded mutex + condvar queue
│   ├── load_balancer.h        # Hash-based packet router thread
│   ├── fast_path.h            # DPI worker thread
│   └── dpi_engine.h           # Multi-threaded orchestrator
├── src/
│   ├── types.cpp              # SNI-to-App mapping, IP utility functions
│   ├── pcap_reader.cpp        # Binary PCAP file I/O
│   ├── packet_parser.cpp      # Protocol header parsing implementation
│   ├── sni_extractor.cpp      # Byte-walk DPI extractor implementation
│   ├── rule_manager.cpp       # Rule engine + JSON loader
│   ├── load_balancer.cpp      # Load Balancer thread implementation
│   ├── fast_path.cpp          # FastPath DPI thread implementation
│   ├── dpi_engine.cpp         # Engine lifecycle and thread orchestration
│   ├── main_simple.cpp        # Single-threaded entry point
│   └── main_mt.cpp            # Multi-threaded entry point
├── dashboard/
│   ├── index.html             # Enterprise analytics dashboard
│   ├── dashboard.css          # Vercel-style dark theme
│   └── dashboard.js           # Chart.js polling and rendering
├── scripts/
│   ├── generate_test_pcap.py  # Synthetic 50K-packet test dataset generator
│   └── benchmark.py           # Throughput benchmark harness
├── test_data/                 # Generated test PCAP files
├── .github/workflows/
│   └── build.yml              # CI: Linux GCC 13 + Windows MSYS2 GCC 16
├── rules.json                 # Example blocking rules
├── Makefile                   # GNU Make build for Linux
└── DOCUMENTATION.md           # Full technical deep-dive
```

---

## CI / Continuous Integration

GitHub Actions runs on every push and pull request:

- **Linux:** Ubuntu latest, GCC 13, `make all`
- **Windows:** MSYS2 + MinGW-w64 GCC 16

Both targets must build cleanly before a commit is accepted. Badge status reflects the live state of the `main` branch.

---

## Technical Deep-Dive: How DPI Works

### TLS SNI Extraction (HTTPS Traffic)

TLS Client Hello packets arrive as raw TCP payload bytes. The extractor walks:

1. TLS Record Layer header (5 bytes) — type `0x16` (Handshake), version, length
2. Handshake header (4 bytes) — type `0x01` (ClientHello), length
3. ClientHello fields — version (2), random (32), session ID (variable), cipher suites (variable), compression methods (variable)
4. Extensions list — iterate each extension, checking the 2-byte type field for `0x0000` (SNI)
5. SNI extension — skip list header (2 bytes), entry header (3 bytes), read hostname of declared length

This is implemented as a single-pass byte-walk with bounds checking. No heap allocations occur on the hot path.

### DNS Query Extraction (UDP Port 53)

DNS label encoding uses a length-prefix format (RFC 1035). The extractor:

1. Skips the 12-byte fixed DNS header
2. Reads each label: the first byte is the length, followed by that many ASCII characters
3. Concatenates labels with `.` separators until a zero-length label (root) is reached
4. Returns the fully-qualified domain name (FQDN)

### Flow Table and Caching

Each FastPath maintains a `std::unordered_map<FiveTuple, FlowEntry>` keyed by (src IP, dst IP, src port, dst port, protocol). On first packet of a new flow, DPI runs and the result (app classification + block decision) is stored. On subsequent packets of the same flow, only a map lookup is needed — DPI extraction is skipped entirely.

---


*Full technical documentation, protocol parsing details, and architecture rationale are in [DOCUMENTATION.md](DOCUMENTATION.md).*
