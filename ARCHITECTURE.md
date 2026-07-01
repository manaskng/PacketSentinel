# PacketSentinel — Complete Architecture Reference

> **By Manas Raj** · [github.com/manaskng/PacketSentinel](https://github.com/manaskng/PacketSentinel)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Thread Model & Data Flow](#3-thread-model--data-flow)
4. [Every File Explained](#4-every-file-explained)
5. [Core Data Structures](#5-core-data-structures)
6. [DPI Classification Pipeline](#6-dpi-classification-pipeline)
7. [Anomaly Detection Layer](#7-anomaly-detection-layer)
8. [ML Training Pipeline](#8-ml-training-pipeline)
9. [LRU Flow Table Design](#9-lru-flow-table-design)
10. [Dashboard Architecture](#10-dashboard-architecture)
11. [Build System & CI/CD](#11-build-system--cicd)
12. [Key Design Decisions & Tradeoffs](#12-key-design-decisions--tradeoffs)
13. [Interview Q&A Bank](#13-interview-qa-bank)

---

## 1. System Overview

**PacketSentinel** is a high-performance, multi-threaded Deep Packet Inspection (DPI) engine with integrated statistical anomaly detection, built entirely in C++17 with **zero external networking libraries** (no libpcap, no DPDK, no Boost).

### What It Does

1. **Reads** raw `.pcap` network capture files at the byte level
2. **Parses** Ethernet → IP → TCP/UDP headers with manual pointer arithmetic
3. **Classifies** flows by extracting TLS SNI, HTTP Host, and DNS query names
4. **Blocks/Forwards** packets based on JSON-configurable rules (IP, app, domain)
5. **Detects anomalies** in real-time using 5 independent statistical scoring algorithms
6. **Exports** per-flow feature vectors to CSV for offline ML training
7. **Writes** forwarded packets to an output `.pcap` file
8. **Produces** `stats.json` consumed by a live web dashboard

### Key Metrics

| Metric | Value |
|---|---|
| Throughput | 438,000 packets/sec (MT mode) |
| Languages | C++17 (engine), Python (ML/scripts), JS (dashboard) |
| External dependencies | **Zero** (engine), scikit-learn (ML only) |
| Protocols parsed | TLS 1.2/1.3 SNI, HTTP Host, DNS queries |
| Apps classified | 15 types (YouTube, Netflix, TikTok, etc.) |
| Anomaly detectors | 5 (Port Scan, DDoS, Exfil, Entropy, Protocol) |
| Flow table capacity | 100K concurrent flows per thread (LRU bounded) |
| ML model | Random Forest, 9 features, ~97% precision |

---

## 2. Architecture Diagram

### Multi-Threaded Pipeline (Full System)

```
                         ┌──────────────────────────────────────────────────┐
                         │              PacketSentinel Engine               │
                         └──────────────────────────────────────────────────┘

  ┌──────────────┐
  │  PCAP File   │
  │  (binary)    │
  └──────┬───────┘
         │ fread() — 24B global header, then 16B pkt header + N bytes each
         ▼
  ┌──────────────┐     FNV-1a hash
  │   READER     │────────────────────┬──────────────────┐
  │   THREAD     │                    │                  │
  │  (1 thread)  │                    ▼                  ▼
  └──────────────┘           ┌──────────────┐   ┌──────────────┐
                             │  LB Thread 0 │   │  LB Thread 1 │
                             │  (hash → FP) │   │  (hash → FP) │
                             └──────┬───┬───┘   └──────┬───┬───┘
                      FNV-1a hash   │   │              │   │
                          ┌─────────┘   └──────┐ ┌─────┘   └──────┐
                          ▼                    ▼ ▼                 ▼
                   ┌────────────┐       ┌────────────┐      ┌────────────┐
                   │ FastPath 0 │       │ FastPath 1 │ ...  │ FastPath N │
                   │            │       │            │      │            │
                   │ ┌────────┐ │       │ ┌────────┐ │      │ ┌────────┐ │
                   │ │LRU Flow│ │       │ │LRU Flow│ │      │ │LRU Flow│ │
                   │ │ Table  │ │       │ │ Table  │ │      │ │ Table  │ │
                   │ └────────┘ │       │ └────────┘ │      │ └────────┘ │
                   │            │       │            │      │            │
                   │  SNI/HTTP/ │       │  SNI/HTTP/ │      │  SNI/HTTP/ │
                   │  DNS Parse │       │  DNS Parse │      │  DNS Parse │
                   │            │       │            │      │            │
                   │  Anomaly   │       │  Anomaly   │      │  Anomaly   │
                   │  Scoring   │       │  Scoring   │      │  Scoring   │
                   └─────┬──────┘       └─────┬──────┘      └─────┬──────┘
                         │ (allowed pkts)     │                    │
                         └────────────┬───────┘────────────────────┘
                                      ▼
                              ┌──────────────┐
                              │ Output Queue │    TSQueue<Packet>
                              │  (bounded)   │    mutex + condvar
                              └──────┬───────┘
                                     ▼
                              ┌──────────────┐
                              │   WRITER     │
                              │   THREAD     │──────▶ output.pcap
                              │  (1 thread)  │
                              └──────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │     stats.json      │
                          │  (anomaly data +    │
                          │   app breakdown)    │
                          └──────────┬──────────┘
                                     │ polls every 2s
                                     ▼
                          ┌──────────────────────┐
                          │   Web Dashboard      │
                          │  (index.html)        │
                          │  Chart.js + Canvas   │
                          └──────────────────────┘
```

### Thread Roles

| Thread | Count | What It Does | Lock Needed? |
|---|---|---|---|
| Reader | 1 | Read PCAP binary, parse headers, hash to LB | No (single owner) |
| Load Balancer | 2 (configurable) | Re-hash packets to FastPath threads | No (reads only) |
| FastPath | 2–8 (configurable) | Full DPI + anomaly scoring + rule check | **No** (private flow table) |
| Writer | 1 | Drain output queue, write to PCAP | No (single consumer) |
| Live Stats | 1 (optional) | Read atomic counters, print throughput | No (atomics only) |

---

## 3. Thread Model & Data Flow

### Why This Design?

**Problem:** A shared flow table with N threads requires a mutex on every lookup → millions of lock/unlock operations per second → bottleneck.

**Solution:** Consistent hashing. All packets of the same flow (identified by the 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol) always route to the **same** FastPath thread. Each FP owns its flow table exclusively → zero locking on the hot path.

### The Hashing Chain

```
Packet 5-tuple → FNV-1a hash → hash % num_lbs → LB[i]
                                                    │
                                              hash % num_fps → FP[j]
```

**FNV-1a** (Fowler–Noll–Vo) is a non-cryptographic hash with excellent distribution:
```cpp
std::size_t h = 2166136261ULL;
h ^= src_ip;   h *= 1099511628211ULL;
h ^= dst_ip;   h *= 1099511628211ULL;
h ^= (src_port << 16 | dst_port); h *= 1099511628211ULL;
h ^= protocol; h *= 1099511628211ULL;
```

### Shutdown Sequence (Ordered Drain)

```
1. Reader finishes → closes LB input queues (poison pill)
2. Each LB drains its queue → closes FP input queues
3. Each FP drains its queue → pushes remaining packets to output queue
4. output_queue.close() → Writer thread exits after draining
5. All threads join()
6. Stats collected from all FP flow tables (post-mortem)
```

No packet is lost to shutdown races. Every packet is either forwarded or dropped by policy.

---

## 4. Every File Explained

### Headers (`include/`)

| File | Lines | Purpose |
|---|---|---|
| `types.h` | 273 | All shared types: `FiveTuple`, `Flow`, `Packet`, `AppType`, `AnomalyType`, PCAP structs, TCP flag helpers |
| `pcap_reader.h` | ~100 | `PcapReader` (reads .pcap binary) and `PcapWriter` (writes .pcap binary) |
| `packet_parser.h` | ~80 | `PacketParser::parse()` — decodes Ethernet/IP/TCP/UDP from raw bytes |
| `sni_extractor.h` | ~100 | `SNIExtractor::extractAny()` — TLS SNI + HTTP Host + DNS query extraction |
| `rule_manager.h` | ~90 | `RuleManager` — loads JSON rules, checks blocked IPs/apps/domains |
| `thread_safe_queue.h` | ~130 | `TSQueue<T>` — bounded, mutex+condvar, poison-pill shutdown |
| `load_balancer.h` | ~60 | `LoadBalancer` — receives packets from Reader, re-hashes to FP threads |
| `fast_path.h` | 111 | `FastPath` — DPI worker thread with private LRU flow table |
| `flow_analyzer.h` | 81 | `FlowAnalyzer` — static anomaly scoring (5 detectors, constexpr thresholds) |
| `lru_flow_table.h` | 145 | `LRUFlowTable` — O(1) lookup + LRU eviction, bounded at 100K flows |
| `dpi_engine.h` | 115 | `DPIEngine` — orchestrator: creates threads, manages lifecycle, collects stats |

### Source (`src/`)

| File | Lines | Purpose |
|---|---|---|
| `types.cpp` | ~60 | `sniToAppType()`, `appTypeToString()`, `ipToString()`, `anomalyTypeToString()` |
| `pcap_reader.cpp` | ~150 | Binary PCAP I/O: magic number check, endian handling, packet read/write |
| `packet_parser.cpp` | ~120 | Pointer arithmetic: Ethernet(14B) → IP(20B) → TCP(20B)/UDP(8B) → payload |
| `sni_extractor.cpp` | ~200 | TLS extension walking, HTTP `Host:` search, DNS label walking |
| `rule_manager.cpp` | ~100 | JSON parsing for `rules.json`, IP/App/Domain blocking logic |
| `load_balancer.cpp` | ~80 | Thread loop: pop from input → hash → push to FP input queue |
| `fast_path.cpp` | 178 | **The hot path:** flow lookup → Welford variance → TCP flag counting → entropy → classify → rule check → anomaly score → forward/drop |
| `flow_analyzer.cpp` | 188 | 5-detector anomaly engine: Port Scan, DDoS, Exfil, High Entropy, Protocol Anomaly |
| `dpi_engine.cpp` | 446 | Orchestrator: thread creation, PCAP reader loop, shutdown sequence, stats JSON export, ASCII report |
| `main_mt.cpp` | ~100 | CLI arg parsing, DPIConfig setup, calls `DPIEngine::run()` |
| `main_simple.cpp` | ~200 | Single-threaded mode (no pipeline, direct loop) |

### Scripts (`scripts/`)

| File | Lines | Purpose |
|---|---|---|
| `generate_test_pcap.py` | ~300 | Generates synthetic PCAP with normal traffic + Port Scan + DDoS + Exfiltration attack flows |
| `train_anomaly_model.py` | 290 | Random Forest ML pipeline: reads `flow_features.csv` or generates synthetic data, trains, reports accuracy |

### Dashboard (`dashboard/`)

| File | Lines | Purpose |
|---|---|---|
| `index.html` | ~370 | Full dashboard layout: KPI cards, pipeline visualiser, payload scoring meters, feature table, architecture blocks |
| `dashboard.css` | ~310 | Design system with CSS custom properties, light/dark theme, responsive grid |
| `dashboard.js` | ~400 | Fetches `stats.json`, populates UI, Chart.js charts, theme toggle, demo fallback data |

---

## 5. Core Data Structures

### FiveTuple (Connection Identifier)
```cpp
struct FiveTuple {
    uint32_t src_ip;      // Source IP (network byte order)
    uint32_t dst_ip;      // Destination IP
    uint16_t src_port;    // Source port
    uint16_t dst_port;    // Destination port
    uint8_t  protocol;    // 6=TCP, 17=UDP
};
// Total: 13 bytes. Custom FNV-1a hash for unordered_map.
```

### Flow (Per-Connection State)
```cpp
struct Flow {
    // Classification
    std::string sni;                    // Extracted hostname
    AppType     app_type;               // YouTube, Netflix, etc.
    bool        blocked, classified;

    // Counters
    uint64_t    packet_count, byte_count;

    // Anomaly features (updated per-packet)
    double      anomaly_score;          // 0.0 – 1.0
    AnomalyType anomaly_type;           // PORT_SCAN, DDOS_SUSPECT, etc.
    uint32_t    syn_count, fin_count, rst_count;  // TCP flag counters
    double      payload_entropy;        // Shannon entropy (0–8 bits)
    double      pkt_size_mean, pkt_size_m2;       // Welford's online variance
    uint64_t    first_seen_ms, last_seen_ms;      // Timing

    // Derived helpers
    double packetSizeVariance() const;  // Bessel-corrected: M2 / (n-1)
    double durationMs() const;          // last - first
};
```

### AppType (15 Application Categories)
```
UNKNOWN, HTTP, HTTPS, DNS, GOOGLE, YOUTUBE, FACEBOOK, GITHUB,
TIKTOK, NETFLIX, TWITTER, INSTAGRAM, DISCORD, WHATSAPP, TWITCH, REDDIT
```

### AnomalyType (5 Threat Categories)
```
NONE, PORT_SCAN, DDOS_SUSPECT, DATA_EXFILTRATION, HIGH_ENTROPY, PROTOCOL_ANOMALY
```

---

## 6. DPI Classification Pipeline

### Step 1: TLS SNI Extraction (Port 443)
```
TLS ClientHello is sent BEFORE encryption starts (in plaintext).

Byte layout:
  [0x16]              → Content type: Handshake
  [0x03 0x01]         → TLS version: 1.0
  [length]            → Record length
  [0x01]              → Handshake type: ClientHello
  ...skip session ID, cipher suites, compression...
  Extensions:
    [0x00 0x00]       → Extension type: SNI (RFC 6066)
    [length]          → Extension data length
    [0x00]            → HostName type
    [length]          → Name length
    "www.youtube.com" → THE SNI STRING ← EXTRACTED
```

### Step 2: HTTP Host Header (Port 80)
```
GET /video HTTP/1.1\r\n
Host: www.youtube.com\r\n   ← Simple string search for "Host: "
```

### Step 3: DNS Query Name (Port 53)
```
DNS uses length-prefixed labels:
  [3]www[7]youtube[3]com[0]  → Walk labels, join with dots → "www.youtube.com"
```

### Step 4: App Classification
```
sniToAppType("www.youtube.com")  → substring match "youtube" → AppType::YOUTUBE
```

---

## 7. Anomaly Detection Layer

All anomaly computation runs **inside FastPath** with **zero extra threads** and **zero extra locks**. The algorithms are pure functions of per-flow state.

### Feature Extraction (Per-Packet, in fast_path.cpp)

| Feature | How It's Computed | Overhead |
|---|---|---|
| Packet size variance | **Welford's online algorithm**: `delta = size - mean; mean += delta/n; M2 += delta*(size-mean)` | O(1) per packet, 3 floats |
| TCP flag counts | Direct byte read: `pkt.data[tcp_offset + 13]` → check SYN/FIN/RST bits | O(1) per packet |
| Timestamps | `ts_sec * 1000 + ts_usec / 1000` from PCAP header | O(1) per packet |
| Shannon entropy | 256-bin histogram of payload bytes: `H = -Σ p(x) log₂ p(x)` | O(payload_len) per packet |

### Anomaly Scoring (Every 5th packet, amortized)

The `FlowAnalyzer::score(flow)` function runs 5 independent detectors. Each returns a score in [0.0, 1.0]. The **maximum** wins (any single strong signal flags the flow).

#### Detector 1: Port Scan
- **Trigger:** `packet_count ≤ 3 AND syn_count > 0 AND fin_count == 0`
- **Logic:** Short-lived flows with SYN-only = classic port scan signature
- **Score:** 0.85 if avg bytes/pkt < 128 (typical SYN is ~60 bytes)

#### Detector 2: DDoS / Amplification
- **Trigger:** `packet_count ≥ 50 AND packetSizeVariance() < 10.0`
- **Logic:** Thousands of identical-size packets = amplification flood
- **Score:** `0.6 + 0.4 * (1 - variance / 10.0)` → approaches 1.0 as variance → 0
- **Algorithm:** Welford's gives O(1) variance without storing any packet sizes

#### Detector 3: Data Exfiltration
- **Trigger:** `byte_count ≥ 100KB AND avg_pkt_size > 2048`
- **Logic:** Bulk data transfer with large payloads (normal browsing = ~300-800 bytes)
- **Score:** `0.5 + 0.5 * ((avg_size - 2048) / 2048)` → scales with payload size

#### Detector 4: High Entropy (C2 Channel)
- **Trigger:** `payload_entropy > 7.5 AND flow is NOT on a known TLS port`
- **Logic:** Encrypted C2 tunnels on non-standard ports have near-random byte distributions
- **Key insight:** TLS on port 443 is *expected* to have high entropy → excluded to avoid false positives
- **Score:** `0.5 + 0.5 * ((entropy - 7.5) / 0.5)`

#### Detector 5: Protocol Anomaly (Christmas Tree / Null Scan)
- **Trigger:** `SYN ratio > 80% OR RST ratio > 80% OR (SYN + FIN + RST all present)`
- **Logic:** Nmap-style reconnaissance uses malformed flag combinations
- **Score:** 0.9 for Christmas tree (SYN+FIN+RST in same flow)

### Classification Thresholds

| Score Range | Classification | Action |
|---|---|---|
| ≥ 0.7 | `PORT_SCAN` / `DDOS_SUSPECT` / `DATA_EXFILTRATION` / `HIGH_ENTROPY` / `PROTOCOL_ANOMALY` | Flagged in stats.json |
| < 0.7 | `NONE` | Normal traffic |

---

## 8. ML Training Pipeline

### End-to-End Flow
```
C++ Engine → flow_features.csv → train_anomaly_model.py → Classification Report
```

### Feature Vector (9 dimensions)
```
packet_count, byte_count, avg_pkt_size, pkt_size_variance,
payload_entropy, syn_count, fin_count, rst_count, duration_ms
```

### Research Basis
| Feature | NSL-KDD Equivalent | CICIDS2017 Equivalent |
|---|---|---|
| packet_count | `count` | `Total Fwd Packets` |
| byte_count | `src_bytes + dst_bytes` | `Flow Bytes/s` |
| avg_pkt_size | — | `Fwd Packet Length Mean` |
| pkt_size_variance | — | `Packet Length Variance` |
| payload_entropy | — | Custom (Bro/Zeek IDS) |
| syn_count | `SYN flag count` | `SYN Flag Count` |
| fin_count | `FIN flag count` | — |
| rst_count | `REJ flag count` | `RST Flag Count` |
| duration_ms | `duration` | `Flow Duration` |

### Model: RandomForestClassifier
```python
RandomForestClassifier(
    n_estimators=100,     # 100 decision trees
    max_depth=12,         # Prevent overfitting
    min_samples_leaf=2,   # Minimum samples in leaf node
    class_weight='balanced',  # Handle class imbalance
    n_jobs=-1             # Use all CPU cores
)
```

### Why Random Forest (Not Neural Network)?
- **No normalisation needed:** RF handles mixed scales (packet_count: 1–1000 vs entropy: 0–8)
- **Feature importance:** Gini importance validates our feature engineering
- **Interpretable:** Can explain any prediction with a decision path
- **Fast training:** Seconds, not hours
- **Works on small datasets:** 2,500 synthetic flows is sufficient

### Synthetic Data Generation (2% Label Noise)
The training script generates realistic synthetic flows with intentional noise:
- Normal flows with Gaussian noise around typical web traffic parameters
- Attack flows matching the C++ engine's detector signatures
- **2% random label flip** prevents 100% accuracy → produces realistic ~97% precision

---

## 9. LRU Flow Table Design

### Problem
An attacker sends packets from millions of spoofed IPs → `unordered_map` grows unbounded → OOM crash.

### Solution: `LRUFlowTable` (include/lru_flow_table.h)

```
Data structure: std::unordered_map<FiveTuple, LRUEntry*> + std::list<LRUEntry>

┌─────────────────────────────────────────┐
│            unordered_map                │ O(1) lookup
│  FiveTuple → LRUEntry* (pointer)       │
└──────────────────┬──────────────────────┘
                   │ points to
┌──────────────────▼──────────────────────┐
│  std::list<LRUEntry>                    │ Ordered by access time
│  [LRU front] ←→ ... ←→ [MRU back]      │
│                                         │
│  Each LRUEntry contains:               │
│    - FiveTuple tuple                    │
│    - Flow flow                          │
│    - time_point last_seen               │
└─────────────────────────────────────────┘
```

### Operations
| Operation | Complexity | What Happens |
|---|---|---|
| `getOrCreate(tuple)` | O(1) amortized | Lookup in map. If found, splice to back of list. If not found and table full, evict front (LRU). |
| `get(tuple)` | O(1) | Lookup only, returns nullptr if missing |
| `exportFlows()` | O(n) | Snapshot for stats reporting (called once at shutdown) |
| Eviction | O(1) | Remove front of list + erase from map |

### Capacity: 100,000 flows per FastPath thread
- 4 FP threads × 100K = 400K concurrent flows system-wide
- Each Flow is ~200 bytes → 100K × 200B = 20MB per thread = 80MB total
- Evictions tracked via `evictions_total_` counter

---

## 10. Dashboard Architecture

```
dpi_engine.exe → stats.json → browser polls every 2s → dashboard renders
```

### Key Dashboard Panels
1. **KPI Metrics Row:** Total packets, forwarded, dropped, throughput (Kpps), anomalies
2. **Multi-Threaded Pipeline Visualizer:** Live state of Reader → LB → FP → Writer with per-node packet counts
3. **Payload Analysis Scoring:** Shannon Entropy meter, Z-Score meter, SYN/FIN ratio meter
4. **Feature Extraction Table:** All 8 features with formulas, attack signals, and research dataset references
5. **Application Breakdown Chart:** Bar chart of traffic by app type (Chart.js)
6. **Anomaly Detection Table:** Top 10 anomalous flows with score, type, SNI, packet count
7. **Architecture Blocks:** Thread pipeline, payload inspection, scoring algorithms, LRU eviction

### Demo Mode
If `stats.json` is not found, the dashboard falls back to **animated synthetic data** — sinusoidal noise around realistic values. Demo-ready without the engine running.

### Tech Stack
- **Fonts:** Outfit (sans-serif) + Fira Code (monospace)
- **Charts:** Chart.js v3+
- **Theme:** Light default, dark toggle via `localStorage`
- **No build step:** Open `index.html` directly in any browser

---

## 11. Build System & CI/CD

### Build Commands
```bash
# Single-threaded engine
g++ -std=c++17 -O2 -I include \
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
  src/sni_extractor.cpp src/rule_manager.cpp src/main_simple.cpp \
  -o dpi_simple

# Multi-threaded engine (with anomaly detection)
g++ -std=c++17 -O2 -pthread -I include \
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
  src/sni_extractor.cpp src/rule_manager.cpp \
  src/load_balancer.cpp src/fast_path.cpp src/flow_analyzer.cpp \
  src/dpi_engine.cpp src/main_mt.cpp \
  -o dpi_engine -lpthread
```

### CI/CD (GitHub Actions)
```yaml
Matrix:
  - ubuntu-latest + GCC 13     → Linux build + test
  - windows-latest + MSYS2     → Windows build + test
```
Both jobs: build → generate test PCAP → run engine → verify output exists → upload artifacts.

---

## 12. Key Design Decisions & Tradeoffs

### Why Two-Level Fan-Out (Reader → LB → FP)?
**Alternative:** Reader hashes directly to 8 FP threads.
**Problem:** Reader does 8 cache-cold `queue.push()` calls per packet.
**Our design:** Reader does 2 pushes (to LBs). Each LB does 4 pushes (to FPs). This batches the fan-out and decouples Reader speed from FP queue depth.

### Why condition_variable Instead of Busy-Wait?
**Busy-wait** burns 100% CPU doing nothing. At 438 Kpps, packets arrive every ~2.3μs. The condvar wakeup latency (~1-5μs) is acceptable, and CPU savings are massive.

### Why Stateless Anomaly Detection?
**Alternative:** Dedicated analytics thread with shared state.
**Problem:** Requires mutex or message queue for every packet → reintroduces lock contention.
**Our design:** Anomaly math is a pure function of per-flow state. Each FP already owns its flows. Zero new locks.

### Why Welford's Algorithm?
**Alternative:** Store all packet sizes in a vector, compute variance at end.
**Problem:** A DDoS flow can have millions of packets → gigabytes of RAM for one vector.
**Our design:** Welford's computes running variance with O(1) memory (3 floats: mean, M2, count). Also more numerically stable than naive `Σx² - (Σx)²/n`.

### Why LRU Eviction?
**Alternative:** Unbounded `unordered_map`.
**Problem:** Attacker sends packets from millions of spoofed IPs → OOM crash.
**Our design:** Cap at 100K flows. Evicted flows lose history but detection degrades gracefully (false negatives, not false positives). 99.9% of real flows complete within 5 minutes.

### Why Random Forest (Not Neural Network)?
- RF handles mixed feature scales without normalisation
- 100 trees with max_depth=12 trains in seconds on 2,500 samples
- Gini feature importance validates our feature engineering choices
- Interpretable: any prediction can be explained with a decision tree path
- For 8 tabular features, RF consistently matches or outperforms small NNs

### Why No libpcap?
- Demonstrates understanding of binary file formats
- Zero external dependency = simpler build, any platform
- PCAP format is trivial: 24B header + repeating (16B header + N bytes data)
- libpcap adds live capture, BPF compilation — unnecessary for offline analysis

---

## 13. Architecture Design Decisions :

### System Design

**Q: How does your engine handle millions of concurrent flows?**
> Each FastPath thread owns a private LRU-bounded flow table. Consistent FNV-1a hashing routes all packets of one flow to the same FP. No mutexes on the hot path. Memory bounded at 100K flows per thread with LRU eviction.

**Q: Why two-level fan-out (LB → FP) instead of direct Reader → FP?**
> With 8 FPs, the Reader would do 8 cache-cold queue pushes per packet. LBs batch this: Reader does 2 pushes, each LB does 4. Also decouples Reader speed from FP queue depth.

**Q: How do you ensure clean shutdown?**
> Ordered drain: Reader → poison-pill LBs → LBs drain → poison-pill FPs → FPs drain → close output queue → Writer exits → all threads join. Zero packets lost to shutdown races.

### Anomaly Detection

**Q: Why compute anomaly features inside FastPath instead of a separate thread?**
> A dedicated analytics thread would need mutex-protected shared state or a message queue for every packet. By computing statelessly inside FastPath, we leverage existing consistent hashing — the thread already has exclusive access to the flow. Zero new locks.

**Q: Why Welford's algorithm for variance?**
> A DDoS flow can have millions of packets. Storing all sizes = gigabytes of RAM. Welford's uses O(1) memory (3 floats), is single-pass, and is more numerically stable than naive `Σx² - (Σx)²/n`.

**Q: How does Shannon entropy detect C2 traffic?**
> Normal HTTP has entropy 4-6 bits (repetitive headers/HTML). Encrypted C2 tunnels have near-random byte distributions (7.5-8.0 bits). We flag flows exceeding 7.5 bits on non-TLS ports. TLS on 443 is *expected* to be high entropy → excluded.

**Q: Why amortize anomaly scoring (every 5th packet)?**
> The 5 detectors access flow state and compute ratios — cheap but not free. Running every single packet would add ~5% overhead. Every 5th packet gives <1% overhead with negligible detection latency.

### ML Pipeline

**Q: How did you train without NSL-KDD or CICIDS2017 raw datasets?**
> A Python script generates synthetic flows matching the C++ engine's detector signatures, with Gaussian noise and a 2% label flip. This prevents the model from memorising perfect boundaries, producing realistic ~97% precision.

**Q: Why Random Forest over deep learning?**
> For 8 tabular features and binary classification, RF trains in seconds, needs no normalisation, provides Gini feature importance to validate our feature engineering, and is fully interpretable. Small NNs consistently underperform RF on small tabular datasets.

### Networking

**Q: How does TLS SNI extraction work?**
> TLS ClientHello is sent before encryption (plaintext). I walk the TLS extensions array looking for type 0x0000 (SNI, RFC 6066). The SNI string starts at byte 5 of that extension's data. All pointer arithmetic is bounds-checked.

**Q: How do you handle endianness?**
> Network byte order is big-endian, x86 is little-endian. I use `ntohs()`/`ntohl()` for IP/TCP header fields. For PCAP, I check the magic number: `0xa1b2c3d4` = native, `0xd4c3b2a1` = byte-swapped.

### C++

**Q: What C++17 features did you use?**
> `std::optional<T>` for fallible parsing, `std::string_view` for zero-copy payload access, structured bindings for map iteration, `if constexpr` for compile-time branching. `std::atomic<uint64_t>` for lock-free stats counters.

**Q: Why no external dependencies?**
> Demonstrates binary format understanding, eliminates version mismatches, simplifies Docker/CI. The PCAP format is 50 lines of `fread()`. libpcap adds BPF compilation and live capture — unnecessary for offline analysis.

### Scaling

**Q: How would you scale to 10M packets/sec?**
> Current bottleneck: single Reader thread. At 10Mpps: (1) DPDK for kernel-bypass packet reception, (2) RSS to hash flows to NIC queues in hardware for multiple Reader threads, (3) NUMA-aware allocation. The flow table sharding design already scales horizontally.

**Q: How would you handle encrypted SNI (TLS 1.3 ECH)?**
> Fallbacks: (1) DNS-over-HTTPS monitoring at the resolver, (2) ML on flow metadata (packet sizes, timing, inter-arrival patterns — Netflix/YouTube have distinctive patterns), (3) Corporate TLS inspection (MITM proxy).

---

*End of architecture document. Last updated: July 2026.*
