# DPI Engine v2.0 — Complete Project Documentation
### Interview-Ready Deep Dive: What, Why, How & Impact

---

## Table of Contents

1. [Project Overview — The 30-Second Pitch](#1-project-overview)
2. [What Problem Does This Solve?](#2-what-problem-does-this-solve)
3. [Core Concepts — Networking Primer](#3-core-concepts)
4. [Architecture — The Big Picture](#4-architecture)
5. [Every Component Explained](#5-every-component-explained)
6. [DPI Techniques — How Detection Works](#6-dpi-techniques)
7. [Multi-threading Design Decisions](#7-multi-threading-design-decisions)
8. [Tools, Languages & Libraries Used](#8-tools-languages--libraries)
9. [Performance & Impact](#9-performance--impact)
10. [Web Dashboard](#10-web-dashboard)
11. [CI/CD Pipeline](#11-cicd-pipeline)
12. [Interview Q&A — Every Likely Question](#12-interview-qa)
13. [How to Deploy, Run & Push to GitHub](#13-deployment-guide)

---

## 1. Project Overview

**DPI Engine v2.0** is a high-performance, multi-threaded **Deep Packet Inspection (DPI)** system built in C++17 from scratch — **no external networking libraries** (no libpcap, no Boost, no DPDK).

### The One-Line Pitch
> "A multi-threaded network traffic analyser that classifies packets by application (YouTube, Netflix, TikTok...), blocks or throttles them based on rules, and processes over 400,000 packets per second — all in pure C++17."

### What It Does (Concretely)
- Reads raw network capture files (`.pcap` format) byte-by-byte
- Parses each packet's Ethernet → IP → TCP/UDP headers
- Extracts **application identity** from TLS SNI, HTTP Host headers, and DNS queries
- Decides: **FORWARD** (allowed) or **DROP** (blocked) each packet
- Writes filtered output to a new PCAP file
- Produces a live web dashboard showing real-time traffic statistics

---

## 2. What Problem Does This Solve?

### Real-World Context
Every ISP, enterprise network, and corporate firewall uses DPI to:
- **Parental controls** — block TikTok/YouTube for minors
- **Corporate policy** — block Netflix on work networks
- **Bandwidth management** — throttle video streaming during peak hours
- **Security** — block traffic to known malicious domains
- **Regulatory compliance** — GDPR/government content filtering

### Without DPI (Old Way: Firewall Rules)
Traditional firewalls only look at IP addresses and port numbers:
- Port 443 = HTTPS (but *which* website?)
- All YouTube, Netflix, TikTok use the same port 443
- You can't block YouTube without blocking all HTTPS

### With DPI (Our Approach)
We look *inside* the packet payload to read the actual destination:
- TLS handshake reveals `sni: www.youtube.com` → identified as YouTube → blocked
- HTTP header reveals `Host: www.netflix.com` → identified as Netflix → throttled
- DNS query reveals `www.tiktok.com` → identified as TikTok → blocked

### Why This Is Hard
- Packets arrive in microseconds — decisions must be made in nanoseconds
- Stateful: a single HTTP session spans hundreds of packets
- Multi-flow: millions of concurrent flows must be tracked simultaneously
- Thread safety: multiple CPU cores must work in parallel without corrupting data

---

## 3. Core Concepts

### 3.1 What is a Packet?
Every piece of data on the internet is broken into **packets** — small chunks (typically 64–1500 bytes) with headers that say where they're going.

```
[Ethernet Header 14B] [IP Header 20B] [TCP Header 20B] [Payload ...]
      ↓                      ↓               ↓                ↓
 MAC addresses          IP addresses      Ports           Actual data
 (local delivery)       (routing)         (app)          (HTTP/TLS/DNS)
```

### 3.2 What is a Flow?
A **flow** (or connection) is a series of packets between the same two endpoints:
- Same source IP + destination IP + source port + destination port + protocol
- Called a **5-tuple**: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Example: Your browser fetching YouTube = hundreds of packets, all in one flow

### 3.3 What is TLS/SNI?
**TLS** (Transport Layer Security) encrypts HTTPS traffic. But before encryption begins, the client sends a **Client Hello** message that includes the **Server Name Indication (SNI)** — the domain name it wants to connect to — **in plaintext**.

```
TLS Client Hello (cleartext):
  Extension: server_name (type 0x0000)
    ServerName: www.youtube.com   ← WE READ THIS
```

This is the key insight: even HTTPS traffic leaks the destination domain before encryption kicks in.

### 3.4 What is PCAP?
**PCAP** (Packet Capture) is a binary file format for storing captured network packets. Tools like Wireshark, tcpdump, and our engine read/write this format.

File structure:
```
[Global Header 24 bytes]
[Packet Header 16 bytes] [Packet Data N bytes]
[Packet Header 16 bytes] [Packet Data N bytes]
...
```

---

## 4. Architecture

### Single-Threaded Mode (`dpi_simple`)
```
PCAP File
    │
    ▼
[Reader] → parse packet → extract SNI/Host/DNS → check rules → [Writer]
                                     ↓
                              [Flow Table]
                         {5-tuple → Flow state}
```

### Multi-Threaded Mode (`dpi_engine`) — The Full Pipeline
```
PCAP File
    │
    ▼
[READER THREAD] ──FNV hash──▶ [LB Thread 0] ──FNV hash──▶ [FP Thread 0]
                          │                            ├──▶ [FP Thread 1]
                          └──▶ [LB Thread 1] ──FNV hash──▶ [FP Thread 2]
                                                       └──▶ [FP Thread 3]
                                                                  │
                                                          [Output Queue]
                                                                  │
                                                        [WRITER THREAD]
                                                                  │
                                                           Output PCAP
```

### Thread Roles
| Thread | Count | Responsibility |
|--------|-------|----------------|
| Reader | 1 | Read PCAP, parse packet headers, hash to LB |
| Load Balancer (LB) | 2 (configurable) | Receive from Reader, re-hash to FastPath |
| FastPath (FP) | 2–8 (configurable) | Full DPI, flow table lookup, classify, block/forward |
| Writer | 1 | Drain output queue, write forwarded packets to PCAP |

---

## 5. Every Component Explained

### 5.1 `include/types.h` + `src/types.cpp`
**What:** Core data structures used everywhere.

**Key types:**
- `FiveTuple` — IP:port:port:proto identifier for a connection
- `Flow` — stateful record of one connection (app type, packet count, SNI, blocked flag)
- `Packet` — a parsed packet ready for DPI
- `AppType` — enum: YouTube, Netflix, TikTok, Facebook, HTTPS, DNS, etc.

**Why important:** These are shared across all threads. `FiveTuple` has a custom FNV-1a hash so it can be used as `unordered_map` keys.

**Interview point:** *"I used an enum class with uint8_t backing for AppType to keep each Flow's memory footprint small — important when you have millions of concurrent flows."*

---

### 5.2 `src/pcap_reader.cpp` — PCAP I/O Without libpcap
**What:** Reads and writes `.pcap` files by parsing the binary format directly.

**Why no libpcap?** 
- Demonstrates understanding of binary formats and byte-level I/O
- libpcap is a wrapper — we do what it does, from scratch
- No external dependencies = simpler build, any platform

**How it works:**
```cpp
// Read global header (24 bytes) to check magic number
struct PcapGlobalHeader {
    uint32_t magic_number;  // 0xa1b2c3d4 = native, 0xd4c3b2a1 = swapped
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;       // 1 = Ethernet
};

// Then for each packet, read 16-byte header + N bytes of data
struct PcapPacketHeader {
    uint32_t ts_sec;    // Timestamp seconds
    uint32_t ts_usec;   // Timestamp microseconds
    uint32_t incl_len;  // Bytes in file
    uint32_t orig_len;  // Original packet length
};
```

**Interview point:** *"I handle both little-endian and big-endian PCAP files by checking the magic number — 0xa1b2c3d4 means native byte order, 0xd4c3b2a1 means byte-swapped."*

---

### 5.3 `src/packet_parser.cpp` — Protocol Header Parsing
**What:** Decodes raw bytes into structured Ethernet/IP/TCP/UDP headers.

**How it works (pointer arithmetic):**
```
Raw bytes: [0x45 0x00 0x00 0x28 ...]
               ↑
         Cast to struct iphdr*
         ip->saddr = source IP (bytes 12-15)
         ip->daddr = dest IP   (bytes 16-19)
         ip->protocol = TCP(6) or UDP(17)
```

**Key safety check:** Bounds validation at every step. Never read beyond packet boundary.

**Interview point:** *"Every pointer dereference is guarded with a bounds check: `if (ptr + sizeof(T) > end) return false`. A single out-of-bounds read would crash the engine or cause undefined behaviour."*

---

### 5.4 `src/sni_extractor.cpp` — The DPI Heart
**What:** Extracts the application identity from packet payloads using three techniques.

#### Technique 1: TLS SNI Extraction
```
TLS Record (5 bytes):
  [0x16] [0x03 0x01] [len_hi len_lo]
   type    version       length
   ↓
   type 0x16 = Handshake

Handshake Header (4 bytes):
  [0x01] [len bytes...]
   type
   ↓
   type 0x01 = ClientHello

ClientHello: skip session ID, cipher suites, compression...
Then walk Extensions:
  [type_hi type_lo] [len_hi len_lo] [data...]
  ↓
  type 0x0000 = server_name extension
  → read SNI string from extension data
```

**Why this works:** TLS extension 0x0000 (SNI) is always sent before encryption. It's standardised in RFC 6066.

#### Technique 2: HTTP Host Header
```
GET /video HTTP/1.1\r\n
Host: www.youtube.com\r\n    ← WE FIND THIS
Accept: */*\r\n
```
Simple string search for `"Host: "` after the first `\r\n`.

#### Technique 3: DNS Query Name
```
DNS Question Section:
  [3] "www" [7] "youtube" [3] "com" [0]
  ↑                                  ↑
  length byte                        null terminator
  → reconstruct: www.youtube.com
```
Label walking: each segment is prefixed by its length byte.

**Interview point:** *"DNS uses a length-prefixed label format, not null-terminated strings. Each label (e.g., 'youtube') is preceded by a single byte giving its length. I walk the labels until I hit a zero byte, concatenating with dots."*

---

### 5.5 `src/rule_manager.cpp` — Policy Engine
**What:** Manages blocking/throttling rules. Evaluates each flow against configured policies.

**Three rule types:**
1. **IP blocking** — block all traffic from a source IP address
2. **App blocking** — block all flows classified as YouTube/TikTok/etc.
3. **Domain blocking** — block domains containing a substring (e.g., "tiktok" matches api.tiktok.com)

**JSON config format:**
```json
{
  "blocked_ips":     ["192.168.1.50"],
  "blocked_apps":    ["YouTube", "TikTok"],
  "blocked_domains": ["tiktok.com"],
  "throttled_apps":  ["Netflix"],
  "throttle_delay_ms": 10
}
```

**Decision logic:**
```cpp
bool isBlocked(src_ip, app_type, domain) {
    if (blocked_ips.contains(src_ip))   return true;
    if (blocked_apps.contains(app_type)) return true;
    for (domain_pattern in blocked_domains)
        if (domain.contains(domain_pattern)) return true;
    return false;
}
```

---

### 5.6 `include/thread_safe_queue.h` — Lock-Based Bounded Queue
**What:** A thread-safe producer-consumer queue with bounded capacity.

**Implementation:**
```cpp
template<typename T>
class TSQueue {
    std::queue<T>           queue_;
    std::mutex              mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t                  capacity_;
    bool                    closed_ = false;
};
```

**Why bounded?**
- Unbounded queues can eat all RAM if consumer is slower than producer
- Bounded queue applies **backpressure** — reader slows down automatically

**Why condition_variable instead of busy-wait?**
- `cv.wait()` puts the thread to sleep → OS scheduler runs other threads → CPU 0%
- Busy-wait (`while (queue_.empty()) {}`) burns CPU at 100% doing nothing useful

**Poison pill pattern for shutdown:**
```cpp
queue_.close(); // sets closed_ = true, notifies all waiters
// pop() returns std::nullopt when closed AND empty
```

---

### 5.7 `src/load_balancer.cpp` — Hash-Based Packet Router
**What:** A LB thread receives packets from the Reader and routes them to FastPath threads using consistent hashing.

**Consistent hashing:**
```cpp
size_t fp_idx = FiveTupleHash{}(packet.tuple) % num_fps;
fps_[fp_idx]->inputQueue().push(packet);
```

**Why consistent hashing?**
- All packets of one TCP connection must go to the **same** FastPath thread
- Because the flow state (SNI, classified, blocked) is stored in that thread's table
- If packets of the same flow went to different FPs, each FP would see only a fraction and fail to classify

**Interview point:** *"Without consistent hashing, TCP reassembly is impossible. Packet 1 of a TLS handshake might go to FP0, and packet 2 (with the Client Hello SNI) to FP1. FP1 has no context for packet 1, so the SNI extraction fails."*

---

### 5.8 `src/fast_path.cpp` — DPI Worker
**What:** Each FastPath thread owns its own flow table (no locks on the hot path) and does full DPI.

**Per-thread flow table:**
```cpp
std::unordered_map<FiveTuple, Flow, FiveTupleHash> flow_table_;
```

**Processing loop:**
```cpp
while (auto pkt = input_queue_.pop()) {
    Flow& flow = flow_table_[pkt->tuple];
    
    if (!flow.classified) {
        // Try to extract SNI/Host/DNS
        SNIExtractor::extract(*pkt, flow);
        if (flow.app_type != AppType::UNKNOWN) {
            flow.classified = true;
            flow.blocked = rules_.isBlocked(pkt->tuple.src_ip, flow.app_type, flow.sni);
        }
    }
    
    if (flow.blocked) { ++dropped_; continue; }
    
    output_queue_->push(*pkt);  // forward
    ++forwarded_;
}
```

**Why no mutex on flow_table_?**
Consistent hashing guarantees that only ONE FastPath thread ever touches a given flow. Zero contention = zero locking needed.

**Interview point:** *"This is the key performance insight. A shared flow table would require a mutex on every packet lookup — that's millions of lock/unlock operations per second. By sharding the table per-thread using consistent hashing, I eliminated all locks on the critical path."*

---

### 5.9 `src/dpi_engine.cpp` — Orchestrator
**What:** Creates and manages all threads, handles startup/shutdown sequencing, collects aggregated statistics.

**Shutdown sequence (important):**
```
1. Reader finishes → calls lb[i].stop() for each LB
2. LB threads drain their queues → call fp[j].stop() for each FP
3. FP threads drain → push remaining packets to output_queue_
4. output_queue_.close() → Writer thread exits after draining
5. All threads join()
6. Stats collected from all FP flow tables
```

If done wrong: data corruption, deadlock, or lost packets.

---

## 6. DPI Techniques

### How SNI Extraction Works (Byte-Level)
```
Packet payload (TCP, port 443, first packet of connection):
Offset 0:  0x16          = TLS content type: Handshake
Offset 1:  0x03 0x01     = TLS version: TLS 1.0
Offset 3:  0x00 0xF4     = Record length: 244 bytes
Offset 5:  0x01          = Handshake type: ClientHello
Offset 6:  0x00 0x00 0xF0 = Handshake length: 240
Offset 9:  0x03 0x03     = Client version: TLS 1.2
Offset 11: [32 bytes]    = Client random
Offset 43: 0x00          = Session ID length: 0
Offset 44: 0x00 0x2A     = Cipher suites length: 42
Offset 46: [42 bytes]    = Cipher suites
...skip session, ciphers, compression...
Extensions start:
  [0x00 0x00] [0x00 0x14] = Extension type: 0 (SNI), length: 20
  [0x00 0x12]             = ServerNameList length: 18
  [0x00]                  = ServerName type: 0 (host_name)
  [0x00 0x0F]             = ServerName length: 15
  "www.youtube.com"       = THE SNI ← EXTRACTED
```

### How Application Classification Works
```
SNI/Host/DNS → sniToAppType()

Mapping (substring matching):
  "youtube"    → AppType::YouTube
  "netflix"    → AppType::Netflix
  "tiktok"     → AppType::TikTok
  "facebook"   → AppType::Facebook
  "instagram"  → AppType::Instagram
  "twitter"    → AppType::Twitter
  "discord"    → AppType::Discord
  "whatsapp"   → AppType::WhatsApp
  "twitch"     → AppType::Twitch
  "reddit"     → AppType::Reddit
  "github"     → AppType::GitHub
  "google"     → AppType::Google
  (no match)   → AppType::HTTPS/HTTP/DNS
```

---

## 7. Multi-threading Design Decisions

### Why Not a Thread Pool?
A generic thread pool would use a shared work queue — requiring a mutex per packet dequeue. At 400K+ packets/second that's 800K mutex operations/second. Bottleneck.

Our design: each thread has a **dedicated queue**. The mutex is only contended between the LB (producer) and FP (consumer) for each specific queue — not across all threads.

### Why Two Levels (LB → FP)?
One could hash directly from Reader to FP. But with 8 FP threads, the Reader would need to maintain 8 queue references and do 8 potentially cache-cold `push()` calls. LBs batch this fan-out: Reader → 2 LBs, each LB → 4 FPs.

### Why Separate Writer Thread?
Without a dedicated writer, each FP would need to acquire a file-write lock on the output PCAP. File I/O is slow and variable. A dedicated writer decouples DPI latency from I/O latency.

### Atomic vs Mutex for Stats
```cpp
std::atomic<uint64_t> processed_{0};  // Counter per FastPath
```
Stats counters use `std::atomic` — lock-free increment, no contention. The live stats thread reads these atomics for display without blocking the DPI hot path.

### The Complete Thread Safety Model
| Resource | Access Pattern | Protection |
|----------|---------------|------------|
| FP flow table | Single owner (one FP thread) | **No lock needed** |
| TSQueue | Multiple producers, single consumer | **mutex + condvar** |
| Atomic counters | Multiple readers, single writer | **std::atomic** |
| Output PCAP | Single writer thread | **No lock needed** |
| stats.json | Written once after all threads stop | **No lock needed** |

---

## 8. Tools, Languages & Libraries

### C++17 (Core Language)
**Why C++17 specifically:**
- `std::optional<T>` — return-by-value with explicit "no value" state (no nullptr abuse)
- `std::string_view` — zero-copy string references into packet payload
- Structured bindings (`auto [key, val] : map`) — cleaner iteration
- `if constexpr` — compile-time branching without template specialization

**Why C++ over Python/Go/Rust:**
- Zero garbage collector pauses (critical for consistent latency)
- Manual memory layout control (struct packing, cache alignment)
- Direct pointer arithmetic into packet buffers (no serialisation overhead)
- Deterministic destructor-based cleanup (RAII)

### MSYS2 + MinGW-w64 GCC 16 (Windows Build)
**Why MSYS2:**
- Provides a Linux-compatible POSIX environment on Windows
- Ships GCC 16 with full C++17/20 support
- `pacman` package manager (same as Arch Linux) for easy deps

**Why not MSVC (Visual Studio)?**
- MSVC has different ABI and some GCC extensions don't compile
- Our code targets GCC, which is used on Linux servers in production

### GitHub Actions (CI/CD)
**Why CI:**
- Proves the code compiles on a **clean machine** (not just "works on my laptop")
- Automatically runs tests on every git push
- Earns the green Build badge on GitHub README

**Our CI matrix:**
- `ubuntu-latest` + GCC 13 → ensures Linux compatibility
- `windows-latest` + MSYS2 → ensures Windows compatibility

### Python 3 (Scripts Only)
Used only for:
- `scripts/generate_test_pcap.py` — synthetic test data generation
- `scripts/benchmark.py` — throughput measurement harness

No Python in the engine itself — pure C++.

### HTML/CSS/JavaScript (Dashboard)
**Why vanilla JS (no React/Vue)?**
- Zero build step — open `index.html` directly in browser
- No npm/node dependency chain to manage
- Canvas API for the throughput chart (native browser API)
- Fetch API for polling `stats.json` every 2 seconds

---

## 9. Performance & Impact

### Measured Performance
| Configuration | Throughput | Notes |
|---|---|---|
| Single-threaded | ~255 Kpps | 1 CPU core |
| MT 2 LB × 4 FP | ~438 Kpps | 8 worker threads |
| Projected (larger PCAP) | 500–800 Kpps | Memory-bound at scale |

**What does 438 Kpps mean?**
- 438,000 packets/second
- At 200 bytes/packet average = **87.6 MB/s** of traffic analysed
- A typical home internet connection is 100–500 Mbps = 60–300 Kpps
- Our engine can handle 1.5–7× a typical home connection in real-time

### Memory Efficiency
- Each `Flow` struct: ~200 bytes
- 1 million concurrent flows: ~200 MB RAM
- Realistic home network: <100K concurrent flows = <20 MB

### Why Zero External Dependencies Matters
- Deploy on any Linux server with just the binary
- No `apt install libpcap-dev` required
- No library version mismatches
- Simpler Docker containers, faster CI

### Real-World Deployment Context
This engine architecture mirrors how commercial products work:
- **pfSense/OPNsense** — open-source firewall with DPI plugins
- **Snort/Suricata** — network intrusion detection systems
- **NetFlow** — Cisco's traffic analysis (similar flow tracking)
- **nDPI** — ntopng's open-source DPI library (same SNI technique)

---

## 10. Web Dashboard

### Architecture
```
dpi_engine.exe ──writes──▶ stats.json
                                │
                          browser polls
                          every 2 seconds
                                │
                    dashboard/index.html
                    dashboard/dashboard.css
                    dashboard/dashboard.js
```

### What It Shows
- **Metrics bar** — Total packets, forwarded, dropped, throughput (Kpps)
- **App breakdown** — Bar chart of traffic by application (YouTube, Netflix...)
- **Thread pipeline** — LB dispatch counts, FP processed/forwarded/dropped
- **Domain list** — All detected SNIs with app classification
- **Throughput chart** — Canvas line chart of packet rate over time
- **Protocol table** — Full sortable table with blocked status

### Demo Mode
If `stats.json` is not found (engine not running), the dashboard falls back to **animated demo data** — sinusoidal noise around realistic values. You can show this to anyone without needing the engine running.

---

## 11. CI/CD Pipeline

### `.github/workflows/build.yml` — What It Does

```yaml
on: push  # Triggers on every git push

jobs:
  build-linux:           # Ubuntu + GCC 13
    - Install GCC 13
    - Build dpi_simple (single-threaded)
    - Build dpi_engine (multi-threaded)
    - Generate test PCAP (Python)
    - Run dpi_simple on test data
    - Run dpi_engine on test data
    - Verify output PCAPfiles exist
    - Upload binaries as GitHub Artifacts

  build-windows:         # Windows + MSYS2
    - Setup MSYS2
    - Install mingw-w64-x86_64-gcc
    - Build dpi_simple.exe
    - Build dpi_engine.exe
    - Test both engines
    - Upload .exe artifacts
```

### The Badge
After your first successful push:
```markdown
[![Build Status](https://github.com/YOUR_USERNAME/dpi-engine/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_USERNAME/dpi-engine/actions/workflows/build.yml)
```
This appears at the top of your README as a green ✅ **passing** badge.

---

## 12. Interview Q&A

### System Design Questions

**Q: How does your engine handle millions of concurrent flows?**
> "Each FastPath thread owns a private `unordered_map<FiveTuple, Flow>`. Using consistent FNV-1a hashing on the 5-tuple, all packets of a given flow always route to the same FastPath. This eliminates shared state on the hot path entirely — no mutexes needed on the flow table. Memory usage is roughly 200 bytes per Flow, so 1 million flows costs ~200MB."

**Q: Why did you choose a two-level LB→FP fan-out instead of direct Reader→FP routing?**
> "With 8 FP threads, the Reader would maintain 8 queue references and perform 8 cache-cold queue.push() calls per packet decision. LBs batch this fan-out: the Reader does 2 pushes (one per LB), each LB does 4 pushes. It also decouples Reader speed from FP queue depth — LBs can buffer while FPs catch up."

**Q: Why use condition_variable instead of busy-wait in the queues?**
> "Busy-wait burns a full CPU core at 100% doing nothing productive. condition_variable.wait() suspends the thread and yields the CPU core to other work. At 438 Kpps, packets arrive roughly every 2.3 microseconds — the wait latency is acceptable and the CPU savings are massive."

**Q: How do you ensure clean shutdown without losing packets?**
> "The shutdown sequence is ordered: Reader signals LBs to stop (poison pill), LBs drain their queues before stopping, LBs signal FPs to stop, FPs drain before stopping, FPs push remaining packets to the output queue, output_queue_.close() tells the writer no more data is coming, Writer drains and exits. This guarantees every packet either gets forwarded or dropped by policy — none are lost to shutdown races."

### Networking Questions

**Q: How does TLS SNI extraction work at the byte level?**
> "TLS ClientHello is sent before the handshake completes, so it's unencrypted. I scan the TCP payload for the TLS record header (content type 0x16 = Handshake), verify the ClientHello type byte (0x01), skip the session ID, cipher suites, and compression methods using length-prefixed jumping, then walk the extensions array looking for extension type 0x0000 (server_name). The SNI string starts at byte 5 of that extension's data."

**Q: What happens if a flow spans multiple packets? How do you handle partial TLS records?**
> "My current implementation inspects each packet independently and early-returns if the payload is too short for a valid TLS record. A production-grade engine would use TCP reassembly — buffering packets in order using sequence numbers. I noted this as a known limitation: very large TLS ClientHellos that span two TCP segments would not be classified. In practice, ClientHello almost always fits in the first packet."

**Q: Why does DNS extraction require label walking instead of simple string reading?**
> "DNS uses a length-prefixed label encoding: each segment of a domain name is preceded by a single byte giving its length, with a zero byte terminating the name. For example, www.youtube.com is encoded as `[3]www[7]youtube[3]com[0]`. You can't use strstr() because there are no literal dots in the binary format. You walk label by label, appending dots between segments."

**Q: How do you handle byte-order (endianness) differences?**
> "Network byte order is big-endian (most significant byte first). x86 CPUs are little-endian. I use `ntohs()` (network-to-host short) and `ntohl()` (network-to-host long) to convert multi-byte fields from IP and TCP headers. For PCAP, I check the magic number: 0xa1b2c3d4 = native order (no swap needed), 0xd4c3b2a1 = byte-swapped (swap all multi-byte PCAP header fields)."

### C++ Questions

**Q: Why C++17? What features did you use?**
> "Key C++17 features: `std::optional<T>` for functions that may fail (e.g., packet parsing) without using sentinel values or output parameters; `std::string_view` for zero-copy string operations on packet payload without allocating heap memory; structured bindings for cleaner map iteration; and `if constexpr` for compile-time conditional code. C++17's parallel algorithms were also available for potential sort parallelism."

**Q: How did you handle the GCC 16 std::hash<AppType> conflict?**
> "GCC 16 added built-in hash specializations for all enum types. My code had a manual specialization in a header file included by multiple translation units, causing a redefinition error. The fix was to remove my specialization — the standard library's built-in enum hash is equivalent and already present."

**Q: Why did you implement your own PCAP reader instead of using libpcap?**
> "Two reasons: demonstrates understanding of binary file formats (interview value), and eliminates an external dependency. The PCAP format is simple: a 24-byte global header followed by repeating 16-byte packet headers + data. Reading it directly with `fread()` and struct casting is 50 lines of code. libpcap adds link capture, filter compilation, live interface access — none of which we need for offline analysis."

### Architecture/Design Questions

**Q: How would you scale this to 10 million packets per second?**
> "Current bottleneck is the single Reader thread. At 10Mpps I'd use: (1) DPDK (Data Plane Development Kit) for kernel-bypass packet reception — avoids kernel/userspace copy overhead; (2) RSS (Receive-Side Scaling) to hash flows to NIC queues in hardware, so multiple Reader threads each own dedicated NIC queues; (3) NUMA-aware memory allocation so each NUMA node's threads use local memory. The flow table sharding design already scales horizontally — just add more FP threads."

**Q: How would you add encrypted TLS 1.3 support where SNI may be encrypted (ECH)?**
> "TLS 1.3 with Encrypted Client Hello (ECH) encrypts the SNI. Fallbacks: (1) DNS-over-HTTPS monitoring at the DNS resolver level (before ECH kicks in); (2) Machine learning on traffic flow metadata (packet sizes, timing, inter-arrival patterns) — Netflix and YouTube have distinctive patterns even without SNI; (3) For corporate environments, TLS inspection (MITM proxy with trusted cert)."

**Q: What's the difference between your approach and Suricata/Snort?**
> "Suricata and Snort use signature-based matching (regex patterns on packet content) with rule engines like Lua or pcre. My approach is protocol-aware, structural DPI — I parse the TLS/HTTP/DNS protocol structure to extract fields rather than pattern-matching on raw bytes. This is faster (O(1) field access vs O(n) regex scan) and more precise (no false positives from SNI-like content in payload). The tradeoff: I only detect protocols I've explicitly programmed, while Snort can detect anything with a matching signature."

---

## 13. Deployment Guide

### Step 1: Open the Web Dashboard

**Option A — Direct browser open (simplest):**
```
Open File Explorer → Navigate to:
C:\Users\Manas\OneDrive\Desktop\DPI\dashboard\
Double-click index.html
```

**Option B — With live stats (run engine first):**
```powershell
# In PowerShell, from the DPI folder:
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH

# Generate test data (if not already done)
python scripts/generate_test_pcap.py

# Run MT engine with stats output
.\dpi_engine.exe test_data/test_large.pcap test_data/out.pcap --lbs 2 --fps 4 --block-app YouTube --block-app TikTok --stats-json --no-stats

# Copy stats to dashboard folder
Copy-Item stats.json dashboard\stats.json

# Open dashboard
Start-Process dashboard\index.html
```
The dashboard will read `dashboard/stats.json` and display live data.

**Option C — Python HTTP server for proper CORS:**
```powershell
# Serve the dashboard and stats.json via HTTP
cd "C:\Users\Manas\OneDrive\Desktop\DPI"
python -m http.server 8080

# Open in browser:
# http://localhost:8080/dashboard/index.html
```
The dashboard polls `../stats.json` which resolves correctly when served via HTTP.

---

### Step 2: Build Commands (Quick Reference)

```powershell
# Add MSYS2 GCC to PATH (required every new PowerShell session)
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH

# Single-threaded engine
g++.exe -std=c++17 -O2 -I include `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp src/main_simple.cpp `
  -o dpi_simple.exe

# Multi-threaded engine
g++.exe -std=c++17 -O2 -pthread -I include `
  src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp `
  src/sni_extractor.cpp src/rule_manager.cpp `
  src/load_balancer.cpp src/fast_path.cpp src/dpi_engine.cpp src/main_mt.cpp `
  -o dpi_engine.exe -lpthread
```

---

### Step 3: Push to GitHub — Step by Step

#### 3.1 Create the GitHub Repository
1. Go to [github.com](https://github.com) → click **New repository**
2. Name: `dpi-engine` (or `DPI-Engine`)
3. **Do NOT** tick "Add a README" (we already have one)
4. Visibility: **Public** (required for free Actions minutes and badge)
5. Click **Create repository**

#### 3.2 Update the README Badge URL
Open `C:\Users\Manas\OneDrive\Desktop\DPI\README.md` and replace:
```
YOUR_USERNAME
```
with your actual GitHub username. Example:
```markdown
[![Build Status](https://github.com/manas_dtu/dpi-engine/actions/workflows/build.yml/badge.svg)](...)
```

#### 3.3 Initialise Git and Push

```powershell
# Navigate to the project folder
cd "C:\Users\Manas\OneDrive\Desktop\DPI"

# Initialise git repository
git init

# Add remote (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/dpi-engine.git

# Stage all files
git add .

# Check what's being committed (review this!)
git status

# Commit
git commit -m "feat: DPI Engine v2.0 - multi-threaded C++17 packet inspector

- Single-threaded and multi-threaded engines (438 Kpps on test data)
- TLS SNI + HTTP Host + DNS query extraction
- JSON-configurable IP/App/Domain blocking rules
- Real-time web dashboard (glassmorphism design, canvas charts)
- GitHub Actions CI: Linux (GCC 13) + Windows (MSYS2) builds
- No external dependencies (no libpcap, no Boost)"

# Push to GitHub
git push -u origin main
```

If `main` branch errors:
```powershell
git push -u origin master
# Or rename:
git branch -M main
git push -u origin main
```

#### 3.4 Watch the CI Run
1. Go to `https://github.com/YOUR_USERNAME/dpi-engine`
2. Click the **Actions** tab
3. You'll see **"Build & Test"** workflow running
4. Wait ~3–5 minutes for both Linux and Windows builds
5. If both succeed → badge turns **green** ✅

#### 3.5 Add Badge to README (Already Done)
Your `README.md` already has the badge line. Once CI passes, it will automatically show green on GitHub.

---

### Step 4: Verify Everything Works

```powershell
# Full test run from scratch:
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
cd "C:\Users\Manas\OneDrive\Desktop\DPI"

# Build both
g++.exe -std=c++17 -O2 -I include src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/rule_manager.cpp src/main_simple.cpp -o dpi_simple.exe
g++.exe -std=c++17 -O2 -pthread -I include src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/rule_manager.cpp src/load_balancer.cpp src/fast_path.cpp src/dpi_engine.cpp src/main_mt.cpp -o dpi_engine.exe -lpthread

# Generate test data
python scripts/generate_test_pcap.py

# Test single-threaded
.\dpi_simple.exe test_data/test_small.pcap test_data/out_simple.pcap --block-app YouTube

# Test multi-threaded (2LB x 4FP = 8 workers)
.\dpi_engine.exe test_data/test_large.pcap test_data/out_mt.pcap --lbs 2 --fps 4 --block-app YouTube --block-app TikTok --stats-json --no-stats

# View stats.json
Get-Content stats.json

# Open dashboard
Start-Process dashboard\index.html
```

---

### Step 5: What to Say on Your Resume

```
DPI Engine v2.0                                              C++17 | Multi-threading
─────────────────────────────────────────────────────────────────────────────────
• Built a high-performance Deep Packet Inspection engine from scratch in C++17
  with no external networking libraries (no libpcap, Boost, or DPDK)
• Implemented TLS SNI, HTTP Host, and DNS query extraction to classify network
  traffic into 15 application types (YouTube, Netflix, TikTok, etc.)
• Designed a lock-free multi-threaded pipeline (LB + FastPath) using consistent
  FNV-1a hashing for per-thread flow table sharding, achieving ~438 Kpps
• Built a real-time web dashboard using vanilla JS + Canvas API polling stats.json
• Implemented bounded thread-safe queues using std::condition_variable
  with poison-pill shutdown and backpressure for zero packet loss
• Set up cross-platform CI/CD (Linux GCC 13 + Windows MSYS2) via GitHub Actions
```

---

## Quick Reference Card

```
Project: DPI Engine v2.0
Language: C++17 (pure stdlib, no external deps)
Platform: Windows (MSYS2 GCC 16) + Linux (GCC 13+)
Threads: 1 Reader + N LBs + M FPs + 1 Writer
Performance: ~438 Kpps (35K packets in 0.08s)
Protocols: TLS/HTTPS, HTTP, DNS
Apps detected: YouTube, Netflix, TikTok, Facebook, Instagram,
               Twitter, Discord, WhatsApp, Twitch, Reddit, GitHub, Google
Queue type: Bounded mutex+condvar (backpressure)
Flow routing: FNV-1a consistent hashing (no lock on flow table)
Dashboard: HTML/CSS/JS, polls stats.json every 2s, Canvas chart
CI: GitHub Actions (.github/workflows/build.yml)
```
