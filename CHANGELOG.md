# CHANGELOG

All notable changes to this project will be documented in this file.

## [1.1.0] — Security & Hardening Release (2025-01-10)

### 🔒 Security Fixes

#### Critical
- **LRU Flow Table Eviction** (#12): Prevents unbounded memory growth DoS attack
  - Implemented `LRUFlowTable` class with configurable max_flows (default 100K per FastPath)
  - Least-recently-used entries evicted when table reaches capacity
  - Bounds memory usage to O(max_flows) regardless of incoming flow count
  - Impact: Prevents attacker from exhausting memory by sending packets from 1M+ IPs

- **Domain Suffix Matching Bypass Fix** (#15): Closes security bypass in rule enforcement
  - Changed naive substring matching (`sni.find(rule)`) to proper suffix matching
  - Now correctly rejects "tiktok.com.attacker.com" when rule is "tiktok.com"
  - Impact: Prevents rule evasion via domain masquerading

- **SNI Hostname Length Validation** (#14): Hardens TLS packet parsing
  - Added DNS-spec bounds: min=1 byte, max=255 bytes (RFC 1035)
  - Prevents potential overflow if malformed TLS packet specifies unreasonable hostname_len
  - Impact: Reduces attack surface for crafted TLS packets

### 🧪 Testing

- **Unit Tests** (NEW):
  - `tests/test_sni_extractor.cpp`: 8 test cases for TLS SNI extraction
    - Valid ClientHello extraction
    - Truncated packet rejection
    - Hostname length validation (1–255 bytes)
    - Null pointer handling
  - `tests/test_domain_matching.cpp`: 8 test cases for rule matching
    - Exact domain matching
    - Subdomain matching ("www.example.com" matches "example.com")
    - Security bypass prevention (core regression test)
    - Case-insensitive matching
    - Multiple concurrent rules

- **Makefile Targets** (NEW):
  - `make test_sni`: Compile & run SNI extraction unit tests
  - `make test_domain`: Compile & run domain matching unit tests  
  - `make test_all`: Run all tests (integration + unit)

### 📚 Documentation

- **SECURITY.md** (NEW): Comprehensive security audit document
  - Detailed vulnerability descriptions (CVSS scores, CWE references)
  - Root cause analysis with code examples (before/after)
  - Threat model and known limitations
  - Security best practices for deployment
  - Incident response procedures
  
- **DEPLOYMENT.md** (NEW): Production deployment guide
  - Phase 1: Edge device installation (systemd service)
  - Phase 2: Docker containerization (Dockerfile + docker-compose)
  - Phase 3: Kubernetes deployment (StatefulSet + ConfigMap)
  - Scaling recommendations (2–16+ cores)
  - Monitoring & alerting setup (Prometheus metrics)
  - Troubleshooting guide

- **README.md** (UPDATED):
  - Added v1.1 security release badge
  - New "Security & Improvements (v1.1)" section
  - Test running instructions
  - Version badge

### 🏗️ Architecture Changes

- **FastPath.h/.cpp**: Updated to use `LRUFlowTable` instead of unbounded `unordered_map`
  - Constructor now accepts optional `max_flows` parameter (default 100000)
  - New `evictions()` stat exposed for monitoring
  - New `exportFlows()` method for stats collection

- **LRUFlowTable.h** (NEW): Production-ready LRU cache implementation
  - O(1) getOrCreate() with eviction
  - `std::list` for LRU ordering + `unordered_map` for fast lookup
  - No external dependencies
  - Comprehensive inline documentation

- **RuleManager.cpp**: Added `domainMatches()` helper function
  - Proper DNS suffix matching logic
  - Inline documentation of matching rules

### ⚠️ Known Issues

- Unit tests require C++17 compiler (GCC 13+, Clang 5+)
  - MSYS2 GCC 6.3.0 is too old; use updated MinGW-w64 or Linux GCC 13
  - GitHub Actions CI uses Ubuntu + GCC 13 (compatible)

### 🔄 Breaking Changes

None. API and CLI arguments remain fully backward-compatible.

### 📈 Performance Impact

- LRU eviction: <1µs overhead (amortized O(1) on hot path)
- Domain matching: ~5% slower on large rule sets due to suffix checking
- Memory: Bounded at max_flows × sizeof(Flow) = ~100K flows × ~500 bytes = ~50MB

### 🎯 Next Steps (v1.2)

- [ ] IPv6 support (extend FiveTuple to handle 128-bit addresses)
- [ ] REST API for stats & rule updates
- [ ] Hot-reload rules without restart (--reload-rules via SIGHUP)
- [ ] Prometheus metrics export
- [ ] Live packet capture mode (--interface eth0)
- [ ] Structured JSON logging

---

## [1.0.0] — Initial Release (2024-12-20)

### ✨ Features

- Multi-threaded DPI pipeline (Load Balancers + FastPaths)
- TLS SNI extraction from ClientHello
- HTTP Host header extraction
- DNS query name extraction
- Layer 7 application classification (15+ apps)
- Real-time anomaly detection (entropy, variance, flag analysis)
- Traffic rule engine (IP/app/domain blocking + throttling)
- Web dashboard with live stats
- Single-threaded and multi-threaded binaries
- Cross-platform (Windows + Linux)
- Zero external dependencies

### 📊 Performance

- 438,000 packets/sec (multi-threaded, 4 cores)
- 255,000 packets/sec (single-threaded)
- 80–400× faster than Python + Scapy

### 📝 Documentation

- README.md (overview, features, usage)
- DOCUMENTATION.md (deep technical dive)
- Inline code documentation (RFC references, design decisions)
- Runnable examples and benchmarks

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- MAJOR: Incompatible API changes
- MINOR: New features (backward-compatible)
- PATCH: Bug fixes (backward-compatible)

**Current:** v1.1.0
