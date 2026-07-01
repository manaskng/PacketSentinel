# Contributing Guide

Thank you for interest in PacketSentinel! This guide helps you contribute effectively.

---

## Development Setup

### Prerequisites

- **Compiler**: GCC 13+ (Linux) or Clang 5+
  - ⚠️ Windows MSYS2: Requires updated MinGW-w64 (not GCC 6.3.0)
- **Language**: C++17
- **Build**: GNU Make or MSYS2 mingw32-make
- **Python**: 3.7+ (for test data generation, optional)

### Linux Setup

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential g++-13 make

# Clone and build
git clone https://github.com/manaskng/PacketSentinel.git
cd PacketSentinel
make all

# Run tests
make test_all
```

### Windows Setup (MSYS2)

```bash
# Install MSYS2: https://www.msys2.org/

# Update MinGW-w64 GCC to latest (not 6.3.0)
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make

# Clone and build
git clone https://github.com/manaskng/PacketSentinel.git
cd PacketSentinel
mingw32-make all
```

---

## Code Style

### Naming Conventions

- **Variables**: `snake_case` (e.g., `packet_count`)
- **Functions**: `camelCase` (e.g., `extractSNI()`)
- **Classes**: `PascalCase` (e.g., `FastPath`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_FLOWS`)
- **File names**: `snake_case.cpp/h` (e.g., `fast_path.cpp`)

### Comments

Write comments for **why**, not **what**. Code should be self-documenting.

**Bad**:
```cpp
// Increment counter
++packet_count;
```

**Good**:
```cpp
// Count this packet toward flow's byte count for anomaly scoring
++flow.packet_count;
```

**Exceptional cases** (comment anyway):
```cpp
// Hot path optimization: Welford's online variance avoids O(n) vector allocation
double delta = size - flow.pkt_size_mean;
flow.pkt_size_mean += delta / flow.packet_count;
```

### Error Handling

- Use `std::optional<>` for functions that may fail (prefer over exceptions on hot paths)
- Use exceptions only off hot paths (startup, shutdown, config loading)
- Always validate input bounds before dereferencing pointers

**Example**:
```cpp
// Good: explicit error return
std::optional<std::string> extractSNI(const uint8_t* payload, size_t length) {
    if (payload == nullptr || length < 44) return std::nullopt;
    // ... parsing ...
    return std::nullopt;  // Explicit failure
}

// Bad: returns garbage on failure
std::string extractSNI_bad(const uint8_t* payload, size_t length) {
    // If fails, returns uninitialized string — undefined behavior!
}
```

---

## Security First

### Threat Model

All input is **untrusted**. Assume adversaries will send:
- Truncated packets
- Malformed headers
- Oversized fields
- Out-of-spec data

### Validation Rules

1. **Bounds checking**: Always check before reading
   ```cpp
   if (offset + sizeof(field) > buffer_size) return error;
   uint16_t field = readU16BE(buffer + offset);
   ```

2. **No unchecked casts**
   ```cpp
   // Good: explicit with bounds
   if (sni_name_len > 255) return std::nullopt;
   
   // Bad: unchecked cast could overflow
   size_t len = (size_t)untrusted_u16;  // Could be 65535
   ```

3. **Fixed-size loops**
   ```cpp
   // Good: bounded loop
   for (int i = 0; i < 256; ++i) {  // Fixed bound
       // ...
   }
   
   // Bad: unbounded growth
   for (int i = 0; i < data_size; ++i) {  // Attacker controls data_size!
   ```

---

## Testing Requirements

### Unit Tests

Every new function must have unit tests.

Example template:
```cpp
#define TEST(name) void test_##name()

TEST(my_new_function_valid_input) {
    auto result = myNewFunction(valid_input);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), expected_value);
    std::cout << "✓ test_my_new_function_valid_input\n";
}

TEST(my_new_function_invalid_input) {
    auto result = myNewFunction(invalid_input);
    ASSERT_FALSE(result.has_value());
    std::cout << "✓ test_my_new_function_invalid_input\n";
}
```

Run tests:
```bash
make test_all
```

### Regression Tests

If you fix a bug, add a test case that would have caught it.

**Example**: Domain matching bypass was fixed by adding:
```cpp
TEST(security_no_suffix_bypass) {
    RuleManager rm;
    rm.addBlockedDomain("tiktok.com");
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, "tiktok.com.attacker.com"));
}
```

---

## Submitting Changes

### Workflow

1. **Fork** the repository on GitHub
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Implement** changes with tests
4. **Verify** all tests pass: `make test_all`
5. **Commit** with clear messages: `git commit -m "Fix domain matching bypass"`
6. **Push** to your fork: `git push origin feature/my-feature`
7. **Open** a Pull Request with description

### Commit Messages

Follow conventional commits:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `fix`, `feat`, `docs`, `test`, `refactor`, `perf`, `security`

**Examples**:
```
fix(rule_manager): prevent domain suffix bypass

Changed naive substring matching to proper DNS suffix
matching. Prevents "tiktok.com.attacker.com" from
matching rule "tiktok.com".

Fixes #15
```

```
feat(fast_path): add LRU flow table eviction

Implemented LRUFlowTable with configurable max_flows
to prevent unbounded memory growth under DoS attack.
Caps memory usage at 100K flows × 500B = ~50MB.

Closes #12
```

### PR Description Template

```markdown
## Description
Brief explanation of what changed and why.

## Testing
- [ ] Unit tests added
- [ ] Integration tests pass
- [ ] No performance regression
- [ ] Compiled on both Linux and Windows

## Security Considerations
- [ ] Input validation checks added
- [ ] Bounds checking on all pointer operations
- [ ] No new unchecked casts or assumptions

## Documentation
- [ ] Code comments added for complex logic
- [ ] README/DOCUMENTATION updated if needed
- [ ] CHANGELOG.md entry added
```

---

## Performance Guidelines

### Hot Path Optimization

Code in `FastPath::processPacket()` is called millions of times per second.

✅ **Do**:
- Use stack allocation (fast)
- Inline small functions (`constexpr`)
- Avoid lock operations (per-thread state)
- Early exit on conditions
- Pre-allocate buffers

❌ **Don't**:
- Allocate on heap in hot path
- Use `std::vector` or `std::string` construction
- Call virtual functions (multiple indirections)
- Take locks (causes contention)
- Log or print (I/O is slow)

### Benchmarking

Before/after performance:
```bash
make benchmark  # Baseline
# ... make changes ...
make benchmark  # Compare
```

Target: No regression > 5% on throughput.

---

## Security Disclosure

Found a security vulnerability?

**Do NOT** open a public GitHub issue.

Instead:
1. Email: security@packsentinel.dev (or create private security advisory on GitHub)
2. Include: vulnerability description, reproduction steps, impact
3. Allow 90 days for patch before public disclosure

---

## Questions?

- **Documentation**: Read DOCUMENTATION.md, SECURITY.md, DEPLOYMENT.md
- **Issues**: Check open issues first, then create new one
- **Discussions**: Use GitHub Discussions for design questions
- **Chat**: (No Discord/Slack yet — PR welcome!)

---

## Resources

- [RFC 5246 — TLS 1.2 Protocol](https://tools.ietf.org/html/rfc5246)
- [RFC 1035 — Domain Names](https://tools.ietf.org/html/rfc1035)
- [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) (reference only)
- [CWE Top 25](https://cwe.mitre.org/top25/) (security awareness)

---

**Thank you for contributing! 🎉**
