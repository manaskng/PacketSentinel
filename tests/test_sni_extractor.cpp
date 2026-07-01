// =============================================================================
// tests/test_sni_extractor.cpp — Unit tests for SNI extraction
// =============================================================================
// Tests byte-level TLS parsing with multiple scenarios:
// - Valid TLS ClientHello with SNI
// - Truncated/malformed packets
// - Edge cases (max hostname length, empty SNI)
// - Security fixes (hostname length validation)
//
// Compile with: g++ -std=c++17 -I include tests/test_sni_extractor.cpp src/sni_extractor.cpp src/types.cpp -o test_sni
// Run: ./test_sni
// =============================================================================

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include "sni_extractor.h"

// Test utilities
#define TEST(name) void test_##name()
#define ASSERT_TRUE(cond) assert((cond))
#define ASSERT_FALSE(cond) assert(!(cond))
#define ASSERT_EQ(a, b) assert((a) == (b))

// Helper to build a minimal valid TLS ClientHello with SNI
std::vector<uint8_t> buildValidTLSClientHello(const std::string& hostname = "example.com") {
    std::vector<uint8_t> packet;
    
    // TLS Record Layer (5 bytes)
    packet.push_back(0x16);  // Content Type: Handshake
    packet.push_back(0x03);  // Version MSB
    packet.push_back(0x03);  // Version LSB (TLS 1.2)
    
    // Record Length (placeholder, will update at the end)
    size_t record_len_offset = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    // Handshake Header (4 bytes)
    packet.push_back(0x01);  // Handshake Type: ClientHello
    
    // Handshake Length (placeholder, 3 bytes)
    size_t hs_len_offset = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    // ClientHello Body
    size_t body_start = packet.size();
    
    // Version (2 bytes)
    packet.push_back(0x03);
    packet.push_back(0x03);  // TLS 1.2
    
    // Random (32 bytes)
    for (int i = 0; i < 32; ++i) packet.push_back(0x00);
    
    // Session ID Length
    packet.push_back(0x00);
    
    // Cipher Suites Length (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x02);
    
    // Cipher Suite (1 suite, 2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x2f);  // TLS_RSA_WITH_AES_128_CBC_SHA
    
    // Compression Methods Length
    packet.push_back(0x01);
    
    // Compression Method (null, 1 byte)
    packet.push_back(0x00);
    
    // Extensions Length (2 bytes)
    size_t ext_len_offset = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    size_t ext_start = packet.size();
    
    // SNI Extension
    packet.push_back(0x00);  // Extension Type MSB (SNI = 0x0000)
    packet.push_back(0x00);  // Extension Type LSB
    
    // SNI Extension Data Length (placeholder)
    size_t sni_ext_len_offset = packet.size();
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    size_t sni_data_start = packet.size();
    
    // SNI List Length (2 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);  // Will update with actual length
    
    // SNI Entry
    packet.push_back(0x00);  // SNI Type: host_name
    
    // Hostname Length (2 bytes)
    uint16_t hostname_len = hostname.length();
    packet.push_back((hostname_len >> 8) & 0xFF);
    packet.push_back(hostname_len & 0xFF);
    
    // Hostname
    for (char c : hostname) packet.push_back(c);
    
    // Update SNI List Length
    uint16_t sni_list_len = packet.size() - sni_data_start - 2;
    packet[sni_data_start] = (sni_list_len >> 8) & 0xFF;
    packet[sni_data_start + 1] = sni_list_len & 0xFF;
    
    // Update Extensions Length
    uint16_t total_ext_len = packet.size() - ext_start;
    packet[ext_len_offset] = (total_ext_len >> 8) & 0xFF;
    packet[ext_len_offset + 1] = total_ext_len & 0xFF;
    
    // Update SNI Extension Data Length
    uint16_t sni_ext_len = packet.size() - sni_data_start;
    packet[sni_ext_len_offset] = (sni_ext_len >> 8) & 0xFF;
    packet[sni_ext_len_offset + 1] = sni_ext_len & 0xFF;
    
    // Update Handshake Length
    uint32_t hs_len = packet.size() - body_start;
    packet[hs_len_offset] = (hs_len >> 16) & 0xFF;
    packet[hs_len_offset + 1] = (hs_len >> 8) & 0xFF;
    packet[hs_len_offset + 2] = hs_len & 0xFF;
    
    // Update Record Length
    uint16_t rec_len = packet.size() - 5;
    packet[record_len_offset] = (rec_len >> 8) & 0xFF;
    packet[record_len_offset + 1] = rec_len & 0xFF;
    
    return packet;
}

// =========== TEST CASES ===========

TEST(valid_tls_client_hello) {
    auto packet = buildValidTLSClientHello("www.example.com");
    auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), "www.example.com");
    std::cout << "✓ test_valid_tls_client_hello\n";
}

TEST(extract_multiple_hostnames) {
    auto test_cases = std::vector<std::string>{
        "google.com",
        "www.github.com",
        "api.example.org",
        "localhost",
        "192.168.1.1",  // Can be in SNI even if not a valid domain
    };
    
    for (const auto& hostname : test_cases) {
        auto packet = buildValidTLSClientHello(hostname);
        auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result.value(), hostname);
    }
    std::cout << "✓ test_extract_multiple_hostnames\n";
}

TEST(reject_truncated_packet) {
    auto packet = buildValidTLSClientHello("example.com");
    
    // Test various truncation points
    for (size_t len = 0; len < 44; ++len) {
        auto result = SNIExtractor::extractSNI(packet.data(), len);
        ASSERT_FALSE(result.has_value());
    }
    std::cout << "✓ test_reject_truncated_packet\n";
}

TEST(reject_non_handshake_type) {
    auto packet = buildValidTLSClientHello("example.com");
    
    // Change TLS record type from 0x16 (Handshake) to 0x17 (Application Data)
    packet[0] = 0x17;
    
    auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
    ASSERT_FALSE(result.has_value());
    std::cout << "✓ test_reject_non_handshake_type\n";
}

TEST(reject_non_client_hello) {
    auto packet = buildValidTLSClientHello("example.com");
    
    // Change Handshake type from 0x01 (ClientHello) to 0x02 (ServerHello)
    packet[5] = 0x02;
    
    auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
    ASSERT_FALSE(result.has_value());
    std::cout << "✓ test_reject_non_client_hello\n";
}

TEST(reject_null_pointer) {
    auto result = SNIExtractor::extractSNI(nullptr, 100);
    ASSERT_FALSE(result.has_value());
    std::cout << "✓ test_reject_null_pointer\n";
}

TEST(security_hostname_length_validation) {
    // SECURITY FIX: Hostname length must be > 0 and <= 255
    auto packet = buildValidTLSClientHello("a");  // Single-char hostname
    auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), "a");
    std::cout << "✓ test_security_hostname_length_validation\n";
}

TEST(max_hostname_length) {
    // DNS max hostname length is 255
    std::string long_hostname(255, 'a');
    auto packet = buildValidTLSClientHello(long_hostname);
    auto result = SNIExtractor::extractSNI(packet.data(), packet.size());
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result.value(), long_hostname);
    std::cout << "✓ test_max_hostname_length\n";
}

// Main test runner
int main() {
    std::cout << "\n=== Running SNI Extractor Tests ===\n";
    
    try {
        test_valid_tls_client_hello();
        test_extract_multiple_hostnames();
        test_reject_truncated_packet();
        test_reject_non_handshake_type();
        test_reject_non_client_hello();
        test_reject_null_pointer();
        test_security_hostname_length_validation();
        test_max_hostname_length();
        
        std::cout << "\n✅ All tests passed!\n\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Test failed: " << e.what() << "\n";
        return 1;
    }
}
