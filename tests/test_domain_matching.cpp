// =============================================================================
// tests/test_domain_matching.cpp — Unit tests for domain suffix matching
// =============================================================================
// Tests domain blocking rules with proper suffix matching to prevent bypasses.
// SECURITY FIX: Tests that "tiktok.com.attacker.com" does NOT match rule "tiktok.com"
//
// Compile with: g++ -std=c++17 -I include tests/test_domain_matching.cpp src/rule_manager.cpp src/types.cpp -o test_domain
// Run: ./test_domain
// =============================================================================

#include <iostream>
#include <cassert>
#include "rule_manager.h"

#define TEST(name) void test_##name()
#define ASSERT_TRUE(cond) assert((cond))
#define ASSERT_FALSE(cond) assert(!(cond))

TEST(exact_match) {
    RuleManager rm;
    rm.addBlockedDomain("tiktok.com");
    
    // Exact match should block
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "tiktok.com"));
    std::cout << "✓ test_exact_match\n";
}

TEST(subdomain_match) {
    RuleManager rm;
    rm.addBlockedDomain("tiktok.com");
    
    // Subdomains should block
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "www.tiktok.com"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "api.tiktok.com"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "m.tiktok.com"));
    std::cout << "✓ test_subdomain_match\n";
}

TEST(security_no_suffix_bypass) {
    // SECURITY FIX: This is the main bypass prevention test
    RuleManager rm;
    rm.addBlockedDomain("tiktok.com");
    
    // These should NOT block (attacker domain has tiktok.com as substring)
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, "tiktok.com.attacker.com"));
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, "fake-tiktok.com"));
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, "my-tiktok.com.net"));
    std::cout << "✓ test_security_no_suffix_bypass\n";
}

TEST(case_insensitive_matching) {
    RuleManager rm;
    rm.addBlockedDomain("tiktok.com");
    
    // Case variations should match
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "TikTok.com"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "WWW.TIKTOK.COM"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "WwW.TiKtOk.CoM"));
    std::cout << "✓ test_case_insensitive_matching\n";
}

TEST(multiple_rules) {
    RuleManager rm;
    rm.addBlockedDomain("youtube.com");
    rm.addBlockedDomain("netflix.com");
    rm.addBlockedDomain("tiktok.com");
    
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "www.youtube.com"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "api.netflix.com"));
    ASSERT_TRUE(rm.isBlocked(0, AppType::UNKNOWN, "m.tiktok.com"));
    
    // Non-matching should not block
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, "www.google.com"));
    std::cout << "✓ test_multiple_rules\n";
}

TEST(empty_domain) {
    RuleManager rm;
    rm.addBlockedDomain("example.com");
    
    // Empty SNI should not match
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, ""));
    std::cout << "✓ test_empty_domain\n";
}

TEST(ip_blocking_independent) {
    RuleManager rm;
    rm.addBlockedIP("192.168.1.100");
    rm.addBlockedDomain("evil.com");
    
    // IP block should work independently
    ASSERT_TRUE(rm.isBlocked(0xC0A80164, AppType::UNKNOWN, "good.com"));
    
    // Domain block should work independently
    ASSERT_TRUE(rm.isBlocked(0x01020304, AppType::UNKNOWN, "evil.com"));
    std::cout << "✓ test_ip_blocking_independent\n";
}

TEST(app_blocking_independent) {
    RuleManager rm;
    rm.addBlockedApp("YouTube");
    
    // Should block YouTube even with no domain
    ASSERT_TRUE(rm.isBlocked(0, AppType::YOUTUBE, ""));
    
    // Should not block unknown app
    ASSERT_FALSE(rm.isBlocked(0, AppType::UNKNOWN, ""));
    std::cout << "✓ test_app_blocking_independent\n";
}

// Main test runner
int main() {
    std::cout << "\n=== Running Domain Matching Tests ===\n";
    
    try {
        test_exact_match();
        test_subdomain_match();
        test_security_no_suffix_bypass();
        test_case_insensitive_matching();
        test_multiple_rules();
        test_empty_domain();
        test_ip_blocking_independent();
        test_app_blocking_independent();
        
        std::cout << "\n✅ All domain matching tests passed!\n\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Test failed: " << e.what() << "\n";
        return 1;
    }
}
