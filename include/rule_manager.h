#pragma once
// =============================================================================
// rule_manager.h — Blocking and throttling rule engine
// =============================================================================
// Manages three types of blocking rules:
//   1. IP blacklist    — block all traffic from a source IP
//   2. App blacklist   — block all traffic of a specific app type
//   3. Domain blacklist — block connections whose SNI matches a substring
// Plus one throttling rule set:
//   4. App throttle list — delay (not drop) traffic of a specific app
//
// Thread safety: RuleManager is read-only after initialization.
// Multiple FastPath threads can call isBlocked() concurrently without locks.
// =============================================================================

#ifndef DPI_RULE_MANAGER_H
#define DPI_RULE_MANAGER_H

#include "types.h"
#include <unordered_set>
#include <vector>
#include <string>
#include <chrono>

class RuleManager {
public:
    RuleManager() = default;

    // ---- Rule loading -------------------------------------------------------

    // Load rules from a JSON file (rules.json format).
    // Returns true on success. On failure, prints error and returns false.
    bool loadFromJSON(const std::string& filename);

    // Add individual rules (used by CLI argument parsing)
    void addBlockedIP(const std::string& ip_str);
    void addBlockedIP(uint32_t ip);
    void addBlockedApp(const std::string& app_name);
    void addBlockedApp(AppType app);
    void addBlockedDomain(const std::string& domain_substr);
    void addThrottledApp(const std::string& app_name);
    void addThrottledApp(AppType app);

    // ---- Rule evaluation ----------------------------------------------------

    // Returns true if the packet/flow should be dropped.
    // Checks: IP blacklist → App blacklist → Domain substring
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const;

    // Returns true if the flow should be delayed (soft throttling)
    bool isThrottled(AppType app) const;

    // ---- Configuration ------------------------------------------------------

    // Per-packet throttle delay (default 10ms — simulates ISP throttling)
    std::chrono::milliseconds throttleDelay() const { return throttle_delay_ms_; }
    void setThrottleDelay(std::chrono::milliseconds ms) { throttle_delay_ms_ = ms; }

    // ---- Inspection ---------------------------------------------------------
    bool hasAnyRules() const {
        return !blocked_ips_.empty()     ||
               !blocked_apps_.empty()    ||
               !blocked_domains_.empty() ||
               !throttled_apps_.empty();
    }

    // Print all active rules to stdout
    void printRules() const;

    // Getters for reporting
    const std::unordered_set<uint32_t>&  blockedIPs()      const { return blocked_ips_; }
    const std::unordered_set<AppType>&   blockedApps()     const { return blocked_apps_; }
    const std::vector<std::string>&      blockedDomains()  const { return blocked_domains_; }
    const std::unordered_set<AppType>&   throttledApps()   const { return throttled_apps_; }

private:
    std::unordered_set<uint32_t>  blocked_ips_;
    std::unordered_set<AppType>   blocked_apps_;
    std::vector<std::string>      blocked_domains_;   // substring match
    std::unordered_set<AppType>   throttled_apps_;

    std::chrono::milliseconds throttle_delay_ms_{10};

    // Find which AppType matches a name string (case-insensitive)
    static AppType nameToAppType(const std::string& name);
};



#endif // DPI_RULE_MANAGER_H
