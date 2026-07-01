// =============================================================================
// rule_manager.cpp — Rule engine implementation with JSON loading
// =============================================================================
// JSON parsing is implemented without any external library using simple
// string scanning (sufficient for our structured rules.json format).
// For production, you would use nlohmann/json, but avoiding dependencies
// is a portfolio strength ("no external deps").
// =============================================================================

#include "rule_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

// ---------------------------------------------------------------------------
// nameToAppType — case-insensitive name to AppType mapping
// ---------------------------------------------------------------------------
AppType RuleManager::nameToAppType(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "youtube")   return AppType::YOUTUBE;
    if (lower == "netflix")   return AppType::NETFLIX;
    if (lower == "tiktok")    return AppType::TIKTOK;
    if (lower == "facebook")  return AppType::FACEBOOK;
    if (lower == "instagram") return AppType::INSTAGRAM;
    if (lower == "twitter")   return AppType::TWITTER;
    if (lower == "discord")   return AppType::DISCORD;
    if (lower == "whatsapp")  return AppType::WHATSAPP;
    if (lower == "twitch")    return AppType::TWITCH;
    if (lower == "reddit")    return AppType::REDDIT;
    if (lower == "github")    return AppType::GITHUB;
    if (lower == "google")    return AppType::GOOGLE;
    if (lower == "http")      return AppType::HTTP;
    if (lower == "https")     return AppType::HTTPS;
    if (lower == "dns")       return AppType::DNS;
    return AppType::UNKNOWN;
}

// ---------------------------------------------------------------------------
// addBlockedIP
// ---------------------------------------------------------------------------
void RuleManager::addBlockedIP(const std::string& ip_str) {
    try {
        blocked_ips_.insert(parseIPString(ip_str));
    } catch (const std::exception& e) {
        std::cerr << "[Rules] Invalid IP '" << ip_str << "': " << e.what() << "\n";
    }
}

void RuleManager::addBlockedIP(uint32_t ip) {
    blocked_ips_.insert(ip);
}

// ---------------------------------------------------------------------------
// addBlockedApp
// ---------------------------------------------------------------------------
void RuleManager::addBlockedApp(const std::string& app_name) {
    AppType t = nameToAppType(app_name);
    if (t != AppType::UNKNOWN) {
        blocked_apps_.insert(t);
    } else {
        std::cerr << "[Rules] Unknown app name: '" << app_name << "'\n";
    }
}

void RuleManager::addBlockedApp(AppType app) {
    blocked_apps_.insert(app);
}

// ---------------------------------------------------------------------------
// addBlockedDomain
// ---------------------------------------------------------------------------
void RuleManager::addBlockedDomain(const std::string& domain_substr) {
    std::string lower = domain_substr;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    blocked_domains_.push_back(lower);
}

// ---------------------------------------------------------------------------
// addThrottledApp
// ---------------------------------------------------------------------------
void RuleManager::addThrottledApp(const std::string& app_name) {
    AppType t = nameToAppType(app_name);
    if (t != AppType::UNKNOWN) {
        throttled_apps_.insert(t);
    } else {
        std::cerr << "[Rules] Unknown app name for throttle: '" << app_name << "'\n";
    }
}

void RuleManager::addThrottledApp(AppType app) {
    throttled_apps_.insert(app);
}

// ---------------------------------------------------------------------------
// domainMatches — check if SNI matches a domain rule using suffix matching
// SECURITY FIX: Prevents bypass like "tiktok.com.attacker.com" matching "tiktok.com"
// Returns true if sni == domain or sni ends with ".domain"
// ---------------------------------------------------------------------------
static bool domainMatches(const std::string& sni, const std::string& domain) {
    if (sni == domain) return true;
    if (sni.length() <= domain.length()) return false;
    
    // Check if sni ends with ".domain"
    size_t pos = sni.length() - domain.length();
    if (sni[pos - 1] != '.') return false;  // Must have '.' before domain
    
    return sni.compare(pos, domain.length(), domain) == 0;
}

// ---------------------------------------------------------------------------
// isBlocked — three-stage rule check
// ---------------------------------------------------------------------------
bool RuleManager::isBlocked(uint32_t src_ip, AppType app,
                             const std::string& sni) const {
    // Stage 1: IP blacklist (O(1))
    if (blocked_ips_.count(src_ip)) return true;

    // Stage 2: App type blacklist (O(1))
    if (app != AppType::UNKNOWN && blocked_apps_.count(app)) return true;

    // Stage 3: Domain suffix match with security fix (O(N * M) but N is usually < 20)
    if (!sni.empty() && !blocked_domains_.empty()) {
        std::string lower_sni = sni;
        std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(), ::tolower);
        for (const auto& dom : blocked_domains_) {
            if (domainMatches(lower_sni, dom)) return true;
        }
    }

    return false;
}

// ---------------------------------------------------------------------------
// isThrottled
// ---------------------------------------------------------------------------
bool RuleManager::isThrottled(AppType app) const {
    return (app != AppType::UNKNOWN) && (throttled_apps_.count(app) > 0);
}

// ---------------------------------------------------------------------------
// printRules — display active rules to stdout
// ---------------------------------------------------------------------------
void RuleManager::printRules() const {
    for (uint32_t ip : blocked_ips_) {
        std::cout << "  [Rules] Block IP: " << ipToString(ip) << "\n";
    }
    for (AppType app : blocked_apps_) {
        std::cout << "  [Rules] Block App: " << appTypeToString(app) << "\n";
    }
    for (const auto& dom : blocked_domains_) {
        std::cout << "  [Rules] Block Domain: *" << dom << "*\n";
    }
    for (AppType app : throttled_apps_) {
        std::cout << "  [Rules] Throttle App: " << appTypeToString(app)
                  << " (delay " << throttle_delay_ms_.count() << "ms/packet)\n";
    }
}

// ---------------------------------------------------------------------------
// loadFromJSON — minimal JSON parser for rules.json
//
// Expected format:
// {
//   "blocked_ips":     ["192.168.1.50", "10.0.0.1"],
//   "blocked_apps":    ["YouTube", "TikTok"],
//   "blocked_domains": ["facebook.com"],
//   "throttled_apps":  ["Netflix"],
//   "throttle_delay_ms": 10
// }
// ---------------------------------------------------------------------------
bool RuleManager::loadFromJSON(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[Rules] Cannot open rules file: " << filename << "\n";
        return false;
    }

    // Read entire file into string
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    // Simple string-scan JSON parser (handles our specific format only)
    // Extracts string arrays and integer values by scanning for known keys

    auto extractStringArray = [&](const std::string& key) -> std::vector<std::string> {
        std::vector<std::string> result;
        std::string search = "\"" + key + "\"";
        size_t pos = content.find(search);
        if (pos == std::string::npos) return result;

        // Find the '[' after the key
        size_t arr_start = content.find('[', pos + search.size());
        if (arr_start == std::string::npos) return result;
        size_t arr_end   = content.find(']', arr_start);
        if (arr_end == std::string::npos) return result;

        // Extract each quoted string within the array
        size_t i = arr_start + 1;
        while (i < arr_end) {
            size_t q1 = content.find('"', i);
            if (q1 == std::string::npos || q1 >= arr_end) break;
            size_t q2 = content.find('"', q1 + 1);
            if (q2 == std::string::npos || q2 > arr_end) break;
            result.push_back(content.substr(q1 + 1, q2 - q1 - 1));
            i = q2 + 1;
        }
        return result;
    };

    auto extractInt = [&](const std::string& key) -> std::optional<int> {
        std::string search = "\"" + key + "\"";
        size_t pos = content.find(search);
        if (pos == std::string::npos) return std::nullopt;
        size_t colon = content.find(':', pos + search.size());
        if (colon == std::string::npos) return std::nullopt;
        size_t val_start = colon + 1;
        while (val_start < content.size() && isspace(content[val_start])) ++val_start;
        try {
            return std::stoi(content.substr(val_start));
        } catch (...) {
            return std::nullopt;
        }
    };

    // Load each rule section
    for (const auto& ip : extractStringArray("blocked_ips")) {
        addBlockedIP(ip);
    }
    for (const auto& app : extractStringArray("blocked_apps")) {
        addBlockedApp(app);
    }
    for (const auto& dom : extractStringArray("blocked_domains")) {
        addBlockedDomain(dom);
    }
    for (const auto& app : extractStringArray("throttled_apps")) {
        addThrottledApp(app);
    }

    auto delay = extractInt("throttle_delay_ms");
    if (delay && *delay > 0) {
        throttle_delay_ms_ = std::chrono::milliseconds(*delay);
    }

    return true;
}
