// =============================================================================
// types.cpp — Implementation of helper functions for DPI types
// =============================================================================

#include "types.h"
#include <sstream>
#include <algorithm>
#include <stdexcept>

// ---------------------------------------------------------------------------
// sniToAppType — map a hostname to an application category
// Uses substring matching for robustness (handles CDN domains etc.)
// ---------------------------------------------------------------------------
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    // Lowercase copy for case-insensitive matching
    std::string lower = sni;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Order matters: more specific before more general
    if (lower.find("youtube")    != std::string::npos ||
        lower.find("ytimg")      != std::string::npos ||
        lower.find("googlevideo")!= std::string::npos ||
        lower.find("yt3.ggpht")  != std::string::npos)
        return AppType::YOUTUBE;

    if (lower.find("netflix")    != std::string::npos ||
        lower.find("nflxso")     != std::string::npos ||
        lower.find("nflximg")    != std::string::npos ||
        lower.find("nflxext")    != std::string::npos)
        return AppType::NETFLIX;

    if (lower.find("tiktok")     != std::string::npos ||
        lower.find("ttwstatic")  != std::string::npos ||
        lower.find("muscdn")     != std::string::npos ||
        lower.find("byteoversea")!= std::string::npos)
        return AppType::TIKTOK;

    if (lower.find("facebook")   != std::string::npos ||
        lower.find("fbcdn")      != std::string::npos ||
        lower.find("fbsbx")      != std::string::npos ||
        lower.find("instagram")  != std::string::npos ||
        lower.find("cdninstagram")!= std::string::npos)
        return (lower.find("instagram") != std::string::npos)
               ? AppType::INSTAGRAM : AppType::FACEBOOK;

    if (lower.find("twitter")    != std::string::npos ||
        lower.find("twimg")      != std::string::npos ||
        lower.find("t.co")       != std::string::npos)
        return AppType::TWITTER;

    if (lower.find("discord")    != std::string::npos ||
        lower.find("discordapp") != std::string::npos ||
        lower.find("discordcdn") != std::string::npos)
        return AppType::DISCORD;

    if (lower.find("whatsapp")   != std::string::npos ||
        lower.find("whatsapp-cdn")!= std::string::npos)
        return AppType::WHATSAPP;

    if (lower.find("twitch")     != std::string::npos ||
        lower.find("jtvnw")      != std::string::npos)
        return AppType::TWITCH;

    if (lower.find("reddit")     != std::string::npos ||
        lower.find("redd.it")    != std::string::npos ||
        lower.find("redditmedia") != std::string::npos)
        return AppType::REDDIT;

    if (lower.find("github")     != std::string::npos ||
        lower.find("githubusercontent")!= std::string::npos ||
        lower.find("githubassets")!= std::string::npos)
        return AppType::GITHUB;

    // Google (after YouTube, since youtube.com is a google property)
    if (lower.find("google")     != std::string::npos ||
        lower.find("googleapis") != std::string::npos ||
        lower.find("gstatic")    != std::string::npos ||
        lower.find("gvt1.com")   != std::string::npos ||
        lower.find("googlesyndication")!= std::string::npos)
        return AppType::GOOGLE;

    // Port-based classification will upgrade HTTPS to the actual app;
    // if we get here, it's an unrecognized HTTPS domain
    return AppType::HTTPS;
}

// ---------------------------------------------------------------------------
// appTypeToString — human-readable app name for reports/CLI output
// ---------------------------------------------------------------------------
std::string appTypeToString(AppType app) {
    switch (app) {
        case AppType::UNKNOWN:   return "Unknown";
        case AppType::HTTP:      return "HTTP";
        case AppType::HTTPS:     return "HTTPS";
        case AppType::DNS:       return "DNS";
        case AppType::GOOGLE:    return "Google";
        case AppType::YOUTUBE:   return "YouTube";
        case AppType::FACEBOOK:  return "Facebook";
        case AppType::GITHUB:    return "GitHub";
        case AppType::TIKTOK:    return "TikTok";
        case AppType::NETFLIX:   return "Netflix";
        case AppType::TWITTER:   return "Twitter";
        case AppType::INSTAGRAM: return "Instagram";
        case AppType::DISCORD:   return "Discord";
        case AppType::WHATSAPP:  return "WhatsApp";
        case AppType::TWITCH:    return "Twitch";
        case AppType::REDDIT:    return "Reddit";
        default:                 return "Unknown";
    }
}

// ---------------------------------------------------------------------------
// ipToString — convert packed uint32_t to "x.x.x.x" dotted-quad notation
// Network byte order (big-endian) input
// ---------------------------------------------------------------------------
std::string ipToString(uint32_t ip) {
    // ip is stored in host byte order after ntohl()
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >>  8) & 0xFF,
             (ip      ) & 0xFF);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// parseIPString — convert "x.x.x.x" to packed uint32_t (host byte order)
// ---------------------------------------------------------------------------
uint32_t parseIPString(const std::string& ip_str) {
    unsigned int a, b, c, d;
    if (sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        throw std::invalid_argument("Invalid IP address: " + ip_str);
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        throw std::invalid_argument("IP octets out of range: " + ip_str);
    }
    return (a << 24) | (b << 16) | (c << 8) | d;
}
