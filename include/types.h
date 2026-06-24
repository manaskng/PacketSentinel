#pragma once
// =============================================================================
// types.h — Core data structures for the DPI Engine
// =============================================================================
// Contains every shared type used across all components:
//   - FiveTuple  : unique connection identifier (src_ip, dst_ip, ports, proto)
//   - Flow       : per-connection state (SNI, app type, counters, block flag)
//   - AppType    : enum of recognized applications
//   - RawPacket  : raw bytes read from PCAP
//   - ParsedPacket: protocol-decoded fields
//   - Packet     : unit of work passed through the multi-threaded pipeline
// =============================================================================

#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <array>

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------
static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
static constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
static constexpr uint8_t  PROTO_TCP      = 6;
static constexpr uint8_t  PROTO_UDP      = 17;
static constexpr uint16_t PORT_HTTP      = 80;
static constexpr uint16_t PORT_HTTPS     = 443;
static constexpr uint16_t PORT_DNS       = 53;
static constexpr uint16_t PORT_HTTP_ALT  = 8080;

// TLS record type
static constexpr uint8_t TLS_HANDSHAKE  = 0x16;
static constexpr uint8_t TLS_CLIENT_HELLO = 0x01;
static constexpr uint16_t TLS_EXT_SNI   = 0x0000;

// ---------------------------------------------------------------------------
// PCAP file format structs (pragma packed = exact byte layout)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (native) or 0xd4c3b2a1 (swapped)
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT to local correction (usually 0)
    uint32_t sigfigs;        // accuracy of timestamps (usually 0)
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type (1 = Ethernet)
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // bytes actually saved in file
    uint32_t orig_len;       // original packet length
};

#pragma pack(pop)

// ---------------------------------------------------------------------------
// AppType — recognized application categories
// ---------------------------------------------------------------------------
enum class AppType : uint8_t {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    GITHUB,
    TIKTOK,
    NETFLIX,
    TWITTER,
    INSTAGRAM,
    DISCORD,
    WHATSAPP,
    TWITCH,
    REDDIT,
    _COUNT   // sentinel — keep last
};

// ---------------------------------------------------------------------------
// AnomalyType — categories of detected network anomalies
// ---------------------------------------------------------------------------
enum class AnomalyType : uint8_t {
    NONE = 0,
    PORT_SCAN,          // Many flows to unique ports from one source
    DDOS_SUSPECT,       // Uniform packet sizes at extremely high rate
    DATA_EXFILTRATION,  // Abnormally large payloads per flow
    HIGH_ENTROPY,       // Near-max entropy on non-TLS traffic
    PROTOCOL_ANOMALY,   // Malformed or suspicious TCP flag combinations
    _COUNT
};

std::string anomalyTypeToString(AnomalyType t);

// ---------------------------------------------------------------------------
// FiveTuple — unique connection identifier
// ---------------------------------------------------------------------------
struct FiveTuple {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;

    bool operator==(const FiveTuple& o) const noexcept {
        return src_ip   == o.src_ip   &&
               dst_ip   == o.dst_ip   &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }

    // Canonical form: low IP:port is always "src" for bidirectional matching
    // (not used here — we track directionality explicitly)
};

// FiveTuple hash — XOR-fold of all 5 fields for std::unordered_map
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const noexcept {
        // Use FNV-1a style mixing for good distribution
        std::size_t h = 2166136261ULL;
        auto mix = [&](auto v) {
            h ^= static_cast<std::size_t>(v);
            h *= 1099511628211ULL;
        };
        mix(t.src_ip);
        mix(t.dst_ip);
        mix((static_cast<uint32_t>(t.src_port) << 16) | t.dst_port);
        mix(t.protocol);
        return h;
    }
};

// Make FiveTuple usable as unordered_map key
namespace std {
    template<>
    struct hash<FiveTuple> {
        std::size_t operator()(const FiveTuple& t) const noexcept {
            return FiveTupleHash{}(t);
        }
    };
}

// ---------------------------------------------------------------------------
// Flow — per-connection state (owned exclusively by one FastPath thread)
// ---------------------------------------------------------------------------
struct Flow {
    std::string sni;                       // extracted hostname (SNI/HTTP-Host/DNS)
    std::string dns_query;                 // DNS queried domain (may differ from SNI)
    AppType     app_type    = AppType::UNKNOWN;
    bool        blocked     = false;       // hard block — drop all packets
    bool        throttled   = false;       // soft throttle — delay packets
    bool        classified  = false;       // true once app_type is determined

    uint64_t    packet_count = 0;
    uint64_t    byte_count   = 0;

    uint32_t    src_ip  = 0;              // cached from first packet
    uint32_t    dst_ip  = 0;

    // -- Anomaly detection fields ------------------------------------------
    double      anomaly_score  = 0.0;      // 0.0 = normal, 1.0 = highly anomalous
    AnomalyType anomaly_type   = AnomalyType::NONE;

    // TCP flag counters
    uint32_t    syn_count      = 0;
    uint32_t    fin_count      = 0;
    uint32_t    rst_count      = 0;

    // Payload entropy (Shannon, 0.0–8.0 bits)
    double      payload_entropy = 0.0;

    // Online variance via Welford's algorithm (no vector needed)
    double      pkt_size_mean  = 0.0;
    double      pkt_size_m2    = 0.0;      // running sum of squared diffs

    // Timing
    uint64_t    first_seen_ms  = 0;
    uint64_t    last_seen_ms   = 0;

    // Helpers
    double packetSizeVariance() const {
        return packet_count > 1 ? pkt_size_m2 / (packet_count - 1) : 0.0;
    }
    double durationMs() const {
        return (last_seen_ms > first_seen_ms) ? (double)(last_seen_ms - first_seen_ms) : 0.0;
    }
};

// ---------------------------------------------------------------------------
// RawPacket — raw bytes read directly from PCAP file
// ---------------------------------------------------------------------------
struct RawPacket {
    PcapPacketHeader header{};
    std::vector<uint8_t> data;            // incl_len bytes of packet data
};

// ---------------------------------------------------------------------------
// ParsedPacket — protocol-decoded fields from a RawPacket
// ---------------------------------------------------------------------------
struct ParsedPacket {
    // Ethernet
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ethertype = 0;

    // IP
    uint32_t src_ip     = 0;
    uint32_t dst_ip     = 0;
    uint8_t  protocol   = 0;
    uint8_t  ttl        = 0;
    uint16_t ip_total_len = 0;

    // TCP
    uint16_t src_port   = 0;
    uint16_t dst_port   = 0;
    uint32_t seq_num    = 0;
    uint32_t ack_num    = 0;
    uint8_t  tcp_flags  = 0;    // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
    uint16_t window_size= 0;

    // Payload
    const uint8_t* payload     = nullptr;  // pointer into RawPacket::data
    uint32_t       payload_len = 0;

    // Status
    bool has_ethernet = false;
    bool has_ipv4     = false;
    bool has_tcp      = false;
    bool has_udp      = false;
    bool is_valid     = false;
};

// ---------------------------------------------------------------------------
// Packet — unit of work in the multi-threaded pipeline
//          Carries everything a FastPath thread needs, self-contained
// ---------------------------------------------------------------------------
struct Packet {
    FiveTuple        tuple;
    PcapPacketHeader pcap_hdr{};
    std::vector<uint8_t> data;          // full packet bytes (for PCAP write)
    const uint8_t*   payload     = nullptr;  // pointer INTO data
    uint32_t         payload_len = 0;

    // Pre-computed at parse time
    AppType          app_hint = AppType::UNKNOWN;  // quick hint (port-based)
    bool             is_valid = false;
};

// ---------------------------------------------------------------------------
// Helper functions (implemented in types.cpp)
// ---------------------------------------------------------------------------
AppType     sniToAppType(const std::string& sni);
std::string appTypeToString(AppType app);
std::string ipToString(uint32_t ip);
uint32_t    parseIPString(const std::string& ip_str);

// TCP flag accessors
inline bool flagSYN(uint8_t f) { return (f & 0x02) != 0; }
inline bool flagACK(uint8_t f) { return (f & 0x10) != 0; }
inline bool flagFIN(uint8_t f) { return (f & 0x01) != 0; }
inline bool flagRST(uint8_t f) { return (f & 0x04) != 0; }

#endif // DPI_TYPES_H
