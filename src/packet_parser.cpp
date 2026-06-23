// =============================================================================
// packet_parser.cpp — Implementation of Ethernet/IPv4/TCP/UDP parsing
// =============================================================================
// All byte offsets and bit manipulations are documented inline.
// Key principle: NEVER read past the end of the buffer. Every access
// is bounds-checked before dereferencing.
// =============================================================================

#include "packet_parser.h"
#include <cstring>
#include <cstdio>

// ---------------------------------------------------------------------------
// PacketParser::parse — top-level dispatcher
// ---------------------------------------------------------------------------
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};  // zero-initialize

    const uint8_t* data = raw.data.data();
    const size_t   len  = raw.data.size();

    if (len < ETH_HEADER_LEN) return false;

    // --- Layer 2: Ethernet ---
    if (!parseEthernet(data, len, parsed)) return false;

    // Only handle IPv4 for now
    if (parsed.ethertype != ETHERTYPE_IPV4) {
        parsed.is_valid = false;
        return false;
    }

    // --- Layer 3: IPv4 ---
    size_t ip_hdr_len     = 0;
    size_t ip_payload_len = 0;
    const uint8_t* ip_start = data + ETH_HEADER_LEN;
    size_t         ip_avail = len  - ETH_HEADER_LEN;

    if (!parseIPv4(ip_start, ip_avail, parsed, ip_hdr_len, ip_payload_len)) {
        parsed.is_valid = false;
        return false;
    }

    // --- Layer 4: TCP or UDP ---
    const uint8_t* l4_start = ip_start + ip_hdr_len;
    size_t         l4_avail = ip_payload_len;

    if (l4_avail == 0) {
        // IP packet with no payload (e.g., ICMP or pure header)
        parsed.is_valid = true;
        return true;
    }

    if (parsed.protocol == PROTO_TCP) {
        size_t tcp_hdr_len = 0;
        if (parseTCP(l4_start, l4_avail, parsed, tcp_hdr_len)) {
            // Payload starts after TCP header
            size_t payload_offset = tcp_hdr_len;
            if (payload_offset < l4_avail) {
                parsed.payload     = l4_start + payload_offset;
                parsed.payload_len = static_cast<uint32_t>(l4_avail - payload_offset);
            }
        }
    } else if (parsed.protocol == PROTO_UDP) {
        if (parseUDP(l4_start, l4_avail, parsed)) {
            // UDP payload starts 8 bytes in
            if (l4_avail > UDP_HEADER_LEN) {
                parsed.payload     = l4_start + UDP_HEADER_LEN;
                parsed.payload_len = static_cast<uint32_t>(l4_avail - UDP_HEADER_LEN);
            }
        }
    }

    parsed.is_valid = true;
    return true;
}

// ---------------------------------------------------------------------------
// PacketParser::parseIntoPacket — parse and fill a pipeline Packet struct
// ---------------------------------------------------------------------------
bool PacketParser::parseIntoPacket(const RawPacket& raw, Packet& pkt) {
    pkt.data     = raw.data;         // copy bytes
    pkt.pcap_hdr = raw.header;

    ParsedPacket parsed;
    if (!parse(raw, parsed)) {
        pkt.is_valid = false;
        return false;
    }

    pkt.tuple    = makeFiveTuple(parsed);
    pkt.is_valid = true;

    // Compute payload pointer into pkt.data (not parsed.payload which points into raw.data)
    if (parsed.payload != nullptr && parsed.payload_len > 0) {
        // Offset = parsed.payload - raw.data.data()
        size_t offset = static_cast<size_t>(parsed.payload - raw.data.data());
        if (offset < pkt.data.size()) {
            pkt.payload     = pkt.data.data() + offset;
            pkt.payload_len = parsed.payload_len;
        }
    }

    // Port-based app hint (upgraded to actual app once SNI is known)
    if (parsed.dst_port == PORT_HTTPS || parsed.src_port == PORT_HTTPS) {
        pkt.app_hint = AppType::HTTPS;
    } else if (parsed.dst_port == PORT_HTTP || parsed.src_port == PORT_HTTP ||
               parsed.dst_port == PORT_HTTP_ALT || parsed.src_port == PORT_HTTP_ALT) {
        pkt.app_hint = AppType::HTTP;
    } else if (parsed.dst_port == PORT_DNS || parsed.src_port == PORT_DNS) {
        pkt.app_hint = AppType::DNS;
    }

    return true;
}

// ---------------------------------------------------------------------------
// PacketParser::makeFiveTuple
// ---------------------------------------------------------------------------
FiveTuple PacketParser::makeFiveTuple(const ParsedPacket& p) {
    FiveTuple t;
    t.src_ip   = p.src_ip;
    t.dst_ip   = p.dst_ip;
    t.src_port = p.src_port;
    t.dst_port = p.dst_port;
    t.protocol = p.protocol;
    return t;
}

// ---------------------------------------------------------------------------
// parseEthernet — parse 14-byte Ethernet II header
//
// Byte layout:
//   [0-5]   Destination MAC (6 bytes)
//   [6-11]  Source MAC      (6 bytes)
//   [12-13] EtherType       (2 bytes, big-endian)
//              0x0800 = IPv4
//              0x0806 = ARP
//              0x86DD = IPv6
// ---------------------------------------------------------------------------
bool PacketParser::parseEthernet(const uint8_t* data, size_t len, ParsedPacket& p) {
    if (len < ETH_HEADER_LEN) return false;

    // Copy MACs (no alignment issues with memcpy)
    std::memcpy(p.dst_mac.data(), data + 0, 6);
    std::memcpy(p.src_mac.data(), data + 6, 6);

    // EtherType at bytes 12-13 (big-endian)
    p.ethertype  = readU16BE(data + 12);
    p.has_ethernet = true;
    return true;
}

// ---------------------------------------------------------------------------
// parseIPv4 — parse IPv4 header (minimum 20 bytes, may have options)
//
// Byte layout (RFC 791):
//   [0]     Version (4 bits) | IHL (4 bits)
//             Version = 4 for IPv4
//             IHL = header length in 32-bit words (min 5 = 20 bytes)
//   [1]     DSCP + ECN (ignored)
//   [2-3]   Total Length (big-endian) — entire IP packet including header
//   [4-5]   Identification (ignored)
//   [6-7]   Flags + Fragment Offset (we don't reassemble fragments)
//   [8]     TTL
//   [9]     Protocol (6=TCP, 17=UDP, 1=ICMP)
//   [10-11] Header Checksum (not verified — DPI trusts captured data)
//   [12-15] Source IP (big-endian)
//   [16-19] Destination IP (big-endian)
//   [20+]   Options (if IHL > 5)
// ---------------------------------------------------------------------------
bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& p,
                              size_t& ip_hdr_len, size_t& ip_payload_len) {
    if (len < IPV4_MIN_HEADER_LEN) return false;

    uint8_t version_ihl = data[0];
    uint8_t version = (version_ihl >> 4) & 0x0F;
    uint8_t ihl     = (version_ihl     ) & 0x0F;

    if (version != 4) return false;  // Not IPv4

    ip_hdr_len = static_cast<size_t>(ihl) * 4;  // IHL is in 32-bit words
    if (ip_hdr_len < IPV4_MIN_HEADER_LEN) return false;  // Bogus IHL
    if (ip_hdr_len > len)                 return false;  // Truncated

    uint16_t total_len  = readU16BE(data + 2);
    p.ip_total_len      = total_len;
    p.ttl               = data[8];
    p.protocol          = data[9];

    // Source and destination IPs stored in host byte order
    p.src_ip = readU32BE(data + 12);
    p.dst_ip = readU32BE(data + 16);

    // ip_payload_len = total packet length minus IP header
    // Guard against crafted packets where total_len < ihl
    if (total_len > ip_hdr_len) {
        ip_payload_len = static_cast<size_t>(total_len) - ip_hdr_len;
    } else {
        ip_payload_len = 0;
    }

    // Clamp to what's actually available in the buffer
    size_t available = (len > ip_hdr_len) ? (len - ip_hdr_len) : 0;
    if (ip_payload_len > available) {
        ip_payload_len = available;  // Truncated packet (common in captures)
    }

    p.has_ipv4 = true;
    return true;
}

// ---------------------------------------------------------------------------
// parseTCP — parse TCP header (minimum 20 bytes, may have options)
//
// Byte layout (RFC 793):
//   [0-1]   Source Port      (big-endian)
//   [2-3]   Destination Port (big-endian)
//   [4-7]   Sequence Number  (big-endian)
//   [8-11]  Acknowledgment Number (big-endian)
//   [12]    Data Offset (4 bits, upper) | Reserved (3 bits) | NS flag (1 bit)
//             Data Offset = TCP header length in 32-bit words (min 5 = 20 bytes)
//   [13]    Flags: CWR ECE URG ACK PSH RST SYN FIN (LSB to MSB)
//   [14-15] Window Size (big-endian)
//   [16-17] Checksum (not verified)
//   [18-19] Urgent Pointer
//   [20+]   Options (if data offset > 5)
// ---------------------------------------------------------------------------
bool PacketParser::parseTCP(const uint8_t* data, size_t len, ParsedPacket& p,
                             size_t& tcp_hdr_len) {
    if (len < TCP_MIN_HEADER_LEN) return false;

    p.src_port = readU16BE(data + 0);
    p.dst_port = readU16BE(data + 2);
    p.seq_num  = readU32BE(data + 4);
    p.ack_num  = readU32BE(data + 8);

    uint8_t data_offset = (data[12] >> 4) & 0x0F;
    tcp_hdr_len = static_cast<size_t>(data_offset) * 4;

    if (tcp_hdr_len < TCP_MIN_HEADER_LEN) tcp_hdr_len = TCP_MIN_HEADER_LEN;
    if (tcp_hdr_len > len)                tcp_hdr_len = len;  // clamp to available

    p.tcp_flags   = data[13];
    p.window_size = readU16BE(data + 14);

    p.has_tcp = true;
    return true;
}

// ---------------------------------------------------------------------------
// parseUDP — parse UDP header (fixed 8 bytes)
//
// Byte layout (RFC 768):
//   [0-1]   Source Port      (big-endian)
//   [2-3]   Destination Port (big-endian)
//   [4-5]   Length           (header + data, big-endian)
//   [6-7]   Checksum
// ---------------------------------------------------------------------------
bool PacketParser::parseUDP(const uint8_t* data, size_t len, ParsedPacket& p) {
    if (len < UDP_HEADER_LEN) return false;

    p.src_port = readU16BE(data + 0);
    p.dst_port = readU16BE(data + 2);
    // [4-5] UDP length includes the 8-byte header
    // [6-7] checksum — not verified

    p.has_udp = true;
    return true;
}
