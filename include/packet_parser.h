#pragma once
// =============================================================================
// packet_parser.h — Protocol header parsing for Ethernet/IP/TCP/UDP
// =============================================================================
// Parses raw bytes from a RawPacket into a ParsedPacket by walking
// through each protocol layer's header manually.
//
// INTERVIEW TALKING POINT:
//   "Every multi-byte field in network protocols is big-endian (network
//   byte order). x86 is little-endian. ntohs()/ntohl() perform the swap.
//   Getting this wrong produces garbage values that are very hard to debug."
// =============================================================================

#ifndef DPI_PACKET_PARSER_H
#define DPI_PACKET_PARSER_H

#include "types.h"
#include <cstdint>

// Header size constants (minimum sizes — IP and TCP can have options)
static constexpr size_t ETH_HEADER_LEN      = 14;   // dst MAC + src MAC + EtherType
static constexpr size_t IPV4_MIN_HEADER_LEN = 20;   // without options
static constexpr size_t TCP_MIN_HEADER_LEN  = 20;   // without options
static constexpr size_t UDP_HEADER_LEN      = 8;    // fixed size

// TCP flag bit masks
static constexpr uint8_t TCP_FLAG_FIN = 0x01;
static constexpr uint8_t TCP_FLAG_SYN = 0x02;
static constexpr uint8_t TCP_FLAG_RST = 0x04;
static constexpr uint8_t TCP_FLAG_PSH = 0x08;
static constexpr uint8_t TCP_FLAG_ACK = 0x10;
static constexpr uint8_t TCP_FLAG_URG = 0x20;

// ---------------------------------------------------------------------------
// PacketParser — stateless static methods for protocol parsing
// ---------------------------------------------------------------------------
class PacketParser {
public:
    PacketParser() = delete;  // All static — not instantiated

    // Main entry point: parse a RawPacket into a ParsedPacket.
    // Returns true if at least Ethernet + IP was successfully parsed.
    // On failure, parsed.is_valid = false; no exception is thrown
    // (malformed packets are common in real traffic).
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

    // Also fills a Packet struct suitable for pipeline use
    static bool parseIntoPacket(const RawPacket& raw, Packet& pkt);

    // Convert ParsedPacket fields into a FiveTuple
    static FiveTuple makeFiveTuple(const ParsedPacket& parsed);

private:
    // Internal per-layer parsers (return false on truncation/malform)
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& p);
    static bool parseIPv4    (const uint8_t* data, size_t len, ParsedPacket& p,
                               size_t& ip_hdr_len, size_t& ip_payload_len);
    static bool parseTCP     (const uint8_t* data, size_t len, ParsedPacket& p,
                               size_t& tcp_hdr_len);
    static bool parseUDP     (const uint8_t* data, size_t len, ParsedPacket& p);

    // Read big-endian integers from raw bytes (avoids UB from unaligned access)
    static uint16_t readU16BE(const uint8_t* p) {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    }
    static uint32_t readU32BE(const uint8_t* p) {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) <<  8) |
               (static_cast<uint32_t>(p[3])      );
    }
};

#endif // DPI_PACKET_PARSER_H
