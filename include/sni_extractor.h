#pragma once
// =============================================================================
// sni_extractor.h — Multi-signal application identification via DPI
// =============================================================================
// Three independent signals for identifying applications:
//
//  1. TLS SNI (Server Name Indication) — most reliable for HTTPS
//     Extracted from TLS 1.0-1.3 Client Hello messages.
//     Visible in cleartext before the encryption handshake completes.
//
//  2. HTTP Host Header — for plaintext HTTP/1.x traffic
//     The "Host: " header in HTTP requests reveals the destination domain.
//
//  3. DNS Query Domain — for DNS over UDP (port 53)
//     The QNAME field in DNS questions reveals the domain being resolved.
//
// All methods return std::optional<std::string> — nullopt on failure.
// No exceptions thrown; callers can safely ignore failures.
// =============================================================================

#ifndef DPI_SNI_EXTRACTOR_H
#define DPI_SNI_EXTRACTOR_H

#include "types.h"
#include <optional>
#include <string>

// ---------------------------------------------------------------------------
// SNIExtractor — stateless DPI extraction methods
// ---------------------------------------------------------------------------
class SNIExtractor {
public:
    SNIExtractor() = delete;  // All static

    // -------------------------------------------------------------------------
    // extractSNI — walk TLS Client Hello to find SNI extension (type 0x0000)
    //
    // Expected payload structure (TLS record + handshake + extensions):
    //   [0]     Content Type = 0x16 (Handshake)
    //   [1-2]   Legacy Record Version (0x0301 or 0x0303)
    //   [3-4]   Record Length
    //   [5]     Handshake Type = 0x01 (Client Hello)
    //   [6-8]   Handshake Length (3 bytes, big-endian)
    //   [9-10]  Client Version
    //   [11-42] Random (32 bytes)
    //   [43]    Session ID Length (N)
    //   [44..]  Session ID (N bytes)
    //   ...     Cipher Suites Length (2) + Cipher Suites (M*2 bytes)
    //   ...     Compression Methods Length (1) + Compression Methods (K bytes)
    //   ...     Extensions Length (2) + Extensions
    //   For each extension:
    //     [0-1]  Extension Type
    //     [2-3]  Extension Data Length
    //     [4..]  Extension Data
    //   SNI extension (type 0x0000):
    //     [0-1]  SNI List Length
    //     [2]    SNI Type (0x00 = hostname)
    //     [3-4]  Hostname Length
    //     [5..]  Hostname (ASCII)
    // -------------------------------------------------------------------------
    static std::optional<std::string> extractSNI(
        const uint8_t* payload, size_t length);

    // -------------------------------------------------------------------------
    // extractHTTPHost — scan HTTP/1.x request for "Host:" header
    //
    // Detects HTTP verbs: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE
    // Then scans for "Host: " (case-insensitive) and extracts until CRLF.
    // Strips port number if present (e.g., "example.com:8080" -> "example.com")
    // -------------------------------------------------------------------------
    static std::optional<std::string> extractHTTPHost(
        const uint8_t* payload, size_t length);

    // -------------------------------------------------------------------------
    // extractDNSQuery — parse DNS question section to get queried domain
    //
    // DNS packet structure (RFC 1035):
    //   [0-1]   Transaction ID
    //   [2-3]   Flags (QR=0 for query, Opcode=0 for standard query)
    //   [4-5]   QDCOUNT (question count)
    //   [6-7]   ANCOUNT (answer count)
    //   [8-9]   NSCOUNT
    //   [10-11] ARCOUNT
    //   [12+]   Questions:
    //             QNAME: series of length-prefixed labels, terminated by 0x00
    //             QTYPE:  2 bytes
    //             QCLASS: 2 bytes
    // -------------------------------------------------------------------------
    static std::optional<std::string> extractDNSQuery(
        const uint8_t* payload, size_t length);

    // Convenience: try all three extractors on a packet, return first match
    static std::optional<std::string> extractAny(
        const uint8_t* payload, size_t length,
        uint16_t dst_port, uint16_t src_port);

private:
    // Read big-endian 16-bit integer
    static uint16_t readU16BE(const uint8_t* p) {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    }
};

#endif // DPI_SNI_EXTRACTOR_H
