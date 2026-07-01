// =============================================================================
// sni_extractor.cpp — Three-signal DPI application identification
// =============================================================================
// CRITICAL SAFETY NOTE: Every byte access is bounds-checked.
// The TLS Client Hello byte-walk is the most UB-prone code in the project:
// if any length field is larger than the remaining buffer, we return nullopt.
// Do NOT use pointer arithmetic without subtracting from a known end pointer.
// =============================================================================

#include "sni_extractor.h"
#include <cstring>
#include <algorithm>
#include <cctype>

// =============================================================================
// TLS SNI Extraction
// =============================================================================

std::optional<std::string> SNIExtractor::extractSNI(
    const uint8_t* payload, size_t length)
{
    // Minimum size: TLS record header (5) + Handshake header (4) +
    //               Client Hello minimum = 9 + 2 + 32 + 1 = 44 bytes minimum
    if (payload == nullptr || length < 44) return std::nullopt;

    // --- TLS Record Layer ---
    // Byte 0: Content Type must be 0x16 (Handshake)
    if (payload[0] != TLS_HANDSHAKE) return std::nullopt;

    // Bytes 1-2: Legacy version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2/1.3)
    // We accept any version to handle TLS 1.3 records
    uint16_t record_version = readU16BE(payload + 1);
    (void)record_version;  // Not used for extraction

    // Bytes 3-4: Record length
    uint16_t record_len = readU16BE(payload + 3);
    if (static_cast<size_t>(record_len) + 5 > length) {
        // Packet may be truncated — use actual available data
        record_len = static_cast<uint16_t>(length - 5);
    }

    // --- TLS Handshake Layer (starts at byte 5) ---
    size_t offset = 5;

    // Byte 5: Handshake type must be 0x01 (Client Hello)
    if (payload[offset] != TLS_CLIENT_HELLO) return std::nullopt;
    offset += 1;

    // Bytes 6-8: Handshake length (3 bytes, big-endian)
    if (offset + 3 > length) return std::nullopt;
    uint32_t hs_len = (static_cast<uint32_t>(payload[offset    ]) << 16) |
                      (static_cast<uint32_t>(payload[offset + 1]) <<  8) |
                      (static_cast<uint32_t>(payload[offset + 2])      );
    offset += 3;

    size_t hs_end = offset + hs_len;
    if (hs_end > length) hs_end = length;  // truncated — parse what we have

    // --- Client Hello Body ---
    // Bytes [offset .. offset+1]: Client Version (2 bytes)
    if (offset + 2 > hs_end) return std::nullopt;
    offset += 2;

    // Bytes [offset .. offset+31]: Random (32 bytes)
    if (offset + 32 > hs_end) return std::nullopt;
    offset += 32;

    // Byte [offset]: Session ID Length (1 byte)
    if (offset + 1 > hs_end) return std::nullopt;
    uint8_t session_id_len = payload[offset];
    offset += 1;

    // Session ID bytes (0-32)
    if (offset + session_id_len > hs_end) return std::nullopt;
    offset += session_id_len;

    // Bytes: Cipher Suites Length (2 bytes)
    if (offset + 2 > hs_end) return std::nullopt;
    uint16_t cipher_suites_len = readU16BE(payload + offset);
    offset += 2;

    // Cipher Suite bytes
    if (offset + cipher_suites_len > hs_end) return std::nullopt;
    offset += cipher_suites_len;

    // Byte: Compression Methods Length (1 byte)
    if (offset + 1 > hs_end) return std::nullopt;
    uint8_t compression_len = payload[offset];
    offset += 1;

    // Compression method bytes
    if (offset + compression_len > hs_end) return std::nullopt;
    offset += compression_len;

    // Bytes: Extensions Length (2 bytes) — may be absent in very old TLS
    if (offset + 2 > hs_end) return std::nullopt;
    uint16_t extensions_total_len = readU16BE(payload + offset);
    offset += 2;

    size_t extensions_end = offset + extensions_total_len;
    if (extensions_end > hs_end) extensions_end = hs_end;

    // --- Walk Extensions ---
    // Each extension: [type: 2B][length: 2B][data: length B]
    while (offset + 4 <= extensions_end) {
        uint16_t ext_type = readU16BE(payload + offset);
        uint16_t ext_len  = readU16BE(payload + offset + 2);
        offset += 4;

        if (offset + ext_len > extensions_end) return std::nullopt;

        if (ext_type == TLS_EXT_SNI) {
            // --- SNI Extension ---
            // [0-1] SNI List Length
            // [2]   SNI Type (0x00 = host_name)
            // [3-4] Hostname Length
            // [5..] Hostname (ASCII, no null terminator)
            if (ext_len < 5) return std::nullopt;

            // uint16_t sni_list_len = readU16BE(payload + offset);  // offset 0
            uint8_t  sni_type     = payload[offset + 2];  // offset 2
            uint16_t sni_name_len = readU16BE(payload + offset + 3);  // offset 3

            if (sni_type != 0x00) return std::nullopt;  // Not a hostname
            
            // SECURITY FIX: Validate hostname length is reasonable (max 255 bytes per DNS spec)
            // and within extension bounds
            if (sni_name_len == 0 || sni_name_len > 255) return std::nullopt;
            if (5 + sni_name_len > ext_len) return std::nullopt;

            // Extract hostname as string
            return std::string(
                reinterpret_cast<const char*>(payload + offset + 5),
                sni_name_len
            );
        }

        // Not the SNI extension — skip
        offset += ext_len;
    }

    return std::nullopt;  // SNI extension not found
}

// =============================================================================
// HTTP Host Header Extraction
// =============================================================================

std::optional<std::string> SNIExtractor::extractHTTPHost(
    const uint8_t* payload, size_t length)
{
    if (payload == nullptr || length < 10) return std::nullopt;

    // Quick check: must start with an HTTP verb
    // We check 3-7 bytes at the start (shortest verb is "GET")
    const char* methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };
    bool is_http = false;
    for (const char* m : methods) {
        size_t mlen = strlen(m);
        if (length >= mlen &&
            memcmp(payload, m, mlen) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http) return std::nullopt;

    // Convert payload to string_view (no copy — just a view)
    // We limit to 8KB to avoid scanning huge HTTP bodies
    size_t scan_len = std::min(length, static_cast<size_t>(8192));
    const char* data = reinterpret_cast<const char*>(payload);

    // Find "Host: " or "host: " (case-insensitive search)
    for (size_t i = 0; i + 7 <= scan_len; ++i) {
        // Check for "Host: " (6 characters, case-insensitive on first letter)
        if ((data[i] == 'H' || data[i] == 'h') &&
            (data[i+1] == 'O' || data[i+1] == 'o') &&
            (data[i+2] == 'S' || data[i+2] == 's') &&
            (data[i+3] == 'T' || data[i+3] == 't') &&
             data[i+4] == ':' &&
             data[i+5] == ' ')
        {
            size_t value_start = i + 6;
            // Extract until \r\n or \n
            size_t j = value_start;
            while (j < scan_len && data[j] != '\r' && data[j] != '\n') ++j;

            if (j == value_start) return std::nullopt;  // Empty host

            std::string host(data + value_start, j - value_start);

            // Strip port number if present (e.g., "example.com:8080")
            auto colon_pos = host.rfind(':');
            if (colon_pos != std::string::npos) {
                // Make sure it's actually a port, not IPv6
                bool is_port = true;
                for (size_t k = colon_pos + 1; k < host.size(); ++k) {
                    if (!std::isdigit(static_cast<unsigned char>(host[k]))) {
                        is_port = false;
                        break;
                    }
                }
                if (is_port) {
                    host = host.substr(0, colon_pos);
                }
            }

            if (host.empty()) return std::nullopt;
            return host;
        }
    }

    return std::nullopt;
}

// =============================================================================
// DNS Query Extraction
// =============================================================================

std::optional<std::string> SNIExtractor::extractDNSQuery(
    const uint8_t* payload, size_t length)
{
    // DNS header is 12 bytes minimum
    if (payload == nullptr || length < 12) return std::nullopt;

    // Bytes 0-1: Transaction ID (ignored)
    // Bytes 2-3: Flags
    uint16_t flags = readU16BE(payload + 2);

    // QR bit (bit 15) must be 0 (query, not response)
    if ((flags & 0x8000) != 0) return std::nullopt;

    // Opcode (bits 14-11) must be 0 (standard query)
    uint8_t opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    if (opcode != 0) return std::nullopt;

    // Bytes 4-5: QDCOUNT — number of questions (must be >= 1)
    uint16_t qdcount = readU16BE(payload + 4);
    if (qdcount == 0) return std::nullopt;

    // --- Parse first question's QNAME ---
    // QNAME is a sequence of labels: [length][data][length][data]...[0x00]
    // Length 0 terminates. Labels must be 63 bytes or fewer.
    // Compression pointers (0xC0xx) are rare in queries but we handle them.

    size_t offset = 12;  // After DNS header
    std::string domain;
    bool first_label = true;

    // Guard: DNS names are max 255 bytes
    size_t name_end = std::min(offset + 255, length);

    while (offset < name_end) {
        uint8_t label_len = payload[offset];
        ++offset;

        // Compression pointer: top 2 bits set = 0xC0
        if ((label_len & 0xC0) == 0xC0) {
            // Compressed pointer — skip (queries rarely use compression)
            // We just bail out since we can't resolve the pointer
            // without the full DNS message context
            return domain.empty() ? std::nullopt : std::optional<std::string>{domain};
        }

        if (label_len == 0) break;  // Root label — end of QNAME

        // Validate: each label max 63 chars
        if (label_len > 63) return std::nullopt;
        if (offset + label_len > length) return std::nullopt;

        if (!first_label) domain += '.';
        domain.append(reinterpret_cast<const char*>(payload + offset), label_len);
        offset += label_len;
        first_label = false;
    }

    if (domain.empty()) return std::nullopt;

    // Convert to lowercase for consistency
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
    return domain;
}

// =============================================================================
// extractAny — try all three signals, return first match
// =============================================================================

std::optional<std::string> SNIExtractor::extractAny(
    const uint8_t* payload, size_t length,
    uint16_t dst_port, uint16_t src_port)
{
    if (payload == nullptr || length == 0) return std::nullopt;

    // Try TLS SNI first (HTTPS port 443)
    if (dst_port == PORT_HTTPS || src_port == PORT_HTTPS) {
        auto result = extractSNI(payload, length);
        if (result) return result;
    }

    // Try HTTP Host header (port 80 or 8080)
    if (dst_port == PORT_HTTP || src_port == PORT_HTTP ||
        dst_port == PORT_HTTP_ALT || src_port == PORT_HTTP_ALT) {
        auto result = extractHTTPHost(payload, length);
        if (result) return result;
    }

    // Try DNS (port 53, UDP)
    if (dst_port == PORT_DNS || src_port == PORT_DNS) {
        auto result = extractDNSQuery(payload, length);
        if (result) return result;
    }

    // Last resort: try all methods regardless of port
    // (some servers run TLS on non-standard ports)
    auto sni = extractSNI(payload, length);
    if (sni) return sni;

    auto host = extractHTTPHost(payload, length);
    if (host) return host;

    return std::nullopt;
}
