#pragma once
// =============================================================================
// pcap_reader.h — PCAP file reading and writing
// =============================================================================
// Implements raw binary PCAP I/O without any external library (no libpcap).
//
// PCAP file format:
//   [Global Header 24B][Packet Header 16B][Packet Data N B][Pkt Hdr][Data]...
//
// Magic number handling:
//   0xa1b2c3d4 = native byte order
//   0xd4c3b2a1 = byte-swapped (big-endian capture on little-endian host)
// =============================================================================

#ifndef DPI_PCAP_READER_H
#define DPI_PCAP_READER_H

#include "types.h"
#include <string>
#include <fstream>
#include <stdexcept>

static constexpr uint32_t PCAP_MAGIC_NATIVE   = 0xa1b2c3d4;
static constexpr uint32_t PCAP_MAGIC_SWAPPED  = 0xd4c3b2a1;
static constexpr uint32_t PCAP_MAGIC_NSEC     = 0xa1b23c4d;  // nanosecond variant
static constexpr uint32_t PCAP_LINK_ETHERNET  = 1;

// ---------------------------------------------------------------------------
// PcapReader — sequential reader over a .pcap file
// Usage:
//   PcapReader r;
//   r.open("capture.pcap");
//   RawPacket pkt;
//   while (r.readNextPacket(pkt)) { /* process pkt */ }
// ---------------------------------------------------------------------------
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader() { close(); }

    // Non-copyable (owns file handle)
    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    // Movable
    PcapReader(PcapReader&&)            = default;
    PcapReader& operator=(PcapReader&&) = default;

    // Open and validate a PCAP file.
    // Throws std::runtime_error on bad magic, unreadable file, or non-Ethernet link.
    void open(const std::string& filename);

    // Read the next packet into raw.
    // Returns true if a packet was read, false at EOF.
    // Throws std::runtime_error on corrupt data.
    bool readNextPacket(RawPacket& raw);

    // Close the file (idempotent).
    void close();

    // Accessors
    bool     isOpen()      const { return file_.is_open(); }
    uint32_t snaplen()     const { return global_hdr_.snaplen; }
    uint32_t linkType()    const { return global_hdr_.network; }
    uint64_t packetsRead() const { return packets_read_; }

private:
    std::ifstream    file_;
    PcapGlobalHeader global_hdr_{};
    bool             byte_swapped_  = false;
    uint64_t         packets_read_  = 0;

    // Swap bytes of a 16-bit value (for big-endian PCAP files)
    static uint16_t swapBytes(uint16_t v) {
        return static_cast<uint16_t>((v >> 8) | (v << 8));
    }
    // Swap bytes of a 32-bit value
    static uint32_t swapBytes(uint32_t v) {
        return ((v & 0xFF000000u) >> 24) |
               ((v & 0x00FF0000u) >>  8) |
               ((v & 0x0000FF00u) <<  8) |
               ((v & 0x000000FFu) << 24);
    }

    // Apply byte-swap if needed
    uint32_t fixU32(uint32_t v) const { return byte_swapped_ ? swapBytes(v) : v; }
    uint16_t fixU16(uint16_t v) const { return byte_swapped_ ? swapBytes(v) : v; }
};

// ---------------------------------------------------------------------------
// PcapWriter — sequential writer that produces a valid .pcap file
// Usage:
//   PcapWriter w;
//   w.open("output.pcap", reader.snaplen());
//   w.writePacket(raw);
// ---------------------------------------------------------------------------
class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter() { close(); }

    PcapWriter(const PcapWriter&)            = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    // Open output file and write PCAP global header.
    // Throws std::runtime_error if file cannot be created.
    void open(const std::string& filename, uint32_t snaplen = 65535,
              uint32_t link_type = PCAP_LINK_ETHERNET);

    // Write one packet (header + data) to the output file.
    void writePacket(const PcapPacketHeader& hdr, const uint8_t* data, uint32_t len);
    void writePacket(const RawPacket& raw);
    void writePacket(const Packet& pkt);

    // Flush and close.
    void close();

    bool isOpen() const { return file_.is_open(); }
    uint64_t packetsWritten() const { return packets_written_; }

private:
    std::ofstream file_;
    uint64_t      packets_written_ = 0;
};

#endif // DPI_PCAP_READER_H
